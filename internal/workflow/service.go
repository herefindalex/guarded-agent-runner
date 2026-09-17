package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/store"
)

type Service struct {
	Store                   *store.Store
	Registry                Registry
	Target                  TargetReader
	Support                 policy.SupportProfile
	CurrentRevocationEpoch  int64
	MutationExecutorEnabled bool
	Now                     func() time.Time
}

func (service *Service) now() time.Time {
	if service.Now != nil {
		return service.Now().UTC()
	}
	return time.Now().UTC()
}

func DecodeProposal(reader io.Reader) (domain.ProposalInput, error) {
	decoder := json.NewDecoder(io.LimitReader(reader, 16*1024))
	decoder.DisallowUnknownFields()
	var input domain.ProposalInput
	if err := decoder.Decode(&input); err != nil {
		return input, domain.NewError(domain.ErrInvalidRequest, fmt.Sprintf("invalid proposal schema: %v", err))
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return input, domain.NewError(domain.ErrInvalidRequest, "proposal contains trailing JSON")
	}
	return input, input.Validate()
}

func (service *Service) Tools() []domain.ToolDefinition {
	return append([]domain.ToolDefinition(nil), domain.AgentTools...)
}

func (service *Service) CallReadTool(
	ctx context.Context,
	scope domain.AgentSessionScope,
	name string,
	arguments map[string]any,
) (any, error) {
	if err := service.authorize(scope, name, "", ""); err != nil {
		return nil, err
	}
	if err := validateReadArguments(name, arguments); err != nil {
		return nil, err
	}
	switch name {
	case "inspect_server_identity":
		return map[string]any{
			"target_id":             service.Registry.Enrollment.TargetID,
			"enrollment_id":         service.Registry.Enrollment.EnrollmentID,
			"deployment_generation": service.Registry.Enrollment.DeploymentGeneration,
			"container_id":          service.Registry.Enrollment.ContainerID,
			"image_digest":          service.Registry.Enrollment.ImageDigest,
			"paper_tuple":           service.Registry.Enrollment.PaperTuple,
			"support_profile":       service.Support,
			"mutation_enabled":      service.Support.MutationAllowed(),
		}, nil
	case "list_plugins":
		return service.listPlugins(ctx, arguments, scope)
	case "get_recent_changes":
		return service.recentChanges(ctx, arguments, scope)
	case "get_health", "get_players", "get_performance", "get_recent_errors", "get_backup_status":
		return service.Target.ReadTool(ctx, name, arguments)
	default:
		return nil, domain.NewError(domain.ErrScopeDenied, "unknown or non-read agent tool")
	}
}

func (service *Service) listPlugins(ctx context.Context, arguments map[string]any, scope domain.AgentSessionScope) (any, error) {
	evidence, err := service.Target.ReadTool(ctx, "list_plugins", arguments)
	if err != nil {
		return nil, err
	}
	artifacts := make([]map[string]any, 0, len(service.Registry.Artifacts))
	artifactIDs := make([]string, 0, len(service.Registry.Artifacts))
	for artifactID := range service.Registry.Artifacts {
		artifactIDs = append(artifactIDs, artifactID)
	}
	sort.Strings(artifactIDs)
	for _, artifactID := range artifactIDs {
		artifact := service.Registry.Artifacts[artifactID]
		if contains(scope.PluginIDs, artifact.PluginID) {
			artifacts = append(artifacts, map[string]any{
				"artifact_id": artifact.ArtifactID, "plugin_id": artifact.PluginID,
				"sha256": artifact.SHA256, "size": artifact.Size,
				"owner_trust_confirmed": artifact.OwnerTrustConfirmed,
			})
		}
	}
	transitions := make([]map[string]any, 0, len(service.Registry.Profiles))
	profileIDs := append([]string(nil), scope.ArtifactProfileIDs...)
	sort.Strings(profileIDs)
	for _, profileID := range profileIDs {
		profile, exists := service.Registry.Profiles[profileID]
		if !exists || !contains(scope.PluginIDs, profile.PluginID) {
			continue
		}
		transitions = append(transitions, map[string]any{
			"profile_id": profile.ProfileID, "plugin_id": profile.PluginID,
			"from_artifact_id": profile.FromArtifactID, "to_artifact_id": profile.ToArtifactID,
			"eligibility": profile.Eligibility,
		})
	}
	result, ok := evidence.(map[string]any)
	if !ok {
		result = map[string]any{"availability": domain.Unavailable, "target_evidence": evidence}
	}
	result["catalog_artifacts"] = artifacts
	result["verified_transitions"] = transitions
	return result, nil
}

func (service *Service) recentChanges(ctx context.Context, arguments map[string]any, scope domain.AgentSessionScope) (any, error) {
	limit := 50
	if value, ok := arguments["limit"].(int); ok {
		limit = value
	}
	cursor, _ := arguments["cursor"].(string)
	changes, nextCursor, err := service.Store.ListIntentSummaries(ctx, scope.PrincipalID, scope.EnrollmentID, cursor, limit)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"availability": domain.Available, "source": "gar-journal", "observed_at": service.now(),
		"changes": changes, "next_cursor": nextCursor,
		"history_scope": "GAR intents visible to this principal and enrollment only",
	}, nil
}

func validateReadArguments(name string, arguments map[string]any) error {
	switch name {
	case "inspect_server_identity", "get_health", "get_players", "get_performance",
		"list_plugins", "get_backup_status":
		if len(arguments) != 0 {
			return domain.NewError(domain.ErrInvalidRequest, name+" accepts no arguments")
		}
		return nil
	case "get_recent_errors", "get_recent_changes":
		for key := range arguments {
			if key != "cursor" && key != "limit" {
				return domain.NewError(domain.ErrInvalidRequest, "unknown bounded-read argument: "+key)
			}
		}
		if cursor, ok := arguments["cursor"]; ok {
			value, valid := cursor.(string)
			if !valid || len(value) > 256 {
				return domain.NewError(domain.ErrInvalidRequest, "cursor must be a string of at most 256 bytes")
			}
		}
		if rawLimit, ok := arguments["limit"]; ok {
			limit, valid := rawLimit.(int)
			if !valid || limit < 1 || limit > 200 {
				return domain.NewError(domain.ErrInvalidRequest, "limit must be an integer from 1 through 200")
			}
		}
		return nil
	default:
		return domain.NewError(domain.ErrScopeDenied, "unknown or non-read agent tool")
	}
}

func (service *Service) Propose(
	ctx context.Context,
	scope domain.AgentSessionScope,
	input domain.ProposalInput,
) (domain.IntentRecord, error) {
	if err := input.Validate(); err != nil {
		return domain.IntentRecord{}, err
	}
	if err := service.authorize(scope, "propose_plugin_change", "", ""); err != nil {
		return domain.IntentRecord{}, err
	}
	if !contains(scope.PluginIDs, input.PluginID) {
		return domain.IntentRecord{}, domain.NewError(domain.ErrScopeDenied,
			"plugin is outside fixed session scope")
	}
	profile, err := service.Registry.ProfileFor(input.PluginID, input.TargetArtifactID)
	if err != nil {
		return domain.IntentRecord{}, err
	}
	if err := service.authorize(scope, "propose_plugin_change", input.PluginID, profile.ProfileID); err != nil {
		return domain.IntentRecord{}, err
	}
	now := service.now()
	observation, err := service.Target.Observe(ctx, service.Registry.Enrollment)
	if err != nil {
		return domain.IntentRecord{}, domain.NewError(domain.ErrPreconditionUnavailable, err.Error())
	}
	if err := service.validateObservation(observation, now, input.PluginID); err != nil {
		return domain.IntentRecord{}, err
	}
	fromArtifactID := observation.ActiveArtifacts[input.PluginID]
	fromArtifact, ok := service.Registry.Artifacts[fromArtifactID]
	if !ok {
		return domain.IntentRecord{}, domain.NewError(domain.ErrPreconditionUnavailable,
			"active artifact is not in owner catalog")
	}
	toArtifact, ok := service.Registry.Artifacts[input.TargetArtifactID]
	if !ok || !toArtifact.OwnerTrustConfirmed {
		return domain.IntentRecord{}, domain.NewError(domain.ErrUnsupportedTransition,
			"target artifact is absent from owner catalog or lacks trust confirmation")
	}
	if profile.FromArtifactID != fromArtifactID || profile.PaperTuple != service.Registry.Enrollment.PaperTuple {
		return domain.IntentRecord{}, domain.NewError(domain.ErrUnsupportedTransition,
			"transition profile does not match current A artifact and Paper tuple")
	}

	proposalDigest, err := domain.Digest(struct {
		PrincipalID  string               `json:"principal_id"`
		EnrollmentID string               `json:"enrollment_id"`
		ScopeDigest  string               `json:"scope_digest"`
		Input        domain.ProposalInput `json:"input"`
	}{scope.PrincipalID, scope.EnrollmentID, scope.ScopeDigest, input})
	if err != nil {
		return domain.IntentRecord{}, err
	}
	if existing, lookupErr := service.Store.GetIntentByClientKey(ctx, scope.PrincipalID,
		scope.EnrollmentID, input.ClientRequestID); lookupErr == nil {
		if existing.ProposalDigest != proposalDigest {
			return domain.IntentRecord{}, domain.NewError(domain.ErrIdempotencyConflict,
				"client_request_id already identifies different proposal bytes")
		}
		return existing, nil
	} else if domain.CodeOf(lookupErr) != domain.ErrNotFound {
		return domain.IntentRecord{}, lookupErr
	}

	backupRecipeDigest := domain.OfflineBackupRecipeDigest()
	intent := domain.ChangeIntent{
		SchemaVersion: "gar.change-intent.v1", IntentID: domain.NewID("intent"),
		ClientRequestID: input.ClientRequestID, PrincipalID: scope.PrincipalID,
		SessionID: scope.SessionID, CreatedAt: now,
		EnrollmentID:         service.Registry.Enrollment.EnrollmentID,
		DeploymentGeneration: service.Registry.Enrollment.DeploymentGeneration,
		ContainerID:          service.Registry.Enrollment.ContainerID,
		PaperTuple:           service.Registry.Enrollment.PaperTuple, ExpectedBootID: observation.BootID,
		WorkflowKind: "UPDATE_PLUGIN_ARTIFACT", WorkflowVersion: "gar.paper-plugin-change.v1",
		PluginID: input.PluginID, FromArtifactID: fromArtifact.ArtifactID, FromSHA256: fromArtifact.SHA256,
		ToArtifactID: toArtifact.ArtifactID, ToSHA256: toArtifact.SHA256,
		ProfileDigest: profile.ProfileDigest, ScopeDigest: scope.ScopeDigest,
		PolicyRevision:      service.Registry.Enrollment.PolicyRevision,
		PolicyDigest:        service.Registry.Enrollment.PolicyDigest,
		CapabilitySnapshot:  append([]string(nil), scope.Capabilities...),
		ObservationBundleID: observation.BundleID, InventoryDigest: observation.InventoryDigest,
		ConfigDigest:       observation.ConfigDigest,
		EvidenceReferences: []string{"observation:" + observation.BundleID},
		Predicates: []domain.Predicate{
			{Name: "target_identity", Phase: "PREPARE", Expected: service.Registry.Enrollment.ContainerID, FreshnessSeconds: 30, OnFailure: domain.ErrIntentStale},
			{Name: "active_artifact", Phase: "OFFLINE_BEFORE_REPLACE", Expected: fromArtifact.SHA256, FreshnessSeconds: 0, OnFailure: domain.ErrIntentStale},
			{Name: "players_zero", Phase: "MAINTENANCE_BARRIER", Expected: "0", FreshnessSeconds: 5, OnFailure: domain.ErrIntentStale},
		},
		Steps: append([]string(nil), domain.FixedWorkflowSteps...), ReservedBackupID: domain.NewID("backup"),
		BackupRecipeDigest:    backupRecipeDigest,
		VerificationProfileID: profile.VerificationProfileID,
		VerificationDigest:    profile.VerificationDigest,
		RecoveryContractID:    profile.RecoveryContractID, RecoveryDigest: profile.RecoveryDigest,
		ApprovalDeadline: now.Add(15 * time.Minute), StartBefore: now.Add(20 * time.Minute),
		ExecutionBudgetSeconds: 900, RecoveryBudgetSeconds: 900, Rationale: input.Rationale,
	}
	if err := intent.Seal(); err != nil {
		return domain.IntentRecord{}, err
	}
	record := domain.IntentRecord{
		Intent: intent, Status: domain.IntentAwaitingApproval,
		ProposalDigest: proposalDigest, UpdatedAt: now,
	}
	stored, _, err := service.Store.PutIntent(ctx, record)
	return stored, err
}

func (service *Service) GetOwnOperation(
	ctx context.Context,
	scope domain.AgentSessionScope,
	reference string,
) (any, error) {
	if err := service.authorize(scope, "get_operation", "", ""); err != nil {
		return nil, err
	}
	if intent, err := service.Store.GetIntent(ctx, reference); err == nil {
		if intent.Intent.PrincipalID != scope.PrincipalID || intent.Intent.EnrollmentID != scope.EnrollmentID {
			return nil, domain.NewError(domain.ErrScopeDenied, "reference belongs to another principal or target")
		}
		operation, operationErr := service.Store.OperationForIntent(ctx, intent.Intent.IntentID)
		if domain.CodeOf(operationErr) == domain.ErrNotFound {
			return map[string]any{"intent": intent, "operation": nil}, nil
		}
		if operationErr != nil {
			return nil, operationErr
		}
		return map[string]any{"intent": intent, "operation": operation}, nil
	}
	if operation, err := service.Store.GetOperation(ctx, reference); err == nil {
		return service.ownOperationResult(ctx, scope, operation)
	}
	if operation, err := service.Store.OperationForStep(ctx, reference); err == nil {
		return service.ownOperationResult(ctx, scope, operation)
	}
	intent, err := service.Store.GetIntentByClientKey(ctx, scope.PrincipalID, scope.EnrollmentID, reference)
	if err != nil {
		return nil, err
	}
	operation, operationErr := service.Store.OperationForIntent(ctx, intent.Intent.IntentID)
	if domain.CodeOf(operationErr) == domain.ErrNotFound {
		return map[string]any{"intent": intent, "operation": nil}, nil
	}
	if operationErr != nil {
		return nil, operationErr
	}
	return map[string]any{"intent": intent, "operation": operation}, nil
}

func (service *Service) ownOperationResult(
	ctx context.Context,
	scope domain.AgentSessionScope,
	operation domain.Operation,
) (any, error) {
	intent, err := service.Store.GetIntent(ctx, operation.IntentID)
	if err != nil {
		return nil, err
	}
	if intent.Intent.PrincipalID != scope.PrincipalID || intent.Intent.EnrollmentID != scope.EnrollmentID {
		return nil, domain.NewError(domain.ErrScopeDenied, "reference belongs to another principal or target")
	}
	return map[string]any{"intent": intent, "operation": operation}, nil
}

func (service *Service) authorize(
	scope domain.AgentSessionScope,
	capability, pluginID, artifactProfileID string,
) error {
	if err := scope.Validate(service.now()); err != nil {
		return err
	}
	if scope.EnrollmentID != service.Registry.Enrollment.EnrollmentID ||
		scope.DeploymentGeneration != service.Registry.Enrollment.DeploymentGeneration {
		return domain.NewError(domain.ErrScopeDenied, "session target identity does not match enrollment")
	}
	if scope.RevocationEpoch != service.CurrentRevocationEpoch {
		return domain.NewError(domain.ErrScopeDenied, "session was revoked or predates current revocation epoch")
	}
	if !contains(scope.Capabilities, capability) {
		return domain.NewError(domain.ErrScopeDenied, "capability is outside fixed session scope")
	}
	if pluginID != "" && !scope.Allows(capability, pluginID, artifactProfileID) {
		return domain.NewError(domain.ErrScopeDenied, "plugin or transition profile is outside fixed session scope")
	}
	return nil
}

type ShadowRevalidation struct {
	IntentID           string           `json:"intent_id"`
	Status             string           `json:"status"`
	Code               domain.ErrorCode `json:"code,omitempty"`
	MutationDispatched bool             `json:"mutation_dispatched"`
	CheckedAt          time.Time        `json:"checked_at"`
}

// ShadowRevalidate proves M3-style preflight behavior without dispatching stop,
// backup, filesystem, or launch operations (AT-013/014/018/026).
func (service *Service) ShadowRevalidate(
	ctx context.Context,
	scope domain.AgentSessionScope,
	intentID string,
) (ShadowRevalidation, error) {
	now := service.now()
	result := ShadowRevalidation{IntentID: intentID, Status: "SHADOW_ONLY", CheckedAt: now}
	if err := service.authorize(scope, "get_operation", "", ""); err != nil {
		result.Code = domain.CodeOf(err)
		return result, err
	}
	record, err := service.Store.GetIntent(ctx, intentID)
	if err != nil {
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if record.Intent.PrincipalID != scope.PrincipalID || record.Intent.EnrollmentID != scope.EnrollmentID {
		err = domain.NewError(domain.ErrScopeDenied, "intent belongs to another principal or target")
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if err := record.Intent.ValidateDigest(); err != nil {
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if record.Intent.PolicyRevision != service.Registry.Enrollment.PolicyRevision ||
		record.Intent.PolicyDigest != service.Registry.Enrollment.PolicyDigest {
		err = domain.NewError(domain.ErrIntentStale, "policy revision or digest changed")
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if !now.Before(record.Intent.StartBefore) {
		err = domain.NewError(domain.ErrApprovalExpired, "start_before elapsed")
		result.Code = domain.CodeOf(err)
		return result, err
	}
	observation, err := service.Target.Observe(ctx, service.Registry.Enrollment)
	if err != nil {
		err = domain.NewError(domain.ErrPreconditionUnavailable, err.Error())
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if err := service.validateObservation(observation, now, record.Intent.PluginID); err != nil {
		result.Code = domain.CodeOf(err)
		return result, err
	}
	if observation.BootID != record.Intent.ExpectedBootID ||
		observation.InventoryDigest != record.Intent.InventoryDigest ||
		observation.ConfigDigest != record.Intent.ConfigDigest ||
		observation.ActiveArtifacts[record.Intent.PluginID] != record.Intent.FromArtifactID {
		err = domain.NewError(domain.ErrIntentStale, "one or more approved identity/artifact predicates changed")
		result.Code = domain.CodeOf(err)
		return result, err
	}
	players := observation.Readings["players"]
	if fmt.Sprint(players.Value) != "0" {
		err = domain.NewError(domain.ErrIntentStale, "players_zero predicate is false")
		result.Code = domain.CodeOf(err)
		return result, err
	}
	return result, nil
}

// StartMutation is the mandatory M0/M4 release gate. The M1 binary has no
// executor, so even a synthetically PASS support profile cannot accidentally
// reach a target.
func (service *Service) StartMutation(_ context.Context, _ string) error {
	if !service.Support.MutationAllowed() || !service.MutationExecutorEnabled {
		return domain.NewError(domain.ErrUnsupportedEnvironment,
			"live mutation is disabled until G-01 through G-07 and the M4 executor are verified")
	}
	return domain.NewError(domain.ErrUnsupportedEnvironment, "M4 executor is not implemented")
}

func (service *Service) validateObservation(bundle domain.ObservationBundle, now time.Time, pluginID string) error {
	enrollment := service.Registry.Enrollment
	if bundle.EnrollmentID != enrollment.EnrollmentID ||
		bundle.DeploymentGeneration != enrollment.DeploymentGeneration ||
		bundle.ContainerID != enrollment.ContainerID {
		return domain.NewError(domain.ErrIntentStale, "authoritative target identity differs from enrollment")
	}
	if bundle.ActiveArtifacts[pluginID] == "" || bundle.InventoryDigest == "" || bundle.ConfigDigest == "" {
		return domain.NewError(domain.ErrPreconditionUnavailable, "artifact inventory or configuration evidence is missing")
	}
	players, ok := bundle.Readings["players"]
	if !ok {
		return domain.NewError(domain.ErrPreconditionUnavailable, "players observation is missing")
	}
	if err := domain.RequireAvailable("players", players, now, 5*time.Second, bundle.BootID); err != nil {
		return err
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func ProposalBytes(input domain.ProposalInput) []byte {
	payload, _ := domain.CanonicalJSON(input)
	return bytes.Clone(payload)
}
