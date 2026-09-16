package workflow

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/store"
)

type fixture struct {
	service *Service
	store   *store.Store
	scope   domain.AgentSessionScope
	target  *FakeTarget
	now     time.Time
	dbPath  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	// SaveSession validates against the real clock before the service's injected
	// clock is available. Keep the fixture deterministic within each test run,
	// but do not let a calendar date turn the suite permanently expired.
	now := time.Now().UTC().Truncate(time.Second)
	dbPath := filepath.Join(t.TempDir(), "gar.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	enrollment := domain.Enrollment{
		TargetID: "paper-a", EnrollmentID: "enrollment-a", DeploymentGeneration: 3,
		ContainerID: "sha256:container-a", ImageDigest: "sha256:image-a",
		DataRootIdentity: "dev:1/inode:2", GameEndpoint: "127.0.0.1:25565",
		RuntimeGuardPairing: "guard-a", BootstrapFingerprint: "bootstrap-a",
		PolicyID: "policy-a", PolicyRevision: "7", PolicyDigest: "policy-digest-a",
		SupportProfileID: "m1-fake", PaperTuple: "paper-test/java-test/itzg-test",
		AllowedPlugins: []string{"example"},
	}
	artifacts := map[string]domain.ArtifactRecord{
		"artifact-a": {
			ArtifactID: "artifact-a", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Size: 100, PluginID: "example", OwnerTrustConfirmed: true,
		},
		"artifact-b": {
			ArtifactID: "artifact-b", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Size: 101, PluginID: "example", OwnerTrustConfirmed: true,
		},
	}
	profile := domain.TransitionProfile{
		ProfileID: "example-a-b", ProfileDigest: "profile-digest-a-b", PluginID: "example",
		FromArtifactID: "artifact-a", ToArtifactID: "artifact-b", PaperTuple: enrollment.PaperTuple,
		VerificationProfileID: "verify-a-b", VerificationDigest: "verify-digest-a-b",
		RecoveryContractID: "recover-b-a", RecoveryDigest: "recover-digest-b-a",
		Eligibility: "VERIFIED_TRANSITION",
	}
	target := &FakeTarget{
		Observation: domain.ObservationBundle{
			BundleID: "observation-a", EnrollmentID: enrollment.EnrollmentID,
			DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: enrollment.ContainerID,
			BootID: "boot-a", InventoryDigest: "inventory-a", ConfigDigest: "config-a",
			ActiveArtifacts: map[string]string{"example": "artifact-a"}, CreatedAt: now,
			Readings: map[string]domain.ObservationValue{
				"players": {Availability: domain.Available, Value: 0, Source: "paper-guard", ObservedAt: now, BootID: "boot-a"},
			},
		},
		Responses: map[string]any{
			"get_health": map[string]any{"availability": domain.Available, "process": "RUNNING"},
		},
	}
	capabilities := make([]string, 0, len(domain.AgentTools))
	for _, tool := range domain.AgentTools {
		capabilities = append(capabilities, tool.Name)
	}
	scope := domain.AgentSessionScope{
		SchemaVersion: "gar.agent-scope.v1", PrincipalID: "agent-a", SessionID: "session-a",
		EnrollmentID: enrollment.EnrollmentID, DeploymentGeneration: enrollment.DeploymentGeneration,
		Capabilities: capabilities, PluginIDs: []string{"example"}, ArtifactProfileIDs: []string{profile.ProfileID},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), RevocationEpoch: 1,
	}
	if err := scope.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSession(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	service := &Service{
		Store: db, Registry: Registry{Enrollment: enrollment, Artifacts: artifacts,
			Profiles: map[string]domain.TransitionProfile{profile.ProfileID: profile}},
		Target: target, Support: policy.DefaultM1Profile(), CurrentRevocationEpoch: 1,
		Now: func() time.Time { return now },
	}
	return fixture{service: service, store: db, scope: scope, target: target, now: now, dbPath: dbPath}
}

func proposal(key, rationale string) domain.ProposalInput {
	return domain.ProposalInput{
		PluginID: "example", TargetArtifactID: "artifact-b", ClientRequestID: key, Rationale: rationale,
	}
}

// AT-001: agent surface has no approval capability or redeemable approval token.
func TestAgentToolCatalogHasNoApprovalTool(t *testing.T) {
	fx := newFixture(t)
	for _, tool := range fx.service.Tools() {
		if tool.Name == "approve" || tool.Name == "intent-approve" {
			t.Fatalf("agent tool catalog contains privileged tool %q", tool.Name)
		}
	}
	if len(fx.service.Tools()) != 10 {
		t.Fatalf("expected fixed ten-tool catalog, got %d", len(fx.service.Tools()))
	}
	if fx.service.Support.MutationAllowed() {
		t.Fatal("M1 support profile must block real mutation")
	}
}

// AT-005/006: identical proposal bytes reuse the intent; changed bytes conflict.
func TestProposalIdempotencyFreezesFirstObservation(t *testing.T) {
	fx := newFixture(t)
	first, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-1", "test update"))
	if err != nil {
		t.Fatal(err)
	}
	fx.target.Observation.BundleID = "new-observation-must-not-replace-frozen-intent"
	second, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-1", "test update"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Intent.IntentID != second.Intent.IntentID || second.Intent.ObservationBundleID != "observation-a" {
		t.Fatal("idempotent replay replaced frozen intent or observation")
	}
	_, err = fx.service.Propose(context.Background(), fx.scope, proposal("request-1", "different bytes"))
	if domain.CodeOf(err) != domain.ErrIdempotencyConflict {
		t.Fatalf("expected IDEMPOTENCY_CONFLICT, got %v", err)
	}
	if fx.target.Mutations != 0 {
		t.Fatal("proposal path mutated target")
	}
}

// AT-018: unavailable is not zero and cannot produce an approvable intent.
func TestUnavailablePlayersFailsClosed(t *testing.T) {
	fx := newFixture(t)
	fx.target.Observation.Readings["players"] = domain.ObservationValue{
		Availability: domain.Unavailable, Reason: "guard timeout", Source: "paper-guard",
		ObservedAt: fx.now, BootID: "boot-a",
	}
	_, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-unavailable", "test"))
	if domain.CodeOf(err) != domain.ErrPreconditionUnavailable {
		t.Fatalf("expected PRECONDITION_UNAVAILABLE, got %v", err)
	}
}

// AT-009/010: current authority may tighten, but an old scope never expands.
func TestRevokedSessionCannotPropose(t *testing.T) {
	fx := newFixture(t)
	fx.service.CurrentRevocationEpoch = 2
	_, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-revoked", "test"))
	if domain.CodeOf(err) != domain.ErrScopeDenied {
		t.Fatalf("expected SCOPE_DENIED, got %v", err)
	}
}

// AT-037: arbitrary path/URL/container fields are schema errors.
func TestProposalSchemaRejectsEscapeHatches(t *testing.T) {
	_, err := DecodeProposal(bytes.NewBufferString(`{
        "plugin_id":"example","target_artifact_id":"artifact-b",
        "client_request_id":"request-escape","rationale":"x",
        "url":"https://attacker.invalid/plugin.jar"
    }`))
	if domain.CodeOf(err) != domain.ErrInvalidRequest {
		t.Fatalf("expected INVALID_REQUEST, got %v", err)
	}
}

func TestBoundedReadRejectsUnboundedOrUnknownArguments(t *testing.T) {
	fx := newFixture(t)
	if _, err := fx.service.CallReadTool(context.Background(), fx.scope, "get_recent_errors",
		map[string]any{"limit": 201}); domain.CodeOf(err) != domain.ErrInvalidRequest {
		t.Fatalf("expected bounded limit rejection, got %v", err)
	}
	if _, err := fx.service.CallReadTool(context.Background(), fx.scope, "get_health",
		map[string]any{"path": "/data/server.log"}); domain.CodeOf(err) != domain.ErrInvalidRequest {
		t.Fatalf("expected arbitrary argument rejection, got %v", err)
	}
}

func TestReadToolsExposeScopedCatalogAndJournalHistory(t *testing.T) {
	fx := newFixture(t)
	fx.target.Responses = map[string]any{
		"list_plugins": map[string]any{"availability": domain.Available, "plugins": []any{}},
	}
	plugins, err := fx.service.CallReadTool(context.Background(), fx.scope, "list_plugins", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	pluginResult := plugins.(map[string]any)
	if len(pluginResult["catalog_artifacts"].([]map[string]any)) != 2 ||
		len(pluginResult["verified_transitions"].([]map[string]any)) != 1 {
		t.Fatalf("scoped catalog evidence missing: %#v", pluginResult)
	}
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("history-key", "bounded history test"))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := fx.service.CallReadTool(context.Background(), fx.scope, "get_recent_changes", map[string]any{"limit": 1})
	if err != nil {
		t.Fatal(err)
	}
	changeResult := changes.(map[string]any)
	summaries := changeResult["changes"].([]store.IntentSummary)
	if len(summaries) != 1 || summaries[0].IntentID != record.Intent.IntentID || summaries[0].ClientRequestID != "history-key" {
		t.Fatalf("principal-scoped journal history missing: %#v", changeResult)
	}
}

// AT-002/003/004: approval is exact, atomic, and replay returns one operation.
func TestOperatorApprovalUsesExactDigestAndSingleClaim(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-approve", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	if _, _, err := operator.Approve(context.Background(), record.Intent.IntentID, "wrong", "owner", 1000); domain.CodeOf(err) != domain.ErrInvalidIntentDigest {
		t.Fatalf("expected exact digest rejection, got %v", err)
	}
	approval, operation, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	replayedApproval, replayedOperation, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner-2", 1001)
	if err != nil {
		t.Fatal(err)
	}
	if approval.ApprovalID != replayedApproval.ApprovalID || operation.OperationID != replayedOperation.OperationID {
		t.Fatal("approval retry created a second durable claim")
	}
}

// AT-003: simultaneous approvers converge on one durable approval/operation.
func TestConcurrentApprovalsConvergeOnOneOperation(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-concurrent", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	type result struct {
		approvalID  string
		operationID string
		err         error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < 2; index++ {
		go func(uid int) {
			start.Wait()
			approval, operation, approveErr := operator.Approve(context.Background(), record.Intent.IntentID,
				record.Intent.IntentDigest, "owner", uid)
			results <- result{approval.ApprovalID, operation.OperationID, approveErr}
		}(1000 + index)
	}
	start.Done()
	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent approval errors: %v / %v", first.err, second.err)
	}
	if first.approvalID != second.approvalID || first.operationID != second.operationID {
		t.Fatalf("concurrent approvals created multiple claims: %+v / %+v", first, second)
	}
}

// AT-008: approval after the frozen deadline cannot create an operation.
func TestExpiredIntentCannotBeApproved(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-expired", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now.Add(30 * time.Minute) }}
	_, _, err = operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if domain.CodeOf(err) != domain.ErrApprovalExpired {
		t.Fatalf("expected APPROVAL_EXPIRED, got %v", err)
	}
}

func TestRejectedIntentCannotLaterBeApproved(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-reject", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	decision, err := operator.Reject(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if err != nil || decision.Decision != "REJECTED" {
		t.Fatalf("reject failed: %+v err=%v", decision, err)
	}
	if _, _, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000); domain.CodeOf(err) != domain.ErrApprovalRevoked {
		t.Fatalf("expected rejected intent to stay closed, got %v", err)
	}
}

func TestRevocationBeforeFirstStepAbortsAndReleasesOwnership(t *testing.T) {
	fx := newFixture(t)
	first, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-revoke-1", "first"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	_, operation, err := operator.Approve(context.Background(), first.Intent.IntentID,
		first.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := operator.Revoke(context.Background(), first.Intent.IntentID,
		first.Intent.IntentDigest, "owner", 1000); err != nil {
		t.Fatal(err)
	}
	aborted, err := fx.store.GetOperation(context.Background(), operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if aborted.Status != domain.OperationAborted || !aborted.OwnershipReleased {
		t.Fatalf("queued revocation did not safely release ownership: %+v", aborted)
	}
	second, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-revoke-2", "second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := operator.Approve(context.Background(), second.Intent.IntentID,
		second.Intent.IntentDigest, "owner", 1000); err != nil {
		t.Fatalf("released ownership should admit next exact operation: %v", err)
	}
}

// AT-034/060: active ownership blocks a second operation; UNKNOWN is stronger.
func TestWriterOwnershipAndUnknownBlockNewIntent(t *testing.T) {
	fx := newFixture(t)
	first, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-owner-1", "first"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	_, operation, err := operator.Approve(context.Background(), first.Intent.IntentID,
		first.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-owner-2", "second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := operator.Approve(context.Background(), second.Intent.IntentID,
		second.Intent.IntentDigest, "owner", 1000); domain.CodeOf(err) != domain.ErrTargetBusy {
		t.Fatalf("expected TARGET_BUSY, got %v", err)
	}
	if err := fx.store.MarkUnknown(context.Background(), operation.OperationID, fx.now); err != nil {
		t.Fatal(err)
	}
	third, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-owner-3", "third"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := operator.Approve(context.Background(), third.Intent.IntentID,
		third.Intent.IntentDigest, "owner", 1000); domain.CodeOf(err) != domain.ErrTargetBlockedUnknown {
		t.Fatalf("expected TARGET_BLOCKED_UNKNOWN, got %v", err)
	}
}

// AT-013/014/018/026: shadow revalidation produces no target mutation.
func TestShadowRevalidationDistinguishesStaleFromUnavailable(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-shadow", "test"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := fx.service.ShadowRevalidate(context.Background(), fx.scope, record.Intent.IntentID)
	if err != nil || result.Status != "SHADOW_ONLY" || result.MutationDispatched {
		t.Fatalf("unexpected shadow result: %+v err=%v", result, err)
	}
	fx.target.Observation.ActiveArtifacts["example"] = "artifact-other"
	result, err = fx.service.ShadowRevalidate(context.Background(), fx.scope, record.Intent.IntentID)
	if domain.CodeOf(err) != domain.ErrIntentStale || result.MutationDispatched {
		t.Fatalf("expected zero-dispatch INTENT_STALE, got %+v err=%v", result, err)
	}
	fx.target.Observation.ActiveArtifacts["example"] = "artifact-a"
	fx.target.Observation.Readings["players"] = domain.ObservationValue{
		Availability: domain.Unavailable, Reason: "guard timeout", Source: "guard",
		ObservedAt: fx.now, BootID: "boot-a",
	}
	result, err = fx.service.ShadowRevalidate(context.Background(), fx.scope, record.Intent.IntentID)
	if domain.CodeOf(err) != domain.ErrPreconditionUnavailable || result.MutationDispatched {
		t.Fatalf("expected PRECONDITION_UNAVAILABLE, got %+v err=%v", result, err)
	}
}

// AT-010: changing current policy invalidates the old frozen intent.
func TestShadowRevalidationRejectsPolicyDrift(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-policy", "test"))
	if err != nil {
		t.Fatal(err)
	}
	fx.service.Registry.Enrollment.PolicyRevision = "8"
	result, err := fx.service.ShadowRevalidate(context.Background(), fx.scope, record.Intent.IntentID)
	if domain.CodeOf(err) != domain.ErrIntentStale || result.MutationDispatched {
		t.Fatalf("expected zero-dispatch INTENT_STALE, got %+v err=%v", result, err)
	}
}

func TestM1CannotDispatchMutationEvenWithSyntheticPassingGates(t *testing.T) {
	fx := newFixture(t)
	for _, gate := range policy.RequiredMutationGates {
		fx.service.Support.Gates[gate] = domain.GatePass
	}
	fx.service.Support.Mode = policy.ModeMutation
	if err := fx.service.StartMutation(context.Background(), "operation-impossible"); domain.CodeOf(err) != domain.ErrUnsupportedEnvironment {
		t.Fatalf("expected UNSUPPORTED_ENVIRONMENT, got %v", err)
	}
}

// AT-049: STEP_PREPARED is durable before any external dispatch and survives reopen.
func TestPreparedStepSurvivesStoreReopen(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-step", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	_, operation, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S01_REVALIDATE", fx.now); domain.CodeOf(err) != domain.ErrScopeDenied {
		t.Fatalf("out-of-order workflow step should be denied, got %v", err)
	}
	attempt, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S00_CLAIM_OPERATION", fx.now)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.DispatchState != domain.NotDispatched || attempt.EffectState != domain.EffectProvenNotApplied {
		t.Fatalf("prepared step must be proven not dispatched/applied, got %+v", attempt)
	}
	if err := fx.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(fx.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.GetOperation(context.Background(), operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Attempts) != 1 || recovered.Attempts[0].StepID != attempt.StepID ||
		recovered.Attempts[0].DispatchState != domain.NotDispatched {
		t.Fatalf("prepared step was not recovered exactly: %+v", recovered.Attempts)
	}
	fx.service.Store = reopened
	byOperation, err := fx.service.GetOwnOperation(context.Background(), fx.scope, operation.OperationID)
	if err != nil || byOperation == nil {
		t.Fatalf("operation reference lookup failed: value=%v err=%v", byOperation, err)
	}
	byStep, err := fx.service.GetOwnOperation(context.Background(), fx.scope, attempt.StepID)
	if err != nil || byStep == nil {
		t.Fatalf("step reference lookup failed: value=%v err=%v", byStep, err)
	}
}

func TestDurableDispatchEvidenceControlsNextStep(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-dispatch", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	_, operation, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	first, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S00_CLAIM_OPERATION", fx.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.store.MarkDispatchPossible(context.Background(), operation.OperationID, first.StepID, fx.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S01_REVALIDATE", fx.now); domain.CodeOf(err) != domain.ErrDispatchOutcomeUnknown {
		t.Fatalf("unknown prior effect should block next step, got %v", err)
	}
	if err := fx.store.RecordStepObservation(context.Background(), operation.OperationID, first.StepID,
		domain.EffectExpectedObserved, domain.AttributionUnattributed,
		[]string{"external state without dispatch correlation"}, fx.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S01_REVALIDATE", fx.now); domain.CodeOf(err) != domain.ErrDispatchOutcomeUnknown {
		t.Fatalf("unattributed expected state should block next step, got %v", err)
	}
	if err := fx.store.RecordStepObservation(context.Background(), operation.OperationID, first.StepID,
		domain.EffectExpectedObserved, domain.AttributionCorrelated,
		[]string{"writer receipt epoch=1"}, fx.now); err != nil {
		t.Fatal(err)
	}
	second, err := fx.store.PrepareStep(context.Background(), operation.OperationID,
		"S01_REVALIDATE", fx.now)
	if err != nil {
		t.Fatal(err)
	}
	if second.StepKind != "S01_REVALIDATE" {
		t.Fatalf("unexpected next step: %+v", second)
	}
}

func TestOperationStateMachineFailsClosed(t *testing.T) {
	fx := newFixture(t)
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("request-state", "test"))
	if err != nil {
		t.Fatal(err)
	}
	operator := OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}
	_, operation, err := operator.Approve(context.Background(), record.Intent.IntentID,
		record.Intent.IntentDigest, "owner", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationSucceeded, domain.VerificationPass, true, fx.now); domain.CodeOf(err) != domain.ErrScopeDenied {
		t.Fatalf("skipping state machine should be denied, got %v", err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationPreparing, domain.VerificationNotStarted, false, fx.now); err != nil {
		t.Fatal(err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationExecuting, domain.VerificationNotStarted, false, fx.now); err != nil {
		t.Fatal(err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationVerifying, domain.VerificationInconclusive, false, fx.now); err != nil {
		t.Fatal(err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationSucceeded, domain.VerificationInconclusive, true, fx.now); domain.CodeOf(err) != domain.ErrVerificationInconclusive {
		t.Fatalf("INCONCLUSIVE must not succeed, got %v", err)
	}
	if err := fx.store.TransitionOperation(context.Background(), operation.OperationID,
		domain.OperationSucceeded, domain.VerificationPass, true, fx.now); err != nil {
		t.Fatal(err)
	}
	completed, err := fx.store.GetOperation(context.Background(), operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != domain.OperationSucceeded || !completed.OwnershipReleased {
		t.Fatalf("verified terminal operation did not release ownership: %+v", completed)
	}
	if err := fx.store.MarkUnknown(context.Background(), operation.OperationID, fx.now); domain.CodeOf(err) != domain.ErrScopeDenied {
		t.Fatalf("terminal operation must not transition back to UNKNOWN, got %v", err)
	}
	unchanged, err := fx.store.GetOperation(context.Background(), operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Status != domain.OperationSucceeded || !unchanged.OwnershipReleased {
		t.Fatalf("rejected UNKNOWN transition corrupted terminal ownership: %+v", unchanged)
	}
}
