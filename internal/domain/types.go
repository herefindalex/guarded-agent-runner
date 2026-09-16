package domain

import (
	"fmt"
	"time"
)

type Availability string

const (
	Available   Availability = "AVAILABLE"
	Unavailable Availability = "UNAVAILABLE"
	Stale       Availability = "STALE"
	Conflicting Availability = "CONFLICTING"
)

type GateStatus string

const (
	GateNotRun GateStatus = "NOT_RUN"
	GatePass   GateStatus = "PASS"
	GateFail   GateStatus = "FAIL"
)

type IntentStatus string

const (
	IntentProposed         IntentStatus = "PROPOSED"
	IntentAwaitingApproval IntentStatus = "AWAITING_APPROVAL"
	IntentApproved         IntentStatus = "APPROVED"
	IntentConsumed         IntentStatus = "CONSUMED"
	IntentRejected         IntentStatus = "REJECTED"
	IntentExpired          IntentStatus = "EXPIRED"
	IntentRevoked          IntentStatus = "REVOKED"
	IntentCancelled        IntentStatus = "CANCELLED"
	IntentStale            IntentStatus = "STALE"
)

type OperationStatus string

const (
	OperationQueued            OperationStatus = "QUEUED"
	OperationPreparing         OperationStatus = "PREPARING"
	OperationExecuting         OperationStatus = "EXECUTING"
	OperationVerifying         OperationStatus = "VERIFYING"
	OperationSucceeded         OperationStatus = "SUCCEEDED"
	OperationFailed            OperationStatus = "FAILED"
	OperationAborted           OperationStatus = "ABORTED"
	OperationUnknown           OperationStatus = "UNKNOWN"
	OperationRollbackRequired  OperationStatus = "ROLLBACK_REQUIRED"
	OperationRollingBack       OperationStatus = "ROLLING_BACK"
	OperationRolledBack        OperationStatus = "ROLLED_BACK"
	OperationRollbackFailed    OperationStatus = "ROLLBACK_FAILED"
	OperationNeedsIntervention OperationStatus = "NEEDS_INTERVENTION"
)

type VerificationStatus string

const (
	VerificationNotStarted   VerificationStatus = "NOT_STARTED"
	VerificationRunning      VerificationStatus = "RUNNING"
	VerificationPass         VerificationStatus = "PASS"
	VerificationFail         VerificationStatus = "FAIL"
	VerificationInconclusive VerificationStatus = "INCONCLUSIVE"
)

type DispatchState string

const (
	NotDispatched    DispatchState = "NOT_DISPATCHED"
	DispatchPossible DispatchState = "DISPATCH_POSSIBLE"
	Acknowledged     DispatchState = "ACKNOWLEDGED"
)

type EffectState string

const (
	EffectProvenNotApplied EffectState = "PROVEN_NOT_APPLIED"
	EffectExpectedObserved EffectState = "EXPECTED_STATE_OBSERVED"
	EffectOtherObserved    EffectState = "OTHER_STATE_OBSERVED"
	EffectUnknown          EffectState = "UNKNOWN"
)

type Attribution string

const (
	AttributionCorrelated   Attribution = "CORRELATED"
	AttributionUnattributed Attribution = "UNATTRIBUTED"
	AttributionConflicting  Attribution = "CONFLICTING"
)

type AgentSessionScope struct {
	SchemaVersion        string    `json:"schema_version"`
	PrincipalID          string    `json:"principal_id"`
	SessionID            string    `json:"session_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	DeploymentGeneration int64     `json:"deployment_generation"`
	Capabilities         []string  `json:"capabilities"`
	PluginIDs            []string  `json:"plugin_ids"`
	ArtifactProfileIDs   []string  `json:"artifact_profile_ids"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	RevocationEpoch      int64     `json:"revocation_epoch"`
	ScopeDigest          string    `json:"scope_digest"`
}

func (scope AgentSessionScope) digestPayload() any {
	return struct {
		SchemaVersion        string   `json:"schema_version"`
		PrincipalID          string   `json:"principal_id"`
		SessionID            string   `json:"session_id"`
		EnrollmentID         string   `json:"enrollment_id"`
		DeploymentGeneration int64    `json:"deployment_generation"`
		Capabilities         []string `json:"capabilities"`
		PluginIDs            []string `json:"plugin_ids"`
		ArtifactProfileIDs   []string `json:"artifact_profile_ids"`
		IssuedAt             string   `json:"issued_at"`
		ExpiresAt            string   `json:"expires_at"`
		RevocationEpoch      int64    `json:"revocation_epoch"`
	}{
		SchemaVersion: scope.SchemaVersion, PrincipalID: scope.PrincipalID,
		SessionID: scope.SessionID, EnrollmentID: scope.EnrollmentID,
		DeploymentGeneration: scope.DeploymentGeneration,
		Capabilities:         SortedCopy(scope.Capabilities), PluginIDs: SortedCopy(scope.PluginIDs),
		ArtifactProfileIDs: SortedCopy(scope.ArtifactProfileIDs),
		IssuedAt:           scope.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:          scope.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RevocationEpoch:    scope.RevocationEpoch,
	}
}

func (scope *AgentSessionScope) Seal() error {
	digest, err := Digest(scope.digestPayload())
	if err != nil {
		return err
	}
	scope.ScopeDigest = digest
	return nil
}

func (scope AgentSessionScope) Validate(now time.Time) error {
	digest, err := Digest(scope.digestPayload())
	if err != nil {
		return err
	}
	if digest != scope.ScopeDigest {
		return NewError(ErrScopeDenied, "session scope digest mismatch")
	}
	if !now.Before(scope.ExpiresAt) {
		return NewError(ErrScopeDenied, "agent session expired")
	}
	return nil
}

func (scope AgentSessionScope) Allows(capability, pluginID, artifactProfileID string) bool {
	return contains(scope.Capabilities, capability) && contains(scope.PluginIDs, pluginID) &&
		contains(scope.ArtifactProfileIDs, artifactProfileID)
}

type Enrollment struct {
	TargetID             string   `json:"target_id"`
	EnrollmentID         string   `json:"enrollment_id"`
	DeploymentGeneration int64    `json:"deployment_generation"`
	ContainerID          string   `json:"container_id"`
	ImageDigest          string   `json:"image_digest"`
	DataRootIdentity     string   `json:"data_root_identity"`
	GameEndpoint         string   `json:"game_endpoint"`
	RuntimeGuardPairing  string   `json:"runtime_guard_pairing"`
	BootstrapFingerprint string   `json:"bootstrap_fingerprint"`
	PolicyID             string   `json:"policy_id"`
	PolicyRevision       string   `json:"policy_revision"`
	PolicyDigest         string   `json:"policy_digest"`
	SupportProfileID     string   `json:"support_profile_id"`
	PaperTuple           string   `json:"paper_tuple"`
	AllowedPlugins       []string `json:"allowed_plugins"`
}

type ArtifactRecord struct {
	ArtifactID            string    `json:"artifact_id"`
	SHA256                string    `json:"sha256"`
	Size                  int64     `json:"size"`
	SourceDescription     string    `json:"source_description"`
	AcquiredAt            time.Time `json:"acquired_at"`
	PluginID              string    `json:"plugin_id"`
	DescriptorDigest      string    `json:"descriptor_digest"`
	OwnerTrustConfirmed   bool      `json:"owner_trust_confirmed"`
	CompatibilityEvidence string    `json:"compatibility_evidence"`
}

type TransitionProfile struct {
	ProfileID             string   `json:"profile_id"`
	ProfileDigest         string   `json:"profile_digest"`
	PluginID              string   `json:"plugin_id"`
	FromArtifactID        string   `json:"from_artifact_id"`
	ToArtifactID          string   `json:"to_artifact_id"`
	PaperTuple            string   `json:"paper_tuple"`
	DependencyInventory   []string `json:"dependency_inventory"`
	WritableDataLocations []string `json:"writable_data_locations"`
	MigrationDeclared     bool     `json:"migration_declared"`
	VerificationProfileID string   `json:"verification_profile_id"`
	VerificationDigest    string   `json:"verification_digest"`
	RecoveryContractID    string   `json:"recovery_contract_id"`
	RecoveryDigest        string   `json:"recovery_digest"`
	Eligibility           string   `json:"eligibility"`
}

type ObservationValue struct {
	Availability Availability `json:"availability"`
	Value        any          `json:"value,omitempty"`
	Unit         string       `json:"unit,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	Source       string       `json:"source"`
	ObservedAt   time.Time    `json:"observed_at"`
	BootID       string       `json:"boot_id,omitempty"`
}

type ObservationBundle struct {
	BundleID             string                      `json:"bundle_id"`
	EnrollmentID         string                      `json:"enrollment_id"`
	DeploymentGeneration int64                       `json:"deployment_generation"`
	ContainerID          string                      `json:"container_id"`
	BootID               string                      `json:"boot_id"`
	InventoryDigest      string                      `json:"inventory_digest"`
	ConfigDigest         string                      `json:"config_digest"`
	ActiveArtifacts      map[string]string           `json:"active_artifacts"`
	Readings             map[string]ObservationValue `json:"readings"`
	CreatedAt            time.Time                   `json:"created_at"`
}

type Predicate struct {
	Name             string    `json:"name"`
	Phase            string    `json:"phase"`
	Expected         string    `json:"expected"`
	FreshnessSeconds int64     `json:"freshness_seconds"`
	OnFailure        ErrorCode `json:"on_failure"`
}

type ChangeIntent struct {
	SchemaVersion          string      `json:"schema_version"`
	IntentID               string      `json:"intent_id"`
	ClientRequestID        string      `json:"client_request_id"`
	PrincipalID            string      `json:"principal_id"`
	SessionID              string      `json:"session_id"`
	CreatedAt              time.Time   `json:"created_at"`
	EnrollmentID           string      `json:"enrollment_id"`
	DeploymentGeneration   int64       `json:"deployment_generation"`
	ContainerID            string      `json:"container_id"`
	PaperTuple             string      `json:"paper_tuple"`
	ExpectedBootID         string      `json:"expected_boot_id"`
	WorkflowKind           string      `json:"workflow_kind"`
	WorkflowVersion        string      `json:"workflow_version"`
	PluginID               string      `json:"plugin_id"`
	FromArtifactID         string      `json:"from_artifact_id"`
	FromSHA256             string      `json:"from_sha256"`
	ToArtifactID           string      `json:"to_artifact_id"`
	ToSHA256               string      `json:"to_sha256"`
	ProfileDigest          string      `json:"profile_digest"`
	ScopeDigest            string      `json:"scope_digest"`
	PolicyRevision         string      `json:"policy_revision"`
	PolicyDigest           string      `json:"policy_digest"`
	CapabilitySnapshot     []string    `json:"capability_snapshot"`
	ObservationBundleID    string      `json:"observation_bundle_id"`
	InventoryDigest        string      `json:"inventory_digest"`
	ConfigDigest           string      `json:"config_digest"`
	EvidenceReferences     []string    `json:"evidence_references"`
	Predicates             []Predicate `json:"predicates"`
	Steps                  []string    `json:"steps"`
	ReservedBackupID       string      `json:"reserved_backup_id"`
	BackupRecipeDigest     string      `json:"backup_recipe_digest"`
	VerificationProfileID  string      `json:"verification_profile_id"`
	VerificationDigest     string      `json:"verification_digest"`
	RecoveryContractID     string      `json:"recovery_contract_id"`
	RecoveryDigest         string      `json:"recovery_digest"`
	ApprovalDeadline       time.Time   `json:"approval_deadline"`
	StartBefore            time.Time   `json:"start_before"`
	ExecutionBudgetSeconds int64       `json:"execution_budget_seconds"`
	RecoveryBudgetSeconds  int64       `json:"recovery_budget_seconds"`
	Rationale              string      `json:"rationale"`
	IntentDigest           string      `json:"intent_digest"`
}

func (intent ChangeIntent) digestPayload() ChangeIntent {
	copy := intent
	copy.IntentDigest = ""
	copy.CapabilitySnapshot = SortedCopy(copy.CapabilitySnapshot)
	copy.EvidenceReferences = SortedCopy(copy.EvidenceReferences)
	return copy
}

func (intent *ChangeIntent) Seal() error {
	digest, err := Digest(intent.digestPayload())
	if err != nil {
		return err
	}
	intent.IntentDigest = digest
	return nil
}

func (intent ChangeIntent) ValidateDigest() error {
	digest, err := Digest(intent.digestPayload())
	if err != nil {
		return err
	}
	if digest != intent.IntentDigest {
		return NewError(ErrInvalidIntentDigest, "change intent digest mismatch")
	}
	return nil
}

type IntentRecord struct {
	Intent         ChangeIntent `json:"intent"`
	Status         IntentStatus `json:"status"`
	ProposalDigest string       `json:"proposal_digest"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type Approval struct {
	ApprovalID        string    `json:"approval_id"`
	IntentID          string    `json:"intent_id"`
	IntentDigest      string    `json:"intent_digest"`
	ApproverPrincipal string    `json:"approver_principal"`
	ApproverOSUID     int       `json:"approver_os_uid"`
	Decision          string    `json:"decision"`
	DecidedAt         time.Time `json:"decided_at"`
}

type StepAttempt struct {
	StepID        string        `json:"step_id"`
	StepKind      string        `json:"step_kind"`
	AttemptNo     int           `json:"attempt_no"`
	DispatchState DispatchState `json:"dispatch_state"`
	EffectState   EffectState   `json:"effect_state"`
	Attribution   Attribution   `json:"attribution"`
	PreparedAt    time.Time     `json:"prepared_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
	Evidence      []string      `json:"evidence"`
}

type Operation struct {
	OperationID       string             `json:"operation_id"`
	IntentID          string             `json:"intent_id"`
	IntentDigest      string             `json:"intent_digest"`
	EnrollmentID      string             `json:"enrollment_id"`
	ExecutionEpoch    int64              `json:"execution_epoch"`
	Status            OperationStatus    `json:"status"`
	Verification      VerificationStatus `json:"verification"`
	OwnershipReleased bool               `json:"ownership_released"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	Attempts          []StepAttempt      `json:"attempts"`
	LastError         ErrorCode          `json:"last_error,omitempty"`
}

type ProposalInput struct {
	PluginID         string `json:"plugin_id"`
	TargetArtifactID string `json:"target_artifact_id"`
	ClientRequestID  string `json:"client_request_id"`
	Rationale        string `json:"rationale"`
}

func (input ProposalInput) Validate() error {
	if input.PluginID == "" || input.TargetArtifactID == "" || input.ClientRequestID == "" {
		return NewError(ErrInvalidRequest, "plugin_id, target_artifact_id, and client_request_id are required")
	}
	if len(input.Rationale) > 2000 {
		return NewError(ErrInvalidRequest, "rationale exceeds 2000 bytes")
	}
	return nil
}

type ToolDefinition struct {
	Name       string `json:"name"`
	Permission string `json:"permission"`
}

var AgentTools = []ToolDefinition{
	{Name: "inspect_server_identity", Permission: "read"},
	{Name: "get_health", Permission: "read"},
	{Name: "get_players", Permission: "read"},
	{Name: "get_performance", Permission: "read"},
	{Name: "get_recent_errors", Permission: "bounded-read"},
	{Name: "list_plugins", Permission: "read"},
	{Name: "get_recent_changes", Permission: "read"},
	{Name: "get_backup_status", Permission: "read"},
	{Name: "propose_plugin_change", Permission: "propose"},
	{Name: "get_operation", Permission: "read-own"},
}

var FixedWorkflowSteps = []string{
	"S00_CLAIM_OPERATION",
	"S01_REVALIDATE",
	"S02_ACQUIRE_MAINTENANCE",
	"S03_GRACEFUL_STOP",
	"S04_OFFLINE_REVALIDATION",
	"S05_CREATE_BACKUP",
	"S06_REPLACE_ARTIFACT",
	"S07_PREPARE_LAUNCH_AND_START",
	"S08_VERIFY_UNDER_MAINTENANCE",
	"S09_RELEASE_MAINTENANCE",
	"S10_FINALIZE",
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func RequireAvailable(name string, value ObservationValue, now time.Time, maxAge time.Duration, bootID string) error {
	if value.Availability != Available {
		return NewError(ErrPreconditionUnavailable, fmt.Sprintf("%s is %s: %s", name, value.Availability, value.Reason))
	}
	if now.Sub(value.ObservedAt) > maxAge || (value.BootID != "" && value.BootID != bootID) {
		return NewError(ErrPreconditionUnavailable, fmt.Sprintf("%s is stale or belongs to another boot", name))
	}
	return nil
}
