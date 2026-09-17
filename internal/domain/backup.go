package domain

import (
	"fmt"
	"time"
)

// G03 is an offline-only foundation. These types confer no executor authority.
type StopState string

const (
	StopNotRequested     StopState = "NOT_REQUESTED"
	StopDispatchPossible StopState = "DISPATCH_POSSIBLE"
	StopStopping         StopState = "STOPPING"
	StopConfirmed        StopState = "STOPPED_CONFIRMED"
	StopFailed           StopState = "FAILED"
	StopUnknown          StopState = "UNKNOWN"
)

type StopEvidence struct {
	State               StopState   `json:"state"`
	OperationID         string      `json:"operation_id"`
	StepID              string      `json:"step_id"`
	ContainerID         string      `json:"container_id"`
	BootID              string      `json:"boot_id"`
	RequestedAt         time.Time   `json:"requested_at"`
	ObservedAt          time.Time   `json:"observed_at"`
	FinishedAt          time.Time   `json:"finished_at"`
	LifecycleAvailable  bool        `json:"lifecycle_available"`
	Running             bool        `json:"running"`
	ExitCode            int         `json:"exit_code"`
	OOMKilled           bool        `json:"oom_killed"`
	RuntimeTerminal     bool        `json:"runtime_terminal"`
	GracefulTermination bool        `json:"graceful_termination"`
	Attribution         Attribution `json:"attribution"`
	References          []string    `json:"references"`
}

// ClassifyStop never infers causation from a stopped container or timeout.
func ClassifyStop(dispatch DispatchState, e StopEvidence, now time.Time) StopState {
	if dispatch == NotDispatched {
		return StopNotRequested
	}
	if dispatch != DispatchPossible && dispatch != Acknowledged {
		return StopUnknown
	}
	if !e.LifecycleAvailable || !FreshEvidence(e.ObservedAt, now) {
		return StopUnknown
	}
	if e.Running {
		return StopStopping
	}
	if e.OOMKilled || e.ExitCode != 0 {
		return StopFailed
	}
	if e.RequestedAt.IsZero() || e.RequestedAt.After(e.FinishedAt) || e.FinishedAt.After(e.ObservedAt) ||
		!e.RuntimeTerminal || !e.GracefulTermination || e.Attribution != AttributionCorrelated ||
		e.OperationID == "" || e.StepID == "" || e.ContainerID == "" || e.BootID == "" || len(e.References) == 0 {
		return StopUnknown
	}
	return StopConfirmed
}

func FreshEvidence(at, now time.Time) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) <= 5*time.Second
}

// SafetyObservation comes only from an owner-installed observer, never request JSON.
// Availability covers every predicate, including filesystem/writer observations.
type SafetyObservation struct {
	Available            bool       `json:"available"`
	ObservedAt           time.Time  `json:"observed_at"`
	Enrollment           Enrollment `json:"enrollment"`
	BootID               string     `json:"boot_id"`
	InventoryDigest      string     `json:"inventory_digest"`
	ConfigDigest         string     `json:"config_digest"`
	SourceArtifactID     string     `json:"source_artifact_id"`
	SourceSHA256         string     `json:"source_sha256"`
	AdmissionClosed      bool       `json:"admission_closed"`
	Maintenance          bool       `json:"maintenance"`
	Players              int        `json:"players"`
	ProcessStopped       bool       `json:"process_stopped"`
	FilesystemRootExists bool       `json:"filesystem_root_exists"`
	NoConflictingWriter  bool       `json:"no_conflicting_writer"`
	References           []string   `json:"references"`
}

func (o SafetyObservation) Validate(enrollment Enrollment, intent ChangeIntent, now time.Time) error {
	if !o.Available || !FreshEvidence(o.ObservedAt, now) || len(o.References) == 0 ||
		o.InventoryDigest == "" || o.ConfigDigest == "" || o.SourceArtifactID == "" || o.SourceSHA256 == "" || o.BootID == "" ||
		o.Enrollment.TargetID == "" || o.Enrollment.EnrollmentID == "" || o.Enrollment.ContainerID == "" || o.Enrollment.DataRootIdentity == "" {
		return NewError(ErrPreconditionUnavailable, "fresh authoritative safety evidence is incomplete")
	}
	expected, _ := Digest(enrollment)
	actual, _ := Digest(o.Enrollment)
	if actual != expected || intent.EnrollmentID != enrollment.EnrollmentID || intent.DeploymentGeneration != enrollment.DeploymentGeneration ||
		intent.ContainerID != enrollment.ContainerID || intent.PaperTuple != enrollment.PaperTuple ||
		intent.PolicyDigest != enrollment.PolicyDigest || intent.PolicyRevision != enrollment.PolicyRevision ||
		o.BootID != intent.ExpectedBootID || o.InventoryDigest != intent.InventoryDigest || o.ConfigDigest != intent.ConfigDigest ||
		o.SourceArtifactID != intent.FromArtifactID || o.SourceSHA256 != intent.FromSHA256 {
		return NewError(ErrIntentStale, "approved target, generation, policy or source state changed")
	}
	if !o.NoConflictingWriter {
		return NewError(ErrTargetBusy, "conflicting writer observed")
	}
	if !o.FilesystemRootExists {
		return NewError(ErrPreconditionUnavailable, "enrolled filesystem root is unavailable")
	}
	return nil
}

type BackupReadyEvidence struct {
	BeforeStop SafetyObservation `json:"before_stop"`
	Offline    SafetyObservation `json:"offline"`
	Stop       StopEvidence      `json:"stop"`
}

func (e BackupReadyEvidence) Validate(enrollment Enrollment, intent ChangeIntent, operation Operation, now time.Time) error {
	if err := intent.ValidateDigest(); err != nil {
		return err
	}
	if operation.IntentID != intent.IntentID || operation.IntentDigest != intent.IntentDigest || operation.EnrollmentID != intent.EnrollmentID {
		return NewError(ErrInvalidIntentDigest, "backup operation does not own this intent")
	}
	if operation.OwnershipReleased || operation.Status != OperationExecuting {
		return NewError(ErrTargetBlockedUnknown, "backup operation no longer owns an executable writer")
	}
	if len(operation.Attempts) < 4 || operation.Attempts[3].StepID != e.Stop.StepID || operation.Attempts[3].StepKind != "S03_GRACEFUL_STOP" || operation.Attempts[3].DispatchState != Acknowledged || operation.Attempts[3].EffectState != EffectExpectedObserved || operation.Attempts[3].Attribution != AttributionCorrelated {
		return NewError(ErrPreconditionUnavailable, "stop evidence does not match the durable acknowledged S03")
	}
	// The zero-player observation is historical evidence, fresh at dispatch time.
	if err := e.BeforeStop.Validate(enrollment, intent, e.Stop.RequestedAt); err != nil {
		return err
	}
	if err := e.Offline.Validate(enrollment, intent, now); err != nil {
		return err
	}
	if !e.BeforeStop.AdmissionClosed || !e.BeforeStop.Maintenance || e.BeforeStop.Players != 0 || e.BeforeStop.ProcessStopped ||
		!e.Offline.AdmissionClosed || !e.Offline.ProcessStopped {
		return NewError(ErrIntentStale, "isolation or offline predicate changed")
	}
	if e.Stop.OperationID != operation.OperationID || e.Stop.ContainerID != intent.ContainerID || e.Stop.BootID != intent.ExpectedBootID ||
		e.Stop.State != StopConfirmed || ClassifyStop(Acknowledged, e.Stop, e.Stop.ObservedAt) != StopConfirmed {
		return NewError(ErrPreconditionUnavailable, "correlated graceful stop evidence is unavailable")
	}
	if e.Offline.ObservedAt.Before(e.Stop.FinishedAt) {
		return NewError(ErrPreconditionUnavailable, "offline evidence predates stop")
	}
	return nil
}

const BackupRecipeID = "gar.offline-tar.v1"

func OfflineBackupRecipeDigest() string {
	digest, _ := Digest(map[string]any{"scope": "enrolled-data-root", "consistency": "offline", "exclude": []string{"logs", "cache", "temporary-sockets"}})
	return digest
}

type BackupStatus string

const (
	BackupReserved   BackupStatus = "RESERVED"
	BackupWriting    BackupStatus = "WRITING"
	BackupFinalizing BackupStatus = "FINALIZING"
	BackupVerifying  BackupStatus = "VERIFYING"
	BackupValid      BackupStatus = "VALID"
	BackupFailed     BackupStatus = "FAILED"
	BackupUnknown    BackupStatus = "UNKNOWN"
	BackupOrphaned   BackupStatus = "ORPHANED"

	// BackupCreating is retained as a source-level alias for older fixtures.
	// New durable records use the explicit RESERVED state.
	BackupCreating = BackupReserved
)

// Incomplete and orphan archives are never promoted during recovery, even when
// a final archive happens to exist.
type BackupRecord struct {
	EvidenceLevel         string              `json:"evidence_level"`
	BackupID              string              `json:"backup_id"`
	SchemaVersion         string              `json:"schema_version"`
	TargetID              string              `json:"target_id"`
	EnrollmentID          string              `json:"enrollment_id"`
	DeploymentGeneration  int64               `json:"deployment_generation"`
	ContainerIdentity     string              `json:"container_identity"`
	DataRootIdentity      string              `json:"data_root_identity"`
	PaperTuple            string              `json:"paper_tuple"`
	BootIDBeforeStop      string              `json:"boot_id_before_stop"`
	IntentID              string              `json:"intent_id"`
	IntentDigest          string              `json:"intent_digest"`
	OperationID           string              `json:"operation_id"`
	StepID                string              `json:"step_id"`
	SourceInventoryDigest string              `json:"source_inventory_digest"`
	SourceConfigDigest    string              `json:"source_config_digest"`
	SourceArtifacts       []ArtifactRecord    `json:"source_artifacts"`
	BackupRecipeID        string              `json:"backup_recipe_id"`
	BackupRecipeDigest    string              `json:"backup_recipe_digest"`
	CreatedAt             time.Time           `json:"created_at"`
	CompletedAt           time.Time           `json:"completed_at"`
	ConsistencyMode       string              `json:"consistency_mode"`
	ArchiveSizeBytes      int64               `json:"archive_size_bytes"`
	ArchiveSHA256         string              `json:"archive_sha256"`
	DigestVerifiedAt      time.Time           `json:"digest_verified_at"`
	Status                BackupStatus        `json:"status"`
	Ready                 BackupReadyEvidence `json:"ready"`
}

func (r BackupRecord) ValidateCompleted() error {
	if r.Status != BackupValid || r.SchemaVersion != "gar.backup.v1" || r.ConsistencyMode != "OFFLINE" ||
		r.ArchiveSizeBytes <= 0 || len(r.ArchiveSHA256) != 64 || r.DigestVerifiedAt.Before(r.CreatedAt) ||
		r.CompletedAt.Before(r.DigestVerifiedAt) || r.CompletedAt.IsZero() {
		return NewError(ErrBackupNotReady, fmt.Sprintf("backup %s is not a completed verified artifact", r.BackupID))
	}
	return nil
}
