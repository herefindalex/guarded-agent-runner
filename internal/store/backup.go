package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"guarded-agent-runner/internal/domain"
)

func (s *Store) GetBackup(ctx context.Context, id string) (domain.BackupRecord, error) {
	var payload string
	err := s.db.QueryRowContext(ctx, "SELECT payload FROM v01_backups WHERE backup_id = ?", id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.BackupRecord{}, domain.NewError(domain.ErrNotFound, "backup not found")
	}
	if err != nil {
		return domain.BackupRecord{}, err
	}
	var r domain.BackupRecord
	err = json.Unmarshal([]byte(payload), &r)
	return r, err
}

// ReserveBackup binds the artifact identity to the durable writer and S05.
// Replays intentionally fail: CREATING may already own a partial or orphan file.
// This review boundary accepts FAKE_TARGET records only; it cannot certify live
// Paper acceptance. A future live adapter requires a separate reviewed change.
func (s *Store) ReserveBackup(ctx context.Context, r domain.BackupRecord, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	op, err := getOperationTx(ctx, tx, r.OperationID)
	if err != nil {
		return err
	}
	if op.OwnershipReleased || op.Status != domain.OperationExecuting || len(op.Attempts) != 6 {
		return domain.NewError(domain.ErrScopeDenied, "backup requires the active S05 writer")
	}
	step := op.Attempts[5]
	if step.StepID != r.StepID || step.StepKind != "S05_CREATE_BACKUP" || step.DispatchState != domain.DispatchPossible {
		return domain.NewError(domain.ErrDispatchOutcomeUnknown, "backup dispatch not durably prepared")
	}
	var payload string
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM v01_intents WHERE intent_id = ?", op.IntentID).Scan(&payload); err != nil {
		return err
	}
	var intent domain.IntentRecord
	if err := json.Unmarshal([]byte(payload), &intent); err != nil {
		return err
	}
	i := intent.Intent
	if err := r.Ready.Validate(r.Ready.Offline.Enrollment, i, op, now); err != nil {
		return err
	}
	e := r.Ready.Offline.Enrollment
	if r.EvidenceLevel != "FAKE_TARGET" || r.BackupID != i.ReservedBackupID || r.IntentID != i.IntentID || r.IntentDigest != i.IntentDigest || r.EnrollmentID != i.EnrollmentID ||
		r.ContainerIdentity != i.ContainerID || r.DeploymentGeneration != i.DeploymentGeneration || r.PaperTuple != i.PaperTuple ||
		r.TargetID != e.TargetID || r.DataRootIdentity != e.DataRootIdentity || r.BootIDBeforeStop != i.ExpectedBootID ||
		r.SourceInventoryDigest != i.InventoryDigest || r.SourceConfigDigest != i.ConfigDigest ||
		len(r.SourceArtifacts) != 1 || r.SourceArtifacts[0].ArtifactID != i.FromArtifactID || r.SourceArtifacts[0].SHA256 != i.FromSHA256 || r.SourceArtifacts[0].PluginID != i.PluginID ||
		r.BackupRecipeID != domain.BackupRecipeID || r.BackupRecipeDigest != i.BackupRecipeDigest || r.BackupRecipeDigest != domain.OfflineBackupRecipeDigest() ||
		r.Status != domain.BackupCreating || r.ConsistencyMode != "OFFLINE" || r.SchemaVersion != "gar.backup.v1" ||
		!r.CompletedAt.IsZero() || !r.DigestVerifiedAt.IsZero() || r.ArchiveSHA256 != "" || r.ArchiveSizeBytes != 0 || !domain.FreshEvidence(r.CreatedAt, now) {
		return domain.NewError(domain.ErrInvalidRequest, "backup reservation differs from approved identity or recipe")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO v01_backups(backup_id, operation_id, status, payload) VALUES(?, ?, ?, ?)", r.BackupID, r.OperationID, r.Status, string(encoded)); err != nil {
		return translateWriteError(err)
	}
	if err := appendAuditTx(ctx, tx, r.OperationID, "BACKUP_RESERVED", r); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

// CompleteBackup commits verified metadata and correlated S05 evidence together.
// Only the offline engine calls this after file+directory sync and a digest reread.
func (s *Store) CompleteBackup(ctx context.Context, id, digest string, size int64, now time.Time) error {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || size <= 0 {
		return domain.NewError(domain.ErrBackupNotReady, "invalid archive digest or size")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var payload string
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM v01_backups WHERE backup_id = ?", id).Scan(&payload); err != nil {
		return err
	}
	var r domain.BackupRecord
	if err := json.Unmarshal([]byte(payload), &r); err != nil {
		return err
	}
	if r.Status != domain.BackupCreating {
		return domain.NewError(domain.ErrScopeDenied, "completed backup metadata is immutable")
	}
	op, err := getOperationTx(ctx, tx, r.OperationID)
	if err != nil {
		return err
	}
	if op.Status != domain.OperationExecuting || op.OwnershipReleased || len(op.Attempts) != 6 {
		return domain.NewError(domain.ErrTargetBlockedUnknown, "backup writer is no longer executable")
	}
	a := &op.Attempts[5]
	if a.StepID != r.StepID || a.DispatchState != domain.DispatchPossible || a.EffectState != domain.EffectUnknown {
		return domain.NewError(domain.ErrDispatchOutcomeUnknown, "backup attempt cannot complete")
	}
	r.Status, r.ArchiveSHA256, r.ArchiveSizeBytes = domain.BackupValid, digest, size
	r.DigestVerifiedAt, r.CompletedAt = now.UTC(), now.UTC()
	if err := r.ValidateCompleted(); err != nil {
		return err
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v01_backups SET status = ?, payload = ? WHERE backup_id = ?", r.Status, string(encoded), id); err != nil {
		return err
	}
	a.DispatchState, a.EffectState, a.Attribution = domain.Acknowledged, domain.EffectExpectedObserved, domain.AttributionCorrelated
	a.Evidence, a.UpdatedAt = []string{"backup:" + id, "sha256:" + digest}, now.UTC()
	op.UpdatedAt = now.UTC()
	attempt, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE v01_steps SET payload = ?, updated_at = ? WHERE step_id = ?", string(attempt), now.UTC().Format(time.RFC3339Nano), a.StepID); err != nil {
		return err
	}
	if err := saveOperationTx(ctx, tx, op); err != nil {
		return err
	}
	if err := appendAuditTx(ctx, tx, r.OperationID, "BACKUP_VERIFIED_S05_COMPLETE", r); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}
