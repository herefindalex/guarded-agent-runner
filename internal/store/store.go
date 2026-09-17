package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/localfile"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type IntentSummary struct {
	IntentID        string    `json:"intent_id"`
	ClientRequestID string    `json:"client_request_id"`
	Status          string    `json:"status"`
	IntentDigest    string    `json:"intent_digest"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (store *Store) ListIntentSummaries(
	ctx context.Context, principalID, enrollmentID, cursor string, limit int,
) ([]IntentSummary, string, error) {
	if limit < 1 || limit > 200 {
		return nil, "", domain.NewError(domain.ErrInvalidRequest, "intent summary limit must be from 1 through 200")
	}
	var cursorTime, cursorID string
	if cursor != "" {
		separator := strings.LastIndexByte(cursor, '|')
		if separator < 1 || separator == len(cursor)-1 {
			return nil, "", domain.NewError(domain.ErrInvalidRequest, "recent-changes cursor is invalid")
		}
		cursorTime, cursorID = cursor[:separator], cursor[separator+1:]
		if _, err := time.Parse(time.RFC3339Nano, cursorTime); err != nil {
			return nil, "", domain.NewError(domain.ErrInvalidRequest, "recent-changes cursor is invalid")
		}
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT intent_id, client_request_id, status, intent_digest, updated_at
		FROM v01_intents
		WHERE principal_id = ? AND enrollment_id = ?
		  AND (? = '' OR updated_at < ? OR (updated_at = ? AND intent_id < ?))
		ORDER BY updated_at DESC, intent_id DESC
		LIMIT ?`, principalID, enrollmentID, cursorTime, cursorTime, cursorTime, cursorID, limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	results := make([]IntentSummary, 0, limit)
	for rows.Next() {
		var result IntentSummary
		var updatedAt string
		if err := rows.Scan(&result.IntentID, &result.ClientRequestID, &result.Status, &result.IntentDigest, &updatedAt); err != nil {
			return nil, "", err
		}
		result.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			return nil, "", err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	nextCursor := ""
	if len(results) == limit {
		last := results[len(results)-1]
		nextCursor = last.UpdatedAt.UTC().Format(time.RFC3339Nano) + "|" + last.IntentID
	}
	return results, nextCursor, nil
}

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := secureDatabaseFile(path); err != nil {
			return nil, err
		}
	}
	dsn := sqliteDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteDSN(path string) string {
	if path == ":memory:" {
		return "file:gar-m1?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)"
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return "file:" + url.PathEscape(absolute) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

func secureDatabaseFile(path string) error {
	if info, err := os.Lstat(path); err == nil {
		_ = info
		if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
			return domain.NewError(domain.ErrJournalUnavailable, err.Error())
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return domain.NewError(domain.ErrJournalUnavailable, err.Error())
	}
	if err := file.Close(); err != nil {
		return domain.NewError(domain.ErrJournalUnavailable, err.Error())
	}
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return domain.NewError(domain.ErrJournalUnavailable, err.Error())
	}
	return nil
}

func (store *Store) initialize(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS v01_backups (
            backup_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            payload TEXT NOT NULL,
            FOREIGN KEY(operation_id) REFERENCES v01_operations(operation_id)
        )`,
		`CREATE TABLE IF NOT EXISTS v01_sessions (
            session_id TEXT PRIMARY KEY,
            principal_id TEXT NOT NULL,
            enrollment_id TEXT NOT NULL,
            scope_digest TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS v01_intents (
            intent_id TEXT PRIMARY KEY,
            principal_id TEXT NOT NULL,
            enrollment_id TEXT NOT NULL,
            client_request_id TEXT NOT NULL,
            proposal_digest TEXT NOT NULL,
            intent_digest TEXT NOT NULL,
            status TEXT NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(principal_id, enrollment_id, client_request_id)
        )`,
		`CREATE TABLE IF NOT EXISTS v01_approvals (
            approval_id TEXT PRIMARY KEY,
            intent_id TEXT NOT NULL UNIQUE,
            intent_digest TEXT NOT NULL,
            payload TEXT NOT NULL,
            decided_at TEXT NOT NULL,
            FOREIGN KEY(intent_id) REFERENCES v01_intents(intent_id)
        )`,
		`CREATE TABLE IF NOT EXISTS v01_operations (
            operation_id TEXT PRIMARY KEY,
            intent_id TEXT NOT NULL UNIQUE,
            enrollment_id TEXT NOT NULL,
            status TEXT NOT NULL,
            ownership_released INTEGER NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(intent_id) REFERENCES v01_intents(intent_id)
        )`,
		`CREATE INDEX IF NOT EXISTS v01_operation_owner
            ON v01_operations(enrollment_id, ownership_released, status)`,
		`CREATE TABLE IF NOT EXISTS v01_steps (
            step_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            attempt_no INTEGER NOT NULL,
            payload TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(operation_id, step_id, attempt_no),
            FOREIGN KEY(operation_id) REFERENCES v01_operations(operation_id)
        )`,
		`CREATE INDEX IF NOT EXISTS v01_step_operation ON v01_steps(operation_id, attempt_no)`,
		`CREATE TABLE IF NOT EXISTS v01_audit (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        )`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize M1 store: %w", err)
		}
	}
	if _, err := store.JournalSettings(ctx); err != nil {
		return err
	}
	return nil
}

func (store *Store) Close() error {
	return store.db.Close()
}

type JournalSettings struct {
	JournalMode string `json:"journal_mode"`
	Synchronous int    `json:"synchronous"`
	ForeignKeys int    `json:"foreign_keys"`
}

func (store *Store) JournalSettings(ctx context.Context) (JournalSettings, error) {
	var settings JournalSettings
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&settings.JournalMode); err != nil {
		return settings, err
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&settings.Synchronous); err != nil {
		return settings, err
	}
	if err := store.db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&settings.ForeignKeys); err != nil {
		return settings, err
	}
	if settings.Synchronous != 2 || settings.ForeignKeys != 1 {
		return settings, domain.NewError(domain.ErrJournalUnavailable, "SQLite FULL synchronous or foreign_keys was not applied")
	}
	return settings, nil
}

func (store *Store) SaveSession(ctx context.Context, scope domain.AgentSessionScope) error {
	if err := scope.Validate(time.Now().UTC()); err != nil {
		return err
	}
	payload, err := json.Marshal(scope)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO v01_sessions(session_id, principal_id, enrollment_id, scope_digest, payload, created_at)
         VALUES(?, ?, ?, ?, ?, ?)`, scope.SessionID, scope.PrincipalID, scope.EnrollmentID,
		scope.ScopeDigest, string(payload), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return translateWriteError(err)
	}
	if err := appendAuditTx(ctx, tx, scope.SessionID, "SESSION_CREATED", map[string]any{
		"principal_id": scope.PrincipalID, "scope_digest": scope.ScopeDigest,
	}); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

func (store *Store) GetSession(ctx context.Context, sessionID string) (domain.AgentSessionScope, error) {
	var payload string
	err := store.db.QueryRowContext(ctx,
		"SELECT payload FROM v01_sessions WHERE session_id = ?", sessionID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AgentSessionScope{}, domain.NewError(domain.ErrScopeDenied, "agent session not found")
	}
	if err != nil {
		return domain.AgentSessionScope{}, err
	}
	var scope domain.AgentSessionScope
	if err := json.Unmarshal([]byte(payload), &scope); err != nil {
		return scope, err
	}
	return scope, nil
}

func (store *Store) PutIntent(ctx context.Context, record domain.IntentRecord) (domain.IntentRecord, bool, error) {
	existing, err := store.GetIntentByClientKey(ctx, record.Intent.PrincipalID,
		record.Intent.EnrollmentID, record.Intent.ClientRequestID)
	if err == nil {
		if existing.ProposalDigest != record.ProposalDigest {
			return domain.IntentRecord{}, false, domain.NewError(domain.ErrIdempotencyConflict,
				"client_request_id already identifies different proposal bytes")
		}
		return existing, false, nil
	}
	if domain.CodeOf(err) != domain.ErrNotFound {
		return domain.IntentRecord{}, false, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return domain.IntentRecord{}, false, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.IntentRecord{}, false, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx,
		`INSERT INTO v01_intents(intent_id, principal_id, enrollment_id, client_request_id,
         proposal_digest, intent_digest, status, payload, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Intent.IntentID, record.Intent.PrincipalID, record.Intent.EnrollmentID,
		record.Intent.ClientRequestID, record.ProposalDigest, record.Intent.IntentDigest,
		record.Status, string(payload), record.UpdatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		// Resolve a concurrent insert through the same idempotency rule.
		_ = tx.Rollback()
		existing, lookupErr := store.GetIntentByClientKey(ctx, record.Intent.PrincipalID,
			record.Intent.EnrollmentID, record.Intent.ClientRequestID)
		if lookupErr == nil {
			if existing.ProposalDigest != record.ProposalDigest {
				return domain.IntentRecord{}, false, domain.NewError(domain.ErrIdempotencyConflict,
					"client_request_id already identifies different proposal bytes")
			}
			return existing, false, nil
		}
		return domain.IntentRecord{}, false, translateWriteError(err)
	}
	if err := appendAuditTx(ctx, tx, record.Intent.IntentID, "INTENT_FROZEN", map[string]any{
		"intent_digest": record.Intent.IntentDigest,
		"scope_digest":  record.Intent.ScopeDigest,
	}); err != nil {
		return domain.IntentRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return domain.IntentRecord{}, false, translateWriteError(err)
	}
	return record, true, nil
}

func (store *Store) GetIntent(ctx context.Context, intentID string) (domain.IntentRecord, error) {
	return store.scanIntent(store.db.QueryRowContext(ctx,
		"SELECT payload FROM v01_intents WHERE intent_id = ?", intentID))
}

func (store *Store) GetIntentByClientKey(ctx context.Context, principalID, enrollmentID, key string) (domain.IntentRecord, error) {
	return store.scanIntent(store.db.QueryRowContext(ctx,
		`SELECT payload FROM v01_intents
         WHERE principal_id = ? AND enrollment_id = ? AND client_request_id = ?`,
		principalID, enrollmentID, key))
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (store *Store) scanIntent(row rowScanner) (domain.IntentRecord, error) {
	var payload string
	if err := row.Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.IntentRecord{}, domain.NewError(domain.ErrNotFound, "intent not found")
	} else if err != nil {
		return domain.IntentRecord{}, err
	}
	var record domain.IntentRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return record, err
	}
	return record, nil
}

func (store *Store) ApproveIntent(
	ctx context.Context,
	intentID, expectedDigest, approver string,
	osUID int,
	now time.Time,
) (domain.Approval, domain.Operation, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Approval{}, domain.Operation{}, err
	}
	defer tx.Rollback()

	if approval, operation, found, lookupErr := lookupExistingApproval(ctx, tx, intentID); lookupErr != nil {
		return domain.Approval{}, domain.Operation{}, lookupErr
	} else if found {
		if approval.IntentDigest != expectedDigest {
			return domain.Approval{}, domain.Operation{}, domain.NewError(domain.ErrInvalidIntentDigest,
				"existing approval is bound to a different digest")
		}
		return approval, operation, nil
	}

	var payload string
	if err := tx.QueryRowContext(ctx, "SELECT payload FROM v01_intents WHERE intent_id = ?", intentID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, domain.Operation{}, domain.NewError(domain.ErrNotFound, "intent not found")
	} else if err != nil {
		return domain.Approval{}, domain.Operation{}, err
	}
	var record domain.IntentRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return domain.Approval{}, domain.Operation{}, err
	}
	if err := record.Intent.ValidateDigest(); err != nil || record.Intent.IntentDigest != expectedDigest {
		return domain.Approval{}, domain.Operation{}, domain.NewError(domain.ErrInvalidIntentDigest,
			"operator supplied digest does not match frozen intent")
	}
	if !now.Before(record.Intent.ApprovalDeadline) || !now.Before(record.Intent.StartBefore) {
		return domain.Approval{}, domain.Operation{}, domain.NewError(domain.ErrApprovalExpired,
			"approval or start deadline has elapsed")
	}
	if record.Status != domain.IntentAwaitingApproval {
		return domain.Approval{}, domain.Operation{}, domain.NewError(domain.ErrApprovalRevoked,
			"intent is not awaiting approval")
	}

	if code, busyErr := activeOwner(ctx, tx, record.Intent.EnrollmentID); busyErr != nil {
		return domain.Approval{}, domain.Operation{}, busyErr
	} else if code != "" {
		return domain.Approval{}, domain.Operation{}, domain.NewError(code,
			"target ownership is held by another unresolved operation")
	}

	approval := domain.Approval{
		ApprovalID: domain.NewID("approval"), IntentID: intentID, IntentDigest: expectedDigest,
		ApproverPrincipal: approver, ApproverOSUID: osUID, Decision: "APPROVED", DecidedAt: now.UTC(),
	}
	operation := domain.Operation{
		OperationID: domain.NewID("operation"), IntentID: intentID, IntentDigest: expectedDigest,
		EnrollmentID: record.Intent.EnrollmentID, ExecutionEpoch: now.UnixNano(),
		Status: domain.OperationQueued, Verification: domain.VerificationNotStarted,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	approvalPayload, _ := json.Marshal(approval)
	operationPayload, _ := json.Marshal(operation)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO v01_approvals(approval_id, intent_id, intent_digest, payload, decided_at)
         VALUES(?, ?, ?, ?, ?)`, approval.ApprovalID, intentID, expectedDigest,
		string(approvalPayload), approval.DecidedAt.Format(time.RFC3339Nano)); err != nil {
		return domain.Approval{}, domain.Operation{}, translateWriteError(err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO v01_operations(operation_id, intent_id, enrollment_id, status,
         ownership_released, payload, updated_at) VALUES(?, ?, ?, ?, 0, ?, ?)`,
		operation.OperationID, intentID, operation.EnrollmentID, operation.Status,
		string(operationPayload), operation.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		return domain.Approval{}, domain.Operation{}, translateWriteError(err)
	}
	record.Status = domain.IntentConsumed
	record.UpdatedAt = now.UTC()
	updatedPayload, _ := json.Marshal(record)
	if _, err := tx.ExecContext(ctx,
		"UPDATE v01_intents SET status = ?, payload = ?, updated_at = ? WHERE intent_id = ?",
		record.Status, string(updatedPayload), record.UpdatedAt.Format(time.RFC3339Nano), intentID); err != nil {
		return domain.Approval{}, domain.Operation{}, translateWriteError(err)
	}
	if err := appendAuditTx(ctx, tx, intentID, "APPROVAL_DECIDED", approval); err != nil {
		return domain.Approval{}, domain.Operation{}, err
	}
	if err := appendAuditTx(ctx, tx, operation.OperationID, "WRITER_ACQUIRED", map[string]any{
		"intent_id": intentID, "execution_epoch": operation.ExecutionEpoch,
	}); err != nil {
		return domain.Approval{}, domain.Operation{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Approval{}, domain.Operation{}, translateWriteError(err)
	}
	return approval, operation, nil
}

func lookupExistingApproval(ctx context.Context, tx *sql.Tx, intentID string) (domain.Approval, domain.Operation, bool, error) {
	var approvalPayload string
	err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_approvals WHERE intent_id = ?", intentID).Scan(&approvalPayload)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, domain.Operation{}, false, nil
	}
	if err != nil {
		return domain.Approval{}, domain.Operation{}, false, err
	}
	var approval domain.Approval
	var operation domain.Operation
	if err := json.Unmarshal([]byte(approvalPayload), &approval); err != nil {
		return approval, operation, false, err
	}
	if approval.Decision != "APPROVED" {
		return approval, operation, false, domain.NewError(domain.ErrApprovalRevoked,
			"intent already has a non-approved operator decision")
	}
	var operationPayload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_operations WHERE intent_id = ?", intentID).Scan(&operationPayload); err != nil {
		return approval, operation, false, err
	}
	if err := json.Unmarshal([]byte(operationPayload), &operation); err != nil {
		return approval, operation, false, err
	}
	return approval, operation, true, nil
}

func (store *Store) RejectIntent(
	ctx context.Context,
	intentID, expectedDigest, approver string,
	osUID int,
	now time.Time,
) (domain.Approval, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Approval{}, err
	}
	defer tx.Rollback()
	var existingPayload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_approvals WHERE intent_id = ?", intentID).Scan(&existingPayload); err == nil {
		var existing domain.Approval
		if unmarshalErr := json.Unmarshal([]byte(existingPayload), &existing); unmarshalErr != nil {
			return domain.Approval{}, unmarshalErr
		}
		if existing.IntentDigest != expectedDigest || existing.Decision != "REJECTED" {
			return domain.Approval{}, domain.NewError(domain.ErrApprovalRevoked,
				"intent already has a different operator decision")
		}
		return existing, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, err
	}
	record, err := intentForDecision(ctx, tx, intentID, expectedDigest)
	if err != nil {
		return domain.Approval{}, err
	}
	if record.Status != domain.IntentAwaitingApproval {
		return domain.Approval{}, domain.NewError(domain.ErrApprovalRevoked, "intent is not awaiting approval")
	}
	approval := domain.Approval{
		ApprovalID: domain.NewID("approval"), IntentID: intentID, IntentDigest: expectedDigest,
		ApproverPrincipal: approver, ApproverOSUID: osUID, Decision: "REJECTED", DecidedAt: now.UTC(),
	}
	payload, _ := json.Marshal(approval)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO v01_approvals(approval_id, intent_id, intent_digest, payload, decided_at)
         VALUES(?, ?, ?, ?, ?)`, approval.ApprovalID, intentID, expectedDigest,
		string(payload), approval.DecidedAt.Format(time.RFC3339Nano)); err != nil {
		return domain.Approval{}, translateWriteError(err)
	}
	record.Status = domain.IntentRejected
	record.UpdatedAt = now.UTC()
	if err := updateIntentTx(ctx, tx, record); err != nil {
		return domain.Approval{}, err
	}
	if err := appendAuditTx(ctx, tx, intentID, "APPROVAL_DECIDED", approval); err != nil {
		return domain.Approval{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Approval{}, translateWriteError(err)
	}
	return approval, nil
}

func (store *Store) RevokeIntent(
	ctx context.Context,
	intentID, expectedDigest, actor string,
	osUID int,
	now time.Time,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	record, err := intentForDecision(ctx, tx, intentID, expectedDigest)
	if err != nil {
		return err
	}
	if record.Status == domain.IntentRejected || record.Status == domain.IntentExpired ||
		record.Status == domain.IntentRevoked || record.Status == domain.IntentCancelled {
		return domain.NewError(domain.ErrApprovalRevoked, "intent is already terminal or revoked")
	}
	record.Status = domain.IntentRevoked
	record.UpdatedAt = now.UTC()
	if err := updateIntentTx(ctx, tx, record); err != nil {
		return err
	}
	var operationPayload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_operations WHERE intent_id = ?", intentID).Scan(&operationPayload); err == nil {
		var operation domain.Operation
		if err := json.Unmarshal([]byte(operationPayload), &operation); err != nil {
			return err
		}
		if operation.Status == domain.OperationQueued && len(operation.Attempts) == 0 {
			operation.Status = domain.OperationAborted
			operation.OwnershipReleased = true
			operation.UpdatedAt = now.UTC()
			if err := saveOperationTx(ctx, tx, operation); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := appendAuditTx(ctx, tx, intentID, "APPROVAL_REVOKED", map[string]any{
		"actor": actor, "os_uid": osUID, "intent_digest": expectedDigest,
	}); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

func intentForDecision(
	ctx context.Context,
	tx *sql.Tx,
	intentID, expectedDigest string,
) (domain.IntentRecord, error) {
	var payload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_intents WHERE intent_id = ?", intentID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.IntentRecord{}, domain.NewError(domain.ErrNotFound, "intent not found")
	} else if err != nil {
		return domain.IntentRecord{}, err
	}
	var record domain.IntentRecord
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return record, err
	}
	if err := record.Intent.ValidateDigest(); err != nil || record.Intent.IntentDigest != expectedDigest {
		return domain.IntentRecord{}, domain.NewError(domain.ErrInvalidIntentDigest,
			"operator supplied digest does not match frozen intent")
	}
	return record, nil
}

func updateIntentTx(ctx context.Context, tx *sql.Tx, record domain.IntentRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		"UPDATE v01_intents SET status = ?, payload = ?, updated_at = ? WHERE intent_id = ?",
		record.Status, string(payload), record.UpdatedAt.Format(time.RFC3339Nano), record.Intent.IntentID)
	return translateWriteError(err)
}

func activeOwner(ctx context.Context, tx *sql.Tx, enrollmentID string) (domain.ErrorCode, error) {
	var status string
	err := tx.QueryRowContext(ctx,
		`SELECT status FROM v01_operations
         WHERE enrollment_id = ? AND ownership_released = 0 LIMIT 1`, enrollmentID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if domain.OperationStatus(status) == domain.OperationUnknown ||
		domain.OperationStatus(status) == domain.OperationNeedsIntervention {
		return domain.ErrTargetBlockedUnknown, nil
	}
	return domain.ErrTargetBusy, nil
}

func (store *Store) GetOperation(ctx context.Context, operationID string) (domain.Operation, error) {
	var payload string
	if err := store.db.QueryRowContext(ctx,
		"SELECT payload FROM v01_operations WHERE operation_id = ?", operationID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.NewError(domain.ErrNotFound, "operation not found")
	} else if err != nil {
		return domain.Operation{}, err
	}
	var operation domain.Operation
	if err := json.Unmarshal([]byte(payload), &operation); err != nil {
		return operation, err
	}
	return operation, nil
}

func (store *Store) OperationForIntent(ctx context.Context, intentID string) (domain.Operation, error) {
	var payload string
	if err := store.db.QueryRowContext(ctx,
		"SELECT payload FROM v01_operations WHERE intent_id = ?", intentID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.NewError(domain.ErrNotFound, "operation not found")
	} else if err != nil {
		return domain.Operation{}, err
	}
	var operation domain.Operation
	if err := json.Unmarshal([]byte(payload), &operation); err != nil {
		return operation, err
	}
	return operation, nil
}

func (store *Store) OperationForStep(ctx context.Context, stepID string) (domain.Operation, error) {
	var payload string
	if err := store.db.QueryRowContext(ctx,
		`SELECT o.payload FROM v01_steps s
         JOIN v01_operations o ON o.operation_id = s.operation_id
         WHERE s.step_id = ?`, stepID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.NewError(domain.ErrNotFound, "step not found")
	} else if err != nil {
		return domain.Operation{}, err
	}
	var operation domain.Operation
	if err := json.Unmarshal([]byte(payload), &operation); err != nil {
		return operation, err
	}
	return operation, nil
}

// PrepareStep durably records the next step before any executor dispatch (INV-13, AT-049).
func (store *Store) PrepareStep(ctx context.Context, operationID, stepKind string, now time.Time) (domain.StepAttempt, error) {
	if stepKind == "S06_REPLACE_ARTIFACT" || stepKind == "S07_PREPARE_LAUNCH_AND_START" || stepKind == "S08_VERIFY_UNDER_MAINTENANCE" || stepKind == "S09_RELEASE_MAINTENANCE" || stepKind == "S10_FINALIZE" {
		return domain.StepAttempt{}, domain.NewError(domain.ErrUnsupportedEnvironment, "S05 is the current review boundary; S06-S10 remain disabled")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.StepAttempt{}, err
	}
	defer tx.Rollback()
	operation, err := getOperationTx(ctx, tx, operationID)
	if err != nil {
		return domain.StepAttempt{}, err
	}
	if operation.Status == domain.OperationUnknown || operation.Status == domain.OperationNeedsIntervention {
		return domain.StepAttempt{}, domain.NewError(domain.ErrTargetBlockedUnknown,
			"unknown operation cannot prepare another forward step")
	}
	var intentPayload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_intents WHERE intent_id = ?", operation.IntentID).Scan(&intentPayload); err != nil {
		return domain.StepAttempt{}, err
	}
	var intent domain.IntentRecord
	if err := json.Unmarshal([]byte(intentPayload), &intent); err != nil {
		return domain.StepAttempt{}, err
	}
	if err := intent.Intent.ValidateDigest(); err != nil {
		return domain.StepAttempt{}, err
	}
	if intent.Status != domain.IntentConsumed || operation.OwnershipReleased || domain.IsTerminalOperation(operation.Status) || operation.IntentDigest != intent.Intent.IntentDigest {
		return domain.StepAttempt{}, domain.NewError(domain.ErrApprovalRevoked, "operation no longer holds an executable approval")
	}
	if len(operation.Attempts) >= len(intent.Intent.Steps) || intent.Intent.Steps[len(operation.Attempts)] != stepKind {
		return domain.StepAttempt{}, domain.NewError(domain.ErrScopeDenied,
			"step kind is not the next step in the approved frozen workflow")
	}
	for _, previous := range operation.Attempts {
		if previous.EffectState != domain.EffectExpectedObserved ||
			previous.Attribution != domain.AttributionCorrelated ||
			previous.DispatchState != domain.Acknowledged {
			return domain.StepAttempt{}, domain.NewError(domain.ErrDispatchOutcomeUnknown,
				"previous step effect is not correlated and acknowledged")
		}
	}
	attemptNo := 1
	for _, attempt := range operation.Attempts {
		if attempt.StepKind == stepKind && attempt.AttemptNo >= attemptNo {
			attemptNo = attempt.AttemptNo + 1
		}
	}
	attempt := domain.StepAttempt{
		StepID: domain.NewID("step"), StepKind: stepKind, AttemptNo: attemptNo,
		DispatchState: domain.NotDispatched, EffectState: domain.EffectProvenNotApplied,
		Attribution: domain.AttributionUnattributed, PreparedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	operation.Attempts = append(operation.Attempts, attempt)
	operation.UpdatedAt = now.UTC()
	attemptPayload, err := json.Marshal(attempt)
	if err != nil {
		return domain.StepAttempt{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO v01_steps(step_id, operation_id, attempt_no, payload, updated_at)
         VALUES(?, ?, ?, ?, ?)`, attempt.StepID, operation.OperationID, attempt.AttemptNo,
		string(attemptPayload), attempt.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		return domain.StepAttempt{}, translateWriteError(err)
	}
	if err := saveOperationTx(ctx, tx, operation); err != nil {
		return domain.StepAttempt{}, err
	}
	if err := appendAuditTx(ctx, tx, operationID, "STEP_PREPARED", attempt); err != nil {
		return domain.StepAttempt{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.StepAttempt{}, translateWriteError(err)
	}
	return attempt, nil
}

func (store *Store) MarkDispatchPossible(
	ctx context.Context,
	operationID, stepID string,
	now time.Time,
) error {
	return store.updateAttempt(ctx, operationID, stepID, now, func(attempt *domain.StepAttempt) error {
		if attempt.DispatchState != domain.NotDispatched || attempt.EffectState != domain.EffectProvenNotApplied {
			return domain.NewError(domain.ErrDispatchOutcomeUnknown,
				"step is not in a proven-not-dispatched state")
		}
		attempt.DispatchState = domain.DispatchPossible
		attempt.EffectState = domain.EffectUnknown
		attempt.Attribution = domain.AttributionUnattributed
		return nil
	}, "STEP_DISPATCH_POSSIBLE")
}

func (store *Store) RecordStepObservation(
	ctx context.Context,
	operationID, stepID string,
	effect domain.EffectState,
	attribution domain.Attribution,
	evidence []string,
	now time.Time,
) error {
	return store.updateAttempt(ctx, operationID, stepID, now, func(attempt *domain.StepAttempt) error {
		if attempt.DispatchState != domain.DispatchPossible && attempt.DispatchState != domain.Acknowledged {
			return domain.NewError(domain.ErrDispatchOutcomeUnknown,
				"step observation cannot be attributed before durable dispatch state")
		}
		switch effect {
		case domain.EffectProvenNotApplied, domain.EffectExpectedObserved,
			domain.EffectOtherObserved, domain.EffectUnknown:
		default:
			return domain.NewError(domain.ErrInvalidRequest, "invalid step effect state")
		}
		attempt.EffectState = effect
		attempt.Attribution = attribution
		attempt.Evidence = append([]string(nil), evidence...)
		if attribution == domain.AttributionCorrelated {
			attempt.DispatchState = domain.Acknowledged
		}
		return nil
	}, "STEP_OBSERVED")
}

func (store *Store) updateAttempt(
	ctx context.Context,
	operationID, stepID string,
	now time.Time,
	mutate func(*domain.StepAttempt) error,
	eventType string,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	operation, err := getOperationTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if eventType == "STEP_DISPATCH_POSSIBLE" {
		if operation.OwnershipReleased || domain.IsTerminalOperation(operation.Status) || operation.Status == domain.OperationUnknown {
			return domain.NewError(domain.ErrTargetBlockedUnknown, "operation cannot dispatch")
		}
		var intentStatus string
		if err := tx.QueryRowContext(ctx, "SELECT status FROM v01_intents WHERE intent_id = ?", operation.IntentID).Scan(&intentStatus); err != nil {
			return err
		}
		if domain.IntentStatus(intentStatus) != domain.IntentConsumed {
			return domain.NewError(domain.ErrApprovalRevoked, "approval was revoked before dispatch")
		}
	}
	index := -1
	for candidate := range operation.Attempts {
		if operation.Attempts[candidate].StepID == stepID {
			index = candidate
			break
		}
	}
	if index < 0 {
		return domain.NewError(domain.ErrNotFound, "step attempt not found in operation")
	}
	if err := mutate(&operation.Attempts[index]); err != nil {
		return err
	}
	operation.Attempts[index].UpdatedAt = now.UTC()
	operation.UpdatedAt = now.UTC()
	if operation.Attempts[index].EffectState == domain.EffectUnknown && eventType == "STEP_OBSERVED" {
		operation.Status = domain.OperationUnknown
		operation.LastError = domain.ErrDispatchOutcomeUnknown
	}
	if operation.Attempts[index].EffectState == domain.EffectOtherObserved {
		operation.Status = domain.OperationNeedsIntervention
		operation.LastError = domain.ErrExternalIntervention
	}
	attemptPayload, err := json.Marshal(operation.Attempts[index])
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"UPDATE v01_steps SET payload = ?, updated_at = ? WHERE step_id = ? AND operation_id = ?",
		string(attemptPayload), now.UTC().Format(time.RFC3339Nano), stepID, operationID); err != nil {
		return translateWriteError(err)
	}
	if err := saveOperationTx(ctx, tx, operation); err != nil {
		return err
	}
	if err := appendAuditTx(ctx, tx, operationID, eventType, operation.Attempts[index]); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

func (store *Store) MarkUnknown(ctx context.Context, operationID string, now time.Time) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	operation, err := getOperationTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if !domain.CanTransitionOperation(operation.Status, domain.OperationUnknown) {
		return domain.NewError(domain.ErrScopeDenied, "operation cannot transition to UNKNOWN")
	}
	operation.Status = domain.OperationUnknown
	operation.OwnershipReleased = false
	operation.LastError = domain.ErrDispatchOutcomeUnknown
	operation.UpdatedAt = now.UTC()
	if err := saveOperationTx(ctx, tx, operation); err != nil {
		return err
	}
	if err := appendAuditTx(ctx, tx, operationID, "OUTCOME_UNKNOWN", map[string]any{
		"code": domain.ErrDispatchOutcomeUnknown,
	}); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

func (store *Store) TransitionOperation(
	ctx context.Context,
	operationID string,
	to domain.OperationStatus,
	verification domain.VerificationStatus,
	maintenanceReleased bool,
	now time.Time,
) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	operation, err := getOperationTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if !domain.CanTransitionOperation(operation.Status, to) {
		return domain.NewError(domain.ErrScopeDenied, "operation state transition is not allowed")
	}
	if to == domain.OperationSucceeded && !domain.VerificationAllowsSuccess(verification, maintenanceReleased) {
		return domain.NewError(domain.ErrVerificationInconclusive,
			"SUCCEEDED requires verification PASS and confirmed maintenance release")
	}
	operation.Status = to
	operation.Verification = verification
	operation.UpdatedAt = now.UTC()
	switch to {
	case domain.OperationSucceeded, domain.OperationFailed, domain.OperationAborted, domain.OperationRolledBack:
		operation.OwnershipReleased = true
	}
	if err := saveOperationTx(ctx, tx, operation); err != nil {
		return err
	}
	if err := appendAuditTx(ctx, tx, operationID, "OPERATION_STATE_CHANGED", map[string]any{
		"status": to, "verification": verification, "maintenance_released": maintenanceReleased,
	}); err != nil {
		return err
	}
	return translateWriteError(tx.Commit())
}

func getOperationTx(ctx context.Context, tx *sql.Tx, operationID string) (domain.Operation, error) {
	var payload string
	if err := tx.QueryRowContext(ctx,
		"SELECT payload FROM v01_operations WHERE operation_id = ?", operationID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return domain.Operation{}, domain.NewError(domain.ErrNotFound, "operation not found")
	} else if err != nil {
		return domain.Operation{}, err
	}
	var operation domain.Operation
	if err := json.Unmarshal([]byte(payload), &operation); err != nil {
		return operation, err
	}
	return operation, nil
}

func saveOperationTx(ctx context.Context, tx *sql.Tx, operation domain.Operation) error {
	payload, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE v01_operations SET status = ?, ownership_released = ?, payload = ?, updated_at = ?
         WHERE operation_id = ?`, operation.Status, boolInt(operation.OwnershipReleased), string(payload),
		operation.UpdatedAt.Format(time.RFC3339Nano), operation.OperationID)
	if err != nil {
		return translateWriteError(err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return domain.NewError(domain.ErrNotFound, "operation not found")
	}
	return nil
}

func appendAuditTx(ctx context.Context, tx *sql.Tx, entityID, eventType string, payload any) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO v01_audit(entity_id, event_type, payload, created_at) VALUES(?, ?, ?, ?)`,
		entityID, eventType, string(encoded), time.Now().UTC().Format(time.RFC3339Nano))
	return translateWriteError(err)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func translateWriteError(err error) error {
	if err == nil {
		return nil
	}
	return domain.NewError(domain.ErrJournalUnavailable, err.Error())
}
