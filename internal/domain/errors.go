package domain

import (
	"errors"
	"fmt"
)

// ErrorCode is the stable machine-facing error vocabulary from GAR-PCS-001 §20.1.
type ErrorCode string

const (
	ErrUnsupportedEnvironment   ErrorCode = "UNSUPPORTED_ENVIRONMENT"
	ErrUnsupportedTransition    ErrorCode = "UNSUPPORTED_PLUGIN_TRANSITION"
	ErrScopeDenied              ErrorCode = "SCOPE_DENIED"
	ErrApprovalRequired         ErrorCode = "APPROVAL_REQUIRED"
	ErrApprovalExpired          ErrorCode = "APPROVAL_EXPIRED"
	ErrApprovalRevoked          ErrorCode = "APPROVAL_REVOKED"
	ErrIntentStale              ErrorCode = "INTENT_STALE"
	ErrPreconditionUnavailable  ErrorCode = "PRECONDITION_UNAVAILABLE"
	ErrTargetBusy               ErrorCode = "TARGET_BUSY"
	ErrTargetBlockedUnknown     ErrorCode = "TARGET_BLOCKED_UNKNOWN"
	ErrIdempotencyConflict      ErrorCode = "IDEMPOTENCY_CONFLICT"
	ErrBackupNotReady           ErrorCode = "BACKUP_NOT_READY"
	ErrDispatchOutcomeUnknown   ErrorCode = "DISPATCH_OUTCOME_UNKNOWN"
	ErrVerificationInconclusive ErrorCode = "VERIFICATION_INCONCLUSIVE"
	ErrRecoveryUnsafe           ErrorCode = "RECOVERY_UNSAFE"
	ErrExternalIntervention     ErrorCode = "EXTERNAL_INTERVENTION"
	ErrJournalUnavailable       ErrorCode = "JOURNAL_UNAVAILABLE"
	ErrClockUnsafe              ErrorCode = "CLOCK_UNSAFE"
	ErrInvalidIntentDigest      ErrorCode = "INVALID_INTENT_DIGEST"
	ErrNotFound                 ErrorCode = "NOT_FOUND"
	ErrInvalidRequest           ErrorCode = "INVALID_REQUEST"
)

type GARException struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e *GARException) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewError(code ErrorCode, message string) error {
	return &GARException{Code: code, Message: message}
}

func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var typed *GARException
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ErrJournalUnavailable
}
