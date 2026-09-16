package workflow

import (
	"context"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

// OperatorService is intentionally separate from the agent tool service.
// It is used by garctl over owner-local database access; it is never registered
// as an agent-facing tool (INV-02, AT-001).
type OperatorService struct {
	Store *store.Store
	Now   func() time.Time
}

func (service OperatorService) Approve(
	ctx context.Context,
	intentID, exactDigest, approver string,
	osUID int,
) (domain.Approval, domain.Operation, error) {
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	return service.Store.ApproveIntent(ctx, intentID, exactDigest, approver, osUID, now)
}

func (service OperatorService) Reject(
	ctx context.Context,
	intentID, exactDigest, approver string,
	osUID int,
) (domain.Approval, error) {
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	return service.Store.RejectIntent(ctx, intentID, exactDigest, approver, osUID, now)
}

func (service OperatorService) Revoke(
	ctx context.Context,
	intentID, exactDigest, actor string,
	osUID int,
) error {
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	return service.Store.RevokeIntent(ctx, intentID, exactDigest, actor, osUID, now)
}
