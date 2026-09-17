package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

// FoundationTarget is an owner-installed evidence/dispatch boundary. No live
// implementation is wired into GAR: the public mutation entry point stays off.
// Implementations must observe all predicates authoritatively and correlate a
// stop to the supplied operation/step; a Docker 2xx is not stop evidence.
type FoundationTarget interface {
	ObserveSafety(context.Context, bool) (domain.SafetyObservation, error)
	CloseAdmission(context.Context, string, string) (MaintenanceReceipt, error)
	DispatchGracefulStop(context.Context, StopRequest) error
	ObserveStop(context.Context, StopRequest) (domain.StopEvidence, error)
}

type StopRequest struct {
	OperationID string
	StepID      string
	ContainerID string
	BootID      string
	RequestedAt time.Time
}

type MaintenanceReceipt struct {
	OperationID string    `json:"operation_id"`
	StepID      string    `json:"step_id"`
	ClosedAt    time.Time `json:"closed_at"`
	References  []string  `json:"references"`
}

type OfflineBackup interface {
	Create(context.Context, domain.BackupRecord, func(context.Context) (domain.BackupReadyEvidence, error)) error
	Inspect(context.Context, string) (domain.BackupRecord, error)
}

// Foundation is intentionally separate from Service/MCP and cannot execute S06.
// Only UNIT/FAKE_TARGET evidence is currently established for this coordinator.
type Foundation struct {
	Store         *store.Store
	Enrollment    domain.Enrollment
	Target        FoundationTarget
	Backup        OfflineBackup
	EvidenceLevel string
	Now           func() time.Time
	StopTimeout   time.Duration
	boundary      func(string) error
}

func (f *Foundation) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

func (f *Foundation) evidenceLevel() string {
	if f.EvidenceLevel == "" {
		return "FAKE_TARGET"
	}
	return f.EvidenceLevel
}
func (f *Foundation) checkpoint(name string) error {
	if f.boundary != nil {
		return f.boundary(name)
	}
	return nil
}

// Run stops at S05 with writer ownership retained and verification NOT_STARTED.
// It never repeats a possibly dispatched action. An interrupted prepared action
// can continue, while a completed action is recovered from durable evidence.
func (f *Foundation) Run(ctx context.Context, operationID string) error {
	if f.Store == nil || f.Target == nil || f.Backup == nil {
		return domain.NewError(domain.ErrPreconditionUnavailable, "foundation adapters are not configured")
	}
	op, err := f.Store.GetOperation(ctx, operationID)
	if err != nil {
		return err
	}
	record, err := f.Store.GetIntent(ctx, op.IntentID)
	if err != nil {
		return err
	}
	i := record.Intent
	if err := i.ValidateDigest(); err != nil {
		return err
	}
	if op.IntentDigest != i.IntentDigest || record.Status != domain.IntentConsumed || op.EnrollmentID != f.Enrollment.EnrollmentID {
		return domain.NewError(domain.ErrApprovalRequired, "foundation requires an independently approved exact intent")
	}
	if len(i.Steps) != len(domain.FixedWorkflowSteps) {
		return domain.NewError(domain.ErrScopeDenied, "unrecognized workflow")
	}
	for n, step := range i.Steps {
		if step != domain.FixedWorkflowSteps[n] {
			return domain.NewError(domain.ErrScopeDenied, "unrecognized workflow")
		}
	}
	if op.OwnershipReleased || (op.Status != domain.OperationQueued && op.Status != domain.OperationPreparing && op.Status != domain.OperationExecuting) {
		return domain.NewError(domain.ErrTargetBlockedUnknown, "operation cannot continue")
	}
	if i.ExecutionBudgetSeconds <= 0 || i.ExecutionBudgetSeconds > 900 {
		return domain.NewError(domain.ErrInvalidRequest, "foundation requires a bounded approved execution budget")
	}
	started := f.now()
	if len(op.Attempts) > 0 {
		started = op.Attempts[0].PreparedAt
	}
	if started.After(f.now()) || !f.now().Before(started.Add(time.Duration(i.ExecutionBudgetSeconds)*time.Second)) {
		return domain.NewError(domain.ErrClockUnsafe, "execution budget elapsed or clock moved backwards")
	}
	ctx, cancel := context.WithTimeout(ctx, started.Add(time.Duration(i.ExecutionBudgetSeconds)*time.Second).Sub(f.now()))
	defer cancel()
	if len(op.Attempts) == 0 || op.Attempts[0].DispatchState == domain.NotDispatched {
		if !f.now().Before(i.StartBefore) {
			return domain.NewError(domain.ErrApprovalExpired, "start deadline elapsed before first durable step")
		}
	}
	if op.Status == domain.OperationQueued {
		if !f.now().Before(i.StartBefore) {
			return domain.NewError(domain.ErrApprovalExpired, "start deadline elapsed")
		}
		if err := f.Store.TransitionOperation(ctx, operationID, domain.OperationPreparing, domain.VerificationNotStarted, false, f.now()); err != nil {
			return err
		}
	}
	for n := 0; n <= 5; n++ {
		op, err = f.Store.GetOperation(ctx, operationID)
		if err != nil {
			return err
		}
		if op.Status == domain.OperationUnknown || op.Status == domain.OperationNeedsIntervention {
			return domain.NewError(domain.ErrTargetBlockedUnknown, "operation is unresolved")
		}
		var a domain.StepAttempt
		if len(op.Attempts) > n {
			a = op.Attempts[n]
			if a.DispatchState == domain.Acknowledged && a.EffectState == domain.EffectExpectedObserved && a.Attribution == domain.AttributionCorrelated {
				continue
			}
			if a.DispatchState != domain.NotDispatched || a.EffectState != domain.EffectProvenNotApplied {
				return f.unknown(ctx, op, a, "interrupted dispatch cannot be repeated")
			}
		} else {
			a, err = f.Store.PrepareStep(ctx, operationID, domain.FixedWorkflowSteps[n], f.now())
			if err != nil {
				return err
			}
			if err := f.checkpoint("prepared:" + a.StepKind); err != nil {
				return err
			}
		}
		if n == 3 && op.Status == domain.OperationPreparing {
			if err := f.Store.TransitionOperation(ctx, operationID, domain.OperationExecuting, domain.VerificationNotStarted, false, f.now()); err != nil {
				return err
			}
		}
		// Read-only checks happen before marking dispatch possible as well.
		var before domain.SafetyObservation
		var ready domain.BackupReadyEvidence
		if n >= 1 && n <= 3 {
			before, err = f.observe(ctx, i, false)
			if err != nil {
				return err
			}
			if before.ProcessStopped {
				return domain.NewError(domain.ErrIntentStale, "Paper is already stopped without this operation's stop evidence")
			}
			if n >= 2 && before.Players != 0 {
				return domain.NewError(domain.ErrIntentStale, "players_zero predicate is false")
			}
			if n == 3 && (!before.AdmissionClosed || !before.Maintenance) {
				return domain.NewError(domain.ErrPreconditionUnavailable, "maintenance acknowledgement is unavailable")
			}
		}
		if n >= 4 {
			ready, err = f.offline(ctx, i, op)
			if err != nil {
				return err
			}
		}
		at := f.now()
		if err := f.Store.MarkDispatchPossible(ctx, operationID, a.StepID, at); err != nil {
			return err
		}
		a.DispatchState = domain.DispatchPossible
		if err := f.checkpoint("dispatch_possible:" + a.StepKind); err != nil {
			return err
		}
		var evidence any
		switch n {
		case 0:
			evidence = map[string]any{"operation_id": op.OperationID, "intent_digest": i.IntentDigest, "execution_epoch": op.ExecutionEpoch}
		case 1:
			evidence = before
		case 2:
			receipt, err := f.Target.CloseAdmission(ctx, operationID, a.StepID)
			if err != nil {
				return f.unknown(ctx, op, a, err.Error())
			}
			if receipt.OperationID != operationID || receipt.StepID != a.StepID || receipt.ClosedAt.Before(at) || !domain.FreshEvidence(receipt.ClosedAt, f.now()) || len(receipt.References) == 0 {
				return f.unknown(ctx, op, a, "maintenance receipt is not correlated")
			}
			closed, err := f.waitMaintenance(ctx, i)
			if err != nil {
				return f.unknown(ctx, op, a, err.Error())
			}
			evidence = struct {
				Receipt     MaintenanceReceipt
				Observation domain.SafetyObservation
			}{receipt, closed}
		case 3:
			request := StopRequest{operationID, a.StepID, i.ContainerID, i.ExpectedBootID, at}
			if err := f.Target.DispatchGracefulStop(ctx, request); err != nil {
				return f.unknown(ctx, op, a, err.Error())
			}
			stop, err := f.waitStopped(ctx, request)
			if err != nil {
				if stop.State == domain.StopFailed {
					if journalErr := f.Store.RecordStepObservation(context.WithoutCancel(ctx), operationID, a.StepID, domain.EffectOtherObserved, stop.Attribution, stop.References, f.now()); journalErr != nil {
						return journalErr
					}
					return domain.NewError(domain.ErrExternalIntervention, err.Error())
				}
				if stop.ContainerID == request.ContainerID && stop.BootID == request.BootID && stop.LifecycleAvailable && !stop.Running && domain.FreshEvidence(stop.ObservedAt, f.now()) && stop.Attribution != domain.AttributionCorrelated {
					if journalErr := f.Store.RecordStepObservation(context.WithoutCancel(ctx), operationID, a.StepID, domain.EffectExpectedObserved, domain.AttributionUnattributed, stop.References, f.now()); journalErr != nil {
						return journalErr
					}
					if journalErr := f.Store.MarkUnknown(context.WithoutCancel(ctx), operationID, f.now()); journalErr != nil {
						return journalErr
					}
					return domain.NewError(domain.ErrDispatchOutcomeUnknown, err.Error())
				}
				return f.unknown(ctx, op, a, err.Error())
			}
			evidence = domain.BackupReadyEvidence{BeforeStop: before, Stop: stop}
		case 4:
			evidence = ready
		case 5:
			r := domain.BackupRecord{
				EvidenceLevel: f.evidenceLevel(),
				BackupID:      i.ReservedBackupID, SchemaVersion: "gar.backup.v1", TargetID: f.Enrollment.TargetID,
				EnrollmentID: i.EnrollmentID, DeploymentGeneration: i.DeploymentGeneration, ContainerIdentity: i.ContainerID,
				DataRootIdentity: f.Enrollment.DataRootIdentity, PaperTuple: i.PaperTuple, BootIDBeforeStop: i.ExpectedBootID,
				IntentID: i.IntentID, IntentDigest: i.IntentDigest, OperationID: operationID, StepID: a.StepID,
				SourceInventoryDigest: i.InventoryDigest, SourceConfigDigest: i.ConfigDigest,
				SourceArtifacts: []domain.ArtifactRecord{{ArtifactID: i.FromArtifactID, PluginID: i.PluginID, SHA256: i.FromSHA256}},
				BackupRecipeID:  domain.BackupRecipeID, BackupRecipeDigest: i.BackupRecipeDigest,
				CreatedAt: f.now(), ConsistencyMode: "OFFLINE", Status: domain.BackupCreating, Ready: ready,
			}
			if err := f.Backup.Create(ctx, r, func(ctx context.Context) (domain.BackupReadyEvidence, error) {
				return f.offline(ctx, i, op)
			}); err != nil {
				// Metadata commit may have succeeded even when its response was lost.
				fresh, readErr := f.Store.GetOperation(ctx, operationID)
				if readErr == nil && len(fresh.Attempts) == 6 && fresh.Attempts[5].EffectState == domain.EffectExpectedObserved && fresh.Attempts[5].Attribution == domain.AttributionCorrelated {
					return err
				}
				return f.unknown(ctx, op, a, err.Error())
			}
			continue
		}
		encoded, err := json.Marshal(evidence)
		if err != nil {
			return f.unknown(ctx, op, a, err.Error())
		}
		if err := f.Store.RecordStepObservation(ctx, operationID, a.StepID, domain.EffectExpectedObserved, domain.AttributionCorrelated, []string{string(encoded)}, f.now()); err != nil {
			return err
		}
		if err := f.checkpoint("completed:" + a.StepKind); err != nil {
			return err
		}
	}
	_, err = f.Backup.Inspect(ctx, i.ReservedBackupID)
	return err
}

func (f *Foundation) observe(ctx context.Context, i domain.ChangeIntent, offline bool) (domain.SafetyObservation, error) {
	o, err := f.Target.ObserveSafety(ctx, offline)
	if err != nil {
		return o, domain.NewError(domain.ErrPreconditionUnavailable, err.Error())
	}
	return o, o.Validate(f.Enrollment, i, f.now())
}

func (f *Foundation) offline(ctx context.Context, i domain.ChangeIntent, op domain.Operation) (domain.BackupReadyEvidence, error) {
	var ready domain.BackupReadyEvidence
	if len(op.Attempts) < 4 || op.Attempts[3].Attribution != domain.AttributionCorrelated || len(op.Attempts[3].Evidence) != 1 {
		return ready, domain.NewError(domain.ErrPreconditionUnavailable, "durable stop evidence is absent")
	}
	if err := json.Unmarshal([]byte(op.Attempts[3].Evidence[0]), &ready); err != nil {
		return ready, err
	}
	if ready.Stop.StepID != op.Attempts[3].StepID {
		return ready, domain.NewError(domain.ErrPreconditionUnavailable, "stop step attribution mismatch")
	}
	o, err := f.observe(ctx, i, true)
	if err != nil {
		return ready, err
	}
	ready.Offline = o
	return ready, ready.Validate(f.Enrollment, i, op, f.now())
}

func (f *Foundation) timeout() time.Duration {
	if f.StopTimeout > 0 && f.StopTimeout <= 2*time.Minute {
		return f.StopTimeout
	}
	return 2 * time.Minute
}

func (f *Foundation) waitMaintenance(ctx context.Context, i domain.ChangeIntent) (domain.SafetyObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		o, err := f.observe(ctx, i, false)
		if err == nil && o.AdmissionClosed && o.Maintenance && o.Players == 0 {
			return o, nil
		}
		if err != nil && domain.CodeOf(err) == domain.ErrIntentStale {
			return o, err
		}
		select {
		case <-ctx.Done():
			return o, ctx.Err()
		case <-tick.C:
		}
	}
}

func (f *Foundation) waitStopped(ctx context.Context, r StopRequest) (domain.StopEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		e, err := f.Target.ObserveStop(ctx, r)
		if err == nil {
			if e.OperationID != r.OperationID || e.StepID != r.StepID || e.ContainerID != r.ContainerID || e.BootID != r.BootID || !e.RequestedAt.Equal(r.RequestedAt) {
				e.State = domain.StopUnknown
				return e, fmt.Errorf("stop observation belongs to another dispatch or target")
			}
			e.State = domain.ClassifyStop(domain.DispatchPossible, e, f.now())
			if e.State == domain.StopConfirmed && e.OperationID == r.OperationID && e.StepID == r.StepID && e.ContainerID == r.ContainerID && e.BootID == r.BootID && e.RequestedAt.Equal(r.RequestedAt) {
				return e, nil
			}
			if e.State == domain.StopFailed {
				return e, fmt.Errorf("graceful termination failed; backup forbidden")
			}
			if e.State == domain.StopUnknown {
				return e, fmt.Errorf("stop completion or attribution is unknown")
			}
		}
		select {
		case <-ctx.Done():
			return e, ctx.Err()
		case <-tick.C:
		}
	}
}

func (f *Foundation) unknown(ctx context.Context, op domain.Operation, a domain.StepAttempt, reason string) error {
	// Persist uncertainty even if the caller's execution deadline has expired.
	journalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := f.Store.RecordStepObservation(journalCtx, op.OperationID, a.StepID, domain.EffectUnknown, domain.AttributionUnattributed, []string{reason}, f.now()); err != nil {
		return err
	}
	return domain.NewError(domain.ErrDispatchOutcomeUnknown, reason)
}
