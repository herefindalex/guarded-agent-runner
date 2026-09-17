package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"guarded-agent-runner/internal/backup"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/store"
)

type foundationTarget struct {
	observation  domain.SafetyObservation
	stopCalls    int
	stopErr      error
	stopping     bool
	unattributed bool
	failed       bool
	wrongTarget  bool
}

func (t *foundationTarget) ObserveSafety(_ context.Context, offline bool) (domain.SafetyObservation, error) {
	o := t.observation
	if offline {
		o.ProcessStopped = t.stopCalls > 0 && !t.stopping
	}
	return o, nil
}
func (t *foundationTarget) CloseAdmission(_ context.Context, op, step string) (MaintenanceReceipt, error) {
	t.observation.AdmissionClosed = true
	t.observation.Maintenance = true
	return MaintenanceReceipt{op, step, t.observation.ObservedAt, []string{"fake-close-receipt"}}, nil
}
func (t *foundationTarget) DispatchGracefulStop(_ context.Context, r StopRequest) error {
	t.stopCalls++
	return t.stopErr
}
func (t *foundationTarget) ObserveStop(_ context.Context, r StopRequest) (domain.StopEvidence, error) {
	if t.wrongTarget {
		r.ContainerID = "different-container"
	}
	a := domain.AttributionCorrelated
	if t.unattributed {
		a = domain.AttributionUnattributed
	}
	exit := 0
	if t.failed {
		exit = 137
	}
	return domain.StopEvidence{OperationID: r.OperationID, StepID: r.StepID, ContainerID: r.ContainerID, BootID: r.BootID, RequestedAt: r.RequestedAt, ObservedAt: t.observation.ObservedAt, FinishedAt: t.observation.ObservedAt, LifecycleAvailable: true, Running: t.stopping, ExitCode: exit, RuntimeTerminal: !t.stopping, GracefulTermination: !t.failed, Attribution: a, References: []string{"FAKE_TARGET: process exit and runtime terminal receipt"}}, nil
}

func foundationFixture(t *testing.T) (*Foundation, *foundationTarget, domain.Operation, domain.ChangeIntent, backup.Config, string) {
	t.Helper()
	fx := newFixture(t)
	root := t.TempDir()
	destination := t.TempDir()
	if err := os.Chmod(destination, 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("approved artifact A")
	if err := os.WriteFile(filepath.Join(root, "example.jar"), data, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	fXEnrollment := fx.service.Registry.Enrollment
	fXEnrollment.DataRootIdentity = fmt.Sprintf("dev:%d/inode:%d", st.Dev, st.Ino)
	fx.service.Registry.Enrollment = fXEnrollment
	h := sha256.Sum256(data)
	artifact := fx.service.Registry.Artifacts["artifact-a"]
	artifact.SHA256 = hex.EncodeToString(h[:])
	fx.service.Registry.Artifacts["artifact-a"] = artifact
	record, err := fx.service.Propose(context.Background(), fx.scope, proposal("foundation", "FAKE_TARGET only"))
	if err != nil {
		t.Fatal(err)
	}
	_, op, err := (OperatorService{Store: fx.store, Now: func() time.Time { return fx.now }}).Approve(context.Background(), record.Intent.IntentID, record.Intent.IntentDigest, "owner", os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	target := &foundationTarget{observation: domain.SafetyObservation{Available: true, ObservedAt: fx.now, Enrollment: fXEnrollment, BootID: "boot-a", InventoryDigest: "inventory-a", ConfigDigest: "config-a", SourceArtifactID: artifact.ArtifactID, SourceSHA256: artifact.SHA256, FilesystemRootExists: true, NoConflictingWriter: true, References: []string{"FAKE_TARGET safety snapshot"}}}
	cfg := backup.Config{DataRoot: root, Destination: destination, SourceArtifactPath: "example.jar", Enrollment: fXEnrollment, MaxBytes: 1 << 20, MaxFiles: 100}
	engine, err := backup.New(cfg, fx.store)
	if err != nil {
		t.Fatal(err)
	}
	f := &Foundation{Store: fx.store, Enrollment: fXEnrollment, Target: target, Backup: engine, Now: func() time.Time { return fx.now }, StopTimeout: 10 * time.Millisecond}
	return f, target, op, record.Intent, cfg, fx.dbPath
}

func TestFoundationThroughS05RetainsWriterAndCannotReachS06(t *testing.T) {
	f, target, op, i, _, _ := foundationFixture(t)
	if err := f.Run(context.Background(), op.OperationID); err != nil {
		t.Fatal(err)
	}
	result, err := f.Store.GetOperation(context.Background(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attempts) != 6 || result.OwnershipReleased || result.Status != domain.OperationExecuting || result.Verification != domain.VerificationNotStarted || target.stopCalls != 1 {
		t.Fatalf("unexpected S05 result: %+v stop=%d", result, target.stopCalls)
	}
	for _, a := range result.Attempts {
		if a.DispatchState != domain.Acknowledged || a.EffectState != domain.EffectExpectedObserved || a.Attribution != domain.AttributionCorrelated || len(a.Evidence) == 0 {
			t.Fatalf("missing durable correlated step: %+v", a)
		}
	}
	if _, err := f.Backup.Inspect(context.Background(), i.ReservedBackupID); err != nil {
		t.Fatal(err)
	}
	if err := f.Run(context.Background(), op.OperationID); err != nil {
		t.Fatal(err)
	}
	if target.stopCalls != 1 {
		t.Fatal("completed stop was dispatched twice")
	}
	if _, err := f.Store.PrepareStep(context.Background(), op.OperationID, "S06_REPLACE_ARTIFACT", f.now()); domain.CodeOf(err) != domain.ErrUnsupportedEnvironment {
		t.Fatalf("S06 allowed: %v", err)
	}
}

func TestFoundationRevokedPreparedStopCannotDispatch(t *testing.T) {
	f, target, op, i, _, _ := foundationFixture(t)
	f.boundary = func(name string) error {
		if name == "prepared:S03_GRACEFUL_STOP" {
			return errors.New("crash")
		}
		return nil
	}
	if err := f.Run(context.Background(), op.OperationID); err == nil {
		t.Fatal("missing interruption")
	}
	state, err := f.Store.GetOperation(context.Background(), op.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Store.RevokeIntent(context.Background(), i.IntentID, i.IntentDigest, "owner", os.Getuid(), f.now()); err != nil {
		t.Fatal(err)
	}
	if err := f.Store.MarkDispatchPossible(context.Background(), op.OperationID, state.Attempts[3].StepID, f.now()); domain.CodeOf(err) != domain.ErrApprovalRevoked {
		t.Fatalf("revoked prepared stop can dispatch: %v", err)
	}
	if target.stopCalls != 0 {
		t.Fatal("stop dispatched despite revocation")
	}
}

func reopenFoundation(t *testing.T, f *Foundation, cfg backup.Config, path string) {
	t.Helper()
	if err := f.Store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f.Store = db
	engine, err := backup.New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	f.Backup = engine
}

func TestFoundationCrashBeforeAndAfterStopDispatch(t *testing.T) {
	for _, point := range []string{"prepared:S03_GRACEFUL_STOP", "dispatch_possible:S03_GRACEFUL_STOP", "completed:S03_GRACEFUL_STOP"} {
		t.Run(point, func(t *testing.T) {
			f, target, op, _, cfg, dbPath := foundationFixture(t)
			crash := errors.New("injected process death")
			f.boundary = func(name string) error {
				if name == point {
					return crash
				}
				return nil
			}
			if err := f.Run(context.Background(), op.OperationID); !errors.Is(err, crash) {
				t.Fatalf("crash not reached: %v", err)
			}
			reopenFoundation(t, f, cfg, dbPath)
			f.boundary = nil
			recovered, err := f.Store.GetOperation(context.Background(), op.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if point == "prepared:S03_GRACEFUL_STOP" && (recovered.Attempts[3].DispatchState != domain.NotDispatched || recovered.Attempts[3].EffectState != domain.EffectProvenNotApplied) {
				t.Fatal("prepared step was not proven unapplied")
			}
			err = f.Run(context.Background(), op.OperationID)
			if point == "dispatch_possible:S03_GRACEFUL_STOP" {
				if domain.CodeOf(err) != domain.ErrDispatchOutcomeUnknown || target.stopCalls != 0 {
					t.Fatalf("ambiguous dispatch retried: %v calls=%d", err, target.stopCalls)
				}
				state, _ := f.Store.GetOperation(context.Background(), op.OperationID)
				if state.Status != domain.OperationUnknown || state.OwnershipReleased {
					t.Fatal("UNKNOWN did not retain ownership")
				}
			} else if err != nil || target.stopCalls != 1 {
				t.Fatalf("safe recovery failed: %v calls=%d", err, target.stopCalls)
			}
		})
	}
}

func TestFoundationStopRecoveryRequiresNewOfflineValidation(t *testing.T) {
	f, target, op, _, cfg, dbPath := foundationFixture(t)
	f.boundary = func(name string) error {
		if name == "completed:S03_GRACEFUL_STOP" {
			return errors.New("crash")
		}
		return nil
	}
	if err := f.Run(context.Background(), op.OperationID); err == nil {
		t.Fatal("missing crash")
	}
	reopenFoundation(t, f, cfg, dbPath)
	f.boundary = nil
	target.observation.SourceSHA256 = "changed"
	if err := f.Run(context.Background(), op.OperationID); domain.CodeOf(err) != domain.ErrIntentStale {
		t.Fatalf("stale offline source accepted: %v", err)
	}
	if target.stopCalls != 1 {
		t.Fatal("recovery dispatched another stop")
	}
	files, err := os.ReadDir(cfg.Destination)
	if err != nil || len(files) != 0 {
		t.Fatal("backup started despite stale source")
	}
}

func TestFoundationAmbiguousOrFailedStopNeverStartsBackup(t *testing.T) {
	for _, mode := range []string{"response_lost", "timeout", "unattributed", "failed", "wrong_target"} {
		t.Run(mode, func(t *testing.T) {
			f, target, op, _, cfg, _ := foundationFixture(t)
			switch mode {
			case "response_lost":
				target.stopErr = errors.New("response lost after dispatch")
			case "timeout":
				target.stopping = true
			case "unattributed":
				target.unattributed = true
			case "failed":
				target.failed = true
			case "wrong_target":
				target.wrongTarget = true
			}
			err := f.Run(context.Background(), op.OperationID)
			if err == nil {
				t.Fatal("unsafe stop succeeded")
			}
			state, _ := f.Store.GetOperation(context.Background(), op.OperationID)
			if mode == "failed" {
				if state.Status != domain.OperationNeedsIntervention {
					t.Fatal(state.Status)
				}
			} else if state.Status != domain.OperationUnknown {
				t.Fatal(state.Status)
			}
			if mode == "unattributed" && (state.Attempts[3].EffectState != domain.EffectExpectedObserved || state.Attempts[3].Attribution != domain.AttributionUnattributed) {
				t.Fatal("unattributed expected state was lost")
			}
			if err := f.Run(context.Background(), op.OperationID); err == nil {
				t.Fatal("unsafe retry succeeded")
			}
			if target.stopCalls != 1 {
				t.Fatal("blind stop retry")
			}
			files, err := os.ReadDir(cfg.Destination)
			if err != nil || len(files) != 0 {
				t.Fatal("backup began after uncertain stop")
			}
		})
	}
}
