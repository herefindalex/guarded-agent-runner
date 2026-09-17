package domain

import (
	"testing"
	"time"
)

func TestGracefulStopOracle(t *testing.T) {
	now := time.Now().UTC()
	base := StopEvidence{OperationID: "operation", StepID: "step", ContainerID: "container", BootID: "boot", RequestedAt: now.Add(-time.Second), ObservedAt: now, FinishedAt: now, LifecycleAvailable: true, RuntimeTerminal: true, GracefulTermination: true, Attribution: AttributionCorrelated, References: []string{"process exit and correlated terminal runtime"}}
	for _, test := range []struct {
		name     string
		dispatch DispatchState
		change   func(*StopEvidence)
		want     StopState
	}{
		{"not_requested", NotDispatched, func(e *StopEvidence) {}, StopNotRequested},
		{"invalid_dispatch", DispatchState("invalid"), func(e *StopEvidence) {}, StopUnknown},
		{"stopped", DispatchPossible, func(e *StopEvidence) {}, StopConfirmed},
		{"stopping", DispatchPossible, func(e *StopEvidence) { e.Running = true }, StopStopping},
		{"docker_ack_only", Acknowledged, func(e *StopEvidence) { e.RuntimeTerminal = false }, StopUnknown},
		{"unattributed", DispatchPossible, func(e *StopEvidence) { e.Attribution = AttributionUnattributed }, StopUnknown},
		{"killed", DispatchPossible, func(e *StopEvidence) { e.ExitCode = 137 }, StopFailed},
		{"oom", DispatchPossible, func(e *StopEvidence) { e.OOMKilled = true }, StopFailed},
		{"stale", DispatchPossible, func(e *StopEvidence) { e.ObservedAt = now.Add(-6 * time.Second) }, StopUnknown},
		{"future", DispatchPossible, func(e *StopEvidence) { e.ObservedAt = now.Add(time.Second) }, StopUnknown},
		{"already_stopped", DispatchPossible, func(e *StopEvidence) { e.FinishedAt = now.Add(-2 * time.Second) }, StopUnknown},
		{"no_graceful_evidence", DispatchPossible, func(e *StopEvidence) { e.GracefulTermination = false }, StopUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := base
			test.change(&e)
			if got := ClassifyStop(test.dispatch, e, now); got != test.want {
				t.Fatalf("got %s want %s", got, test.want)
			}
		})
	}
}

func TestSafetyUnavailableAndStaleRemainDistinct(t *testing.T) {
	now := time.Now().UTC()
	en := Enrollment{TargetID: "target", EnrollmentID: "enrollment", ContainerID: "container", DataRootIdentity: "dev:1/inode:2"}
	i := ChangeIntent{EnrollmentID: en.EnrollmentID, ContainerID: en.ContainerID, ExpectedBootID: "boot", FromArtifactID: "a", FromSHA256: "sha", InventoryDigest: "inventory", ConfigDigest: "config"}
	base := SafetyObservation{Available: true, ObservedAt: now, Enrollment: en, BootID: "boot", InventoryDigest: "inventory", ConfigDigest: "config", SourceArtifactID: "a", SourceSHA256: "sha", NoConflictingWriter: true, FilesystemRootExists: true, References: []string{"authoritative"}}
	for _, tc := range []struct {
		name   string
		change func(*SafetyObservation)
		want   ErrorCode
	}{
		{"missing", func(o *SafetyObservation) { o.Available = false }, ErrPreconditionUnavailable},
		{"stale_snapshot", func(o *SafetyObservation) { o.ObservedAt = now.Add(-6 * time.Second) }, ErrPreconditionUnavailable},
		{"future", func(o *SafetyObservation) { o.ObservedAt = now.Add(time.Second) }, ErrPreconditionUnavailable},
		{"missing_hash", func(o *SafetyObservation) { o.SourceSHA256 = "" }, ErrPreconditionUnavailable},
		{"changed_hash", func(o *SafetyObservation) { o.SourceSHA256 = "new" }, ErrIntentStale},
		{"changed_generation", func(o *SafetyObservation) { o.Enrollment.DeploymentGeneration++ }, ErrIntentStale},
		{"changed_root", func(o *SafetyObservation) { o.Enrollment.DataRootIdentity = "new" }, ErrIntentStale},
		{"writer", func(o *SafetyObservation) { o.NoConflictingWriter = false }, ErrTargetBusy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.change(&o)
			if err := o.Validate(en, i, now); CodeOf(err) != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
		})
	}
}
