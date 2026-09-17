// Package paperops provides the fixed, owner-side G-03 lifecycle boundary for
// one enrolled Paper container. It is not reachable from MCP.
package paperops

import (
	"context"
	"fmt"
	"sync"
	"time"

	hostadapter "guarded-agent-runner/internal/adapters/host"
	paperadapter "guarded-agent-runner/internal/adapters/paper"
	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/workflow"
)

type Target struct {
	host       *hostadapter.Observer
	runtime    *paperadapter.SnapshotTarget
	admission  admission.Config
	enrollment domain.Enrollment
	pluginID   string
	artifacts  map[string]string
	now        func() time.Time

	mu           sync.Mutex
	acknowledged *workflow.StopRequest
}

func New(
	host *hostadapter.Observer,
	runtime *paperadapter.SnapshotTarget,
	admissionConfig admission.Config,
	enrollment domain.Enrollment,
	artifacts map[string]domain.ArtifactRecord,
	pluginID string,
) (*Target, error) {
	if host == nil || runtime == nil || pluginID == "" {
		return nil, fmt.Errorf("Paper operations require fixed host, runtime and plugin evidence")
	}
	registered := make(map[string]string)
	for id, artifact := range artifacts {
		if artifact.PluginID != pluginID {
			continue
		}
		if existing, ok := registered[artifact.SHA256]; ok && existing != id {
			return nil, fmt.Errorf("artifact registry ambiguously maps the active plugin digest")
		}
		registered[artifact.SHA256] = id
	}
	if len(registered) == 0 {
		return nil, fmt.Errorf("active plugin has no owner registry entry")
	}
	return &Target{
		host: host, runtime: runtime, admission: admissionConfig,
		enrollment: enrollment, pluginID: pluginID, artifacts: registered,
		now: time.Now,
	}, nil
}

func (target *Target) SetClockForTest(now func() time.Time) { target.now = now }

func (target *Target) ObserveSafety(ctx context.Context, offline bool) (domain.SafetyObservation, error) {
	var (
		hostSnapshot hostadapter.Snapshot
		err          error
	)
	if offline {
		hostSnapshot, err = target.host.ObserveOffline(ctx)
	} else {
		hostSnapshot, err = target.host.Observe(ctx)
	}
	if err != nil {
		return domain.SafetyObservation{}, err
	}
	runtimeSnapshot, runtimeDigest, quality, err := target.runtime.ReadSnapshot()
	if err != nil {
		return domain.SafetyObservation{}, err
	}
	if runtimeSnapshot.BootID == "" {
		return domain.SafetyObservation{}, fmt.Errorf("Paper runtime boot identity unavailable")
	}
	if !offline && quality != domain.Available {
		return domain.SafetyObservation{}, fmt.Errorf("Paper runtime observation is not fresh")
	}
	if offline {
		lifecycle, lifecycleErr := target.host.ObserveLifecycle(ctx)
		if lifecycleErr != nil {
			return domain.SafetyObservation{}, lifecycleErr
		}
		if lifecycle.Running || lifecycle.Status != "exited" || lifecycle.OOMKilled || lifecycle.ExitCode != 0 ||
			runtimeSnapshot.Ready || runtimeSnapshot.ObservedAt.Before(lifecycle.StartedAt) ||
			runtimeSnapshot.ObservedAt.After(lifecycle.FinishedAt) {
			return domain.SafetyObservation{}, fmt.Errorf("terminal Paper runtime evidence does not match the stopped container")
		}
	} else if !runtimeSnapshot.Ready {
		return domain.SafetyObservation{}, fmt.Errorf("Paper runtime is not ready")
	}

	artifactID, artifactSHA, err := target.activeArtifact(hostSnapshot)
	if err != nil {
		return domain.SafetyObservation{}, err
	}
	decision := admission.EvaluateState(target.admission, target.now().UTC())
	admissionClosed := !decision.Open && decision.ReasonCode == "ADMISSION_CLOSED"
	maintenance := runtimeSnapshot.AdmissionState == "MAINTENANCE"
	return domain.SafetyObservation{
		Available: true, ObservedAt: target.now().UTC(), Enrollment: target.enrollment,
		BootID: runtimeSnapshot.BootID, InventoryDigest: hostSnapshot.InventoryDigest,
		ConfigDigest: hostSnapshot.BootstrapFingerprint, SourceArtifactID: artifactID,
		SourceSHA256: artifactSHA, AdmissionClosed: admissionClosed, Maintenance: maintenance,
		Players: runtimeSnapshot.PlayerCount, ProcessStopped: offline,
		FilesystemRootExists: hostSnapshot.DataRootIdentity == target.enrollment.DataRootIdentity,
		NoConflictingWriter:  len(hostSnapshot.CompetingStartupWriters) == 0,
		References: []string{
			"host-observation:" + hostSnapshot.ObservedAt.UTC().Format(time.RFC3339Nano),
			"paper-runtime:sha256:" + runtimeDigest,
			"admission:" + decision.ReasonCode,
		},
	}, nil
}

func (target *Target) activeArtifact(snapshot hostadapter.Snapshot) (string, string, error) {
	for _, artifact := range snapshot.PluginArtifacts {
		if artifact.PluginID != target.pluginID {
			continue
		}
		id, ok := target.artifacts[artifact.SHA256]
		if !ok {
			return "", "", fmt.Errorf("active plugin digest is absent from the owner registry")
		}
		return id, artifact.SHA256, nil
	}
	return "", "", fmt.Errorf("active plugin is absent from host evidence")
}

func (target *Target) CloseAdmission(_ context.Context, operationID, stepID string) (workflow.MaintenanceReceipt, error) {
	closedAt := target.now().UTC()
	state, err := admission.WriteState(target.admission, admission.ModeClosed,
		"GAR G-03 operation "+operationID+" step "+stepID, 0, closedAt)
	if err != nil {
		return workflow.MaintenanceReceipt{}, err
	}
	return workflow.MaintenanceReceipt{
		OperationID: operationID, StepID: stepID, ClosedAt: state.IssuedAt,
		References: []string{"admission-state:CLOSED", "pairing:" + state.PairingID},
	}, nil
}

func (target *Target) DispatchGracefulStop(ctx context.Context, request workflow.StopRequest) error {
	if request.ContainerID != target.enrollment.ContainerID || request.OperationID == "" || request.StepID == "" || request.BootID == "" {
		return fmt.Errorf("stop request does not match the fixed enrollment")
	}
	if err := target.host.StopContainer(ctx, 120*time.Second); err != nil {
		return err
	}
	target.mu.Lock()
	copy := request
	target.acknowledged = &copy
	target.mu.Unlock()
	return nil
}

func (target *Target) ObserveStop(ctx context.Context, request workflow.StopRequest) (domain.StopEvidence, error) {
	lifecycle, err := target.host.ObserveLifecycle(ctx)
	if err != nil {
		return domain.StopEvidence{}, err
	}
	evidence := domain.StopEvidence{
		OperationID: request.OperationID, StepID: request.StepID,
		ContainerID: lifecycle.ContainerID, BootID: request.BootID,
		RequestedAt: request.RequestedAt, ObservedAt: lifecycle.ObservedAt,
		FinishedAt: lifecycle.FinishedAt, LifecycleAvailable: true,
		Running: lifecycle.Running, ExitCode: lifecycle.ExitCode, OOMKilled: lifecycle.OOMKilled,
		Attribution: domain.AttributionUnattributed,
		References:  []string{"docker-lifecycle:" + lifecycle.Status},
	}
	if lifecycle.Running {
		evidence.State = domain.StopStopping
		return evidence, nil
	}
	runtimeSnapshot, runtimeDigest, _, runtimeErr := target.runtime.ReadSnapshot()
	if runtimeErr == nil && !runtimeSnapshot.Ready && runtimeSnapshot.BootID == request.BootID &&
		!runtimeSnapshot.ObservedAt.Before(request.RequestedAt) && !runtimeSnapshot.ObservedAt.After(lifecycle.FinishedAt) {
		evidence.RuntimeTerminal = true
		evidence.References = append(evidence.References, "paper-terminal:sha256:"+runtimeDigest)
	}
	logReferences, logErr := target.host.GracefulStopLogEvidence(ctx, request.RequestedAt)
	if logErr == nil && evidence.RuntimeTerminal {
		evidence.GracefulTermination = true
		evidence.References = append(evidence.References, logReferences...)
	}
	target.mu.Lock()
	acknowledged := target.acknowledged != nil && *target.acknowledged == request
	target.mu.Unlock()
	if acknowledged && !lifecycle.FinishedAt.Before(request.RequestedAt) {
		evidence.Attribution = domain.AttributionCorrelated
	}
	return evidence, nil
}
