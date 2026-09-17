package paperops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	hostadapter "guarded-agent-runner/internal/adapters/host"
	paperadapter "guarded-agent-runner/internal/adapters/paper"
	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/workflow"
)

func TestNewRejectsMissingAndAmbiguousFixedEvidence(t *testing.T) {
	if _, err := New(nil, nil, admission.Config{}, domain.Enrollment{}, nil, ""); err == nil {
		t.Fatal("missing fixed adapters were accepted")
	}
	enrollment := domain.Enrollment{RuntimeGuardPairing: "pairing"}
	runtime, err := paperadapter.NewSnapshotTarget(filepath.Join(t.TempDir(), "runtime.json"), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string]domain.ArtifactRecord{
		"a": {ArtifactID: "a", PluginID: "plugin", SHA256: "same"},
		"b": {ArtifactID: "b", PluginID: "plugin", SHA256: "same"},
	}
	if _, err := New(&hostadapter.Observer{}, runtime, admission.Config{}, enrollment, artifacts, "plugin"); err == nil {
		t.Fatal("ambiguous artifact digest registry was accepted")
	}
}

func TestActiveArtifactAndStopRequestStayInsideEnrollment(t *testing.T) {
	target := &Target{
		pluginID: "plugin", artifacts: map[string]string{"digest-a": "artifact-a"},
		enrollment: domain.Enrollment{ContainerID: "fixed-container"},
	}
	artifactID, digest, err := target.activeArtifact(hostadapter.Snapshot{PluginArtifacts: []hostadapter.PluginArtifact{{
		PluginID: "plugin", SHA256: "digest-a",
	}}})
	if err != nil || artifactID != "artifact-a" || digest != "digest-a" {
		t.Fatalf("registered artifact not resolved: id=%q digest=%q err=%v", artifactID, digest, err)
	}
	if _, _, err := target.activeArtifact(hostadapter.Snapshot{PluginArtifacts: []hostadapter.PluginArtifact{{PluginID: "plugin", SHA256: "unknown"}}}); err == nil {
		t.Fatal("unregistered active artifact digest was accepted")
	}
	if err := target.DispatchGracefulStop(context.Background(), workflow.StopRequest{ContainerID: "other"}); err == nil {
		t.Fatal("stop request outside fixed enrollment reached the host adapter")
	}
}

func TestObserveStopRequiresLifecycleRuntimeLogsAndDispatchCorrelation(t *testing.T) {
	const containerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const imageID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Now().UTC()
	request := workflow.StopRequest{
		OperationID: "operation", StepID: "step", ContainerID: containerID,
		BootID: "paper-boot-identity", RequestedAt: now.Add(-2 * time.Second),
	}
	finished := now.Add(-time.Second)
	inspection := map[string]any{
		"Id": containerID,
		"State": map[string]any{
			"Status": "exited", "Running": false, "OOMKilled": false, "ExitCode": 0,
			"StartedAt":  now.Add(-time.Hour).Format(time.RFC3339Nano),
			"FinishedAt": finished.Format(time.RFC3339Nano),
		},
	}
	inspectionPayload, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	logs := request.RequestedAt.Add(time.Millisecond).Format(time.RFC3339Nano) + " Stopping server\n" +
		request.RequestedAt.Add(2*time.Millisecond).Format(time.RFC3339Nano) + " All dimensions are saved\n" +
		request.RequestedAt.Add(3*time.Millisecond).Format(time.RFC3339Nano) + " mc-server-runner\tDone\n"
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
		switch httpRequest.URL.Path {
		case "/containers/" + containerID + "/json":
			_, _ = response.Write(inspectionPayload)
		case "/containers/" + containerID + "/logs":
			_, _ = io.Copy(response, bytes.NewBufferString(logs))
		default:
			http.NotFound(response, httpRequest)
		}
	})}
	go server.Serve(listener)
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	enrollment := domain.Enrollment{
		EnrollmentID: "enrollment", DeploymentGeneration: 1, ContainerID: containerID,
		RuntimeGuardPairing: "pairing", DataRootIdentity: "fixed-root",
	}
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	runtimeSnapshot := paperadapter.Snapshot{
		SchemaVersion: paperadapter.SnapshotSchemaVersion, PairingID: "pairing", BootID: request.BootID,
		ObservedAt: finished.Add(-time.Millisecond), Ready: false, AdmissionState: "MAINTENANCE",
		PlayerCount: 0, TPS: []float64{20, 20, 20}, MSPT: 1, HeapMaxBytes: 1,
	}
	runtimePayload, err := json.Marshal(runtimeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimePath, runtimePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	hostObserver, err := hostadapter.NewObserver(hostadapter.ObserverConfig{
		SchemaVersion: hostadapter.ObserverConfigSchemaVersion, EnrollmentID: enrollment.EnrollmentID,
		DeploymentGeneration: enrollment.DeploymentGeneration, ContainerID: containerID,
		ExpectedImageID: imageID, DataRootPath: t.TempDir(), ExpectedDataRootIdentity: "fixed-root",
		ExpectedBootstrapFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ManagedPluginSlots:           map[string]string{}, DockerSocketPath: socket,
		SnapshotPath: filepath.Join(t.TempDir(), "host.json"), IntervalSeconds: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeTarget, err := paperadapter.NewSnapshotTarget(runtimePath, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	target, err := New(hostObserver, runtimeTarget, admission.Config{}, enrollment,
		map[string]domain.ArtifactRecord{"artifact": {ArtifactID: "artifact", PluginID: "plugin", SHA256: "digest"}}, "plugin")
	if err != nil {
		t.Fatal(err)
	}
	target.acknowledged = &request

	evidence, err := target.ObserveStop(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.LifecycleAvailable || evidence.Running || !evidence.RuntimeTerminal || !evidence.GracefulTermination ||
		evidence.Attribution != domain.AttributionCorrelated {
		t.Fatalf("incomplete stop evidence: %#v", evidence)
	}
	if state := domain.ClassifyStop(domain.DispatchPossible, evidence, evidence.ObservedAt); state != domain.StopConfirmed {
		t.Fatalf("stop state = %s, want %s", state, domain.StopConfirmed)
	}
}
