package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/domain"
)

const testContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testImageID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testGateContainerID = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const testGateImageID = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func TestObserverPublishesFixedTargetEvidence(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	dataRoot := makeDataRoot(t)
	inspection := testInspection(dataRoot)
	fingerprint, _, err := bootstrapFingerprint(inspection)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := dataRootIdentity(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	socket, stop := serveDockerInspect(t, inspection)
	defer stop()
	config := ObserverConfig{
		SchemaVersion: ObserverConfigSchemaVersion, EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
		ContainerID: testContainerID, ExpectedImageID: testImageID, DataRootPath: dataRoot,
		ExpectedDataRootIdentity: identity, ExpectedBootstrapFingerprint: fingerprint,
		ManagedPluginSlots: map[string]string{"gar-guard": "GARGuard.jar"}, DockerSocketPath: socket,
		SnapshotPath: filepath.Join(t.TempDir(), "host-observation.json"), IntervalSeconds: 1,
	}
	observer, err := NewObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	observer.SetClockForTest(func() time.Time { return now })
	snapshot, err := observer.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Running || len(snapshot.PluginArtifacts) != 1 || snapshot.PluginArtifacts[0].SHA256 == "" {
		t.Fatalf("incomplete host evidence: %#v", snapshot)
	}
	if len(snapshot.RecentErrors) != 1 || !strings.HasPrefix(snapshot.RecentErrors[0], "PAPER_ERROR sha256:") {
		t.Fatalf("bounded error evidence missing: %#v", snapshot.RecentErrors)
	}
	if snapshot.RecentErrorsAvailability != domain.Available || snapshot.ErrorCursor == "" {
		t.Fatalf("recent-error quality metadata missing: %#v", snapshot)
	}
	if err := observer.Publish(snapshot); err != nil {
		t.Fatal(err)
	}
	enrollment := domain.Enrollment{
		EnrollmentID: "enrollment-a", DeploymentGeneration: 1, ContainerID: testContainerID,
		ImageDigest: testImageID, DataRootIdentity: identity, BootstrapFingerprint: fingerprint,
	}
	target, err := NewSnapshotTarget(config.SnapshotPath, enrollment, map[string]domain.ArtifactRecord{
		"artifact-a": {ArtifactID: "artifact-a", PluginID: "gar-guard", SHA256: snapshot.PluginArtifacts[0].SHA256},
	})
	if err != nil {
		t.Fatal(err)
	}
	target.SetClockForTest(func() time.Time { return now })
	bundle, err := target.Observe(context.Background(), enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.ActiveArtifacts["gar-guard"] != "artifact-a" || bundle.ContainerID != testContainerID {
		t.Fatalf("unexpected observation bundle: %#v", bundle)
	}
}

func TestEnrollmentObserverAllowsMissingPinsButServingDoesNot(t *testing.T) {
	dataRoot := makeDataRoot(t)
	inspection := testInspection(dataRoot)
	socket, stop := serveDockerInspect(t, inspection)
	defer stop()
	config := ObserverConfig{
		SchemaVersion: ObserverConfigSchemaVersion, EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
		ContainerID: testContainerID, DataRootPath: dataRoot, ManagedPluginSlots: map[string]string{"gar-guard": "GARGuard.jar"},
		DockerSocketPath: socket, SnapshotPath: filepath.Join(t.TempDir(), "host.json"), IntervalSeconds: 1,
	}
	if _, err := NewObserver(config); err == nil {
		t.Fatal("serving observer accepted missing fixed identity pins")
	}
	observer, err := NewEnrollmentObserver(config)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := observer.Observe(context.Background())
	if err != nil || snapshot.ImageID != testImageID || snapshot.BootstrapFingerprint == "" || snapshot.DataRootIdentity == "" {
		t.Fatalf("enrollment facts were not derived: %#v %v", snapshot, err)
	}
}

func TestObserverFailsClosedForCompetingWriterAndStoppedContainer(t *testing.T) {
	dataRoot := makeDataRoot(t)
	for _, test := range []struct {
		name   string
		mutate func(*dockerInspection)
		reason string
	}{
		{"competing writer", func(value *dockerInspection) {
			value.Config.Env = append(value.Config.Env, "PLUGINS=https://invalid.example/plugin.jar")
		}, "COMPETING_STARTUP_WRITERS"},
		{"mutable default configs", func(value *dockerInspection) {
			value.Config.Env = []string{"ENABLE_AUTOPAUSE=FALSE", "ENABLE_AUTOSTOP=FALSE", "TYPE=PAPER"}
		}, "COMPETING_STARTUP_WRITERS"},
		{"stopped", func(value *dockerInspection) { value.State.Running = false; value.State.Status = "exited" }, "CONTAINER_NOT_RUNNING"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspection := testInspection(dataRoot)
			test.mutate(&inspection)
			fingerprint, _, _ := bootstrapFingerprint(inspection)
			identity, _ := dataRootIdentity(dataRoot)
			socket, stop := serveDockerInspect(t, inspection)
			defer stop()
			observer, err := NewObserver(ObserverConfig{
				SchemaVersion: ObserverConfigSchemaVersion, EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
				ContainerID: testContainerID, ExpectedImageID: testImageID, DataRootPath: dataRoot,
				ExpectedDataRootIdentity: identity, ExpectedBootstrapFingerprint: fingerprint,
				ManagedPluginSlots: map[string]string{}, DockerSocketPath: socket,
				SnapshotPath: filepath.Join(t.TempDir(), "host.json"), IntervalSeconds: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := observer.Observe(context.Background())
			if err == nil || snapshot.ReasonCode != test.reason || snapshot.Availability != domain.Unavailable {
				t.Fatalf("did not fail closed: snapshot=%#v err=%v", snapshot, err)
			}
		})
	}
}

func TestSnapshotRejectsDuplicateKeysAndSymlinkedPlugin(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "host.json")
	duplicate := `{"schema_version":"gar.host-observation.v1","schema_version":"gar.host-observation.v1"}`
	if err := os.WriteFile(path, []byte(duplicate), 0o640); err != nil {
		t.Fatal(err)
	}
	target, err := NewSnapshotTarget(path, domain.Enrollment{EnrollmentID: "e", DeploymentGeneration: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	target.SetClockForTest(func() time.Time { return now })
	if _, _, err := target.read(); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}

	dataRoot := makeDataRoot(t)
	pluginPath := filepath.Join(dataRoot, "plugins", "GARGuard.jar")
	if err := os.Remove(pluginPath); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.jar")
	if err := os.WriteFile(outside, []byte("plugin"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, pluginPath); err != nil {
		t.Fatal(err)
	}
	if _, err := observePluginArtifacts(dataRoot, map[string]string{"gar-guard": "GARGuard.jar"}, nil); err == nil {
		t.Fatal("symlinked plugin artifact was accepted")
	}
}

func TestObserverHashesBindMountedPluginAndRejectsUnknownJar(t *testing.T) {
	dataRoot := makeDataRoot(t)
	if err := os.Remove(filepath.Join(dataRoot, "plugins", "GARGuard.jar")); err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(t.TempDir(), "GARGuard.jar")
	if err := os.WriteFile(mounted, []byte("mounted plugin"), 0o640); err != nil {
		t.Fatal(err)
	}
	mounts := []dockerMount{{Type: "bind", Source: mounted, Destination: "/data/plugins/GARGuard.jar", RW: false}}
	artifacts, err := observePluginArtifacts(dataRoot, map[string]string{"gar-guard": "GARGuard.jar"}, mounts)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("bind-mounted managed plugin was not attributed: %#v %v", artifacts, err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "plugins", "Unknown.jar"), []byte("unknown"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := observePluginArtifacts(dataRoot, map[string]string{"gar-guard": "GARGuard.jar"}, mounts); err == nil {
		t.Fatal("unregistered plugin JAR was accepted")
	}
}

func TestValidateAdmissionBarrierAcceptsOnlyEnrolledTopology(t *testing.T) {
	paper := testInspection(t.TempDir())
	setPublishedBindings(&paper, []PublishedBinding{
		{HostIP: "127.0.0.1", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"},
		{HostIP: "::1", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"},
	})
	config, admissionConfig := testAdmissionBarrierConfig(t)
	gate := testGateInspection(config, admissionConfig)

	if err := validateAdmissionBarrier(paper, gate, config, admissionConfig); err != nil {
		t.Fatalf("valid enrolled admission topology rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*dockerInspection, *dockerInspection)
	}{
		{"published port drift", func(paper, _ *dockerInspection) {
			setPublishedBindings(paper, []PublishedBinding{
				{HostIP: "127.0.0.1", HostPort: 25566, ContainerPort: 25565, Protocol: "tcp"},
				{HostIP: "::1", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"},
			})
		}},
		{"direct Paper port published", func(paper, _ *dockerInspection) {
			setPublishedBindings(paper, append(config.PublishedBindings,
				PublishedBinding{HostIP: "127.0.0.1", HostPort: 25566, ContainerPort: 25566, Protocol: "tcp"}))
		}},
		{"network namespace mismatch", func(_, gate *dockerInspection) {
			gate.HostConfig.NetworkMode = "bridge"
		}},
		{"missing capability drop", func(_, gate *dockerInspection) {
			gate.HostConfig.CapDrop = nil
		}},
		{"writable root filesystem", func(_, gate *dockerInspection) {
			gate.HostConfig.ReadonlyRootfs = false
		}},
		{"missing no-new-privileges", func(_, gate *dockerInspection) {
			gate.HostConfig.SecurityOpt = nil
		}},
		{"command mismatch", func(_, gate *dockerInspection) {
			gate.Config.Cmd = []string{"serve", "--config", "/untrusted/config.json"}
		}},
		{"Docker socket mount", func(_, gate *dockerInspection) {
			gate.Mounts = append(gate.Mounts, dockerMount{Destination: "/var/run/docker.sock"})
		}},
		{"gate binary mount missing", func(_, gate *dockerInspection) {
			gate.Mounts = gate.Mounts[1:]
		}},
		{"evidence mount writable", func(_, gate *dockerInspection) {
			gate.Mounts[1].RW = true
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedPaper := paper
			changedGate := gate
			test.mutate(&changedPaper, &changedGate)
			if err := validateAdmissionBarrier(changedPaper, changedGate, config, admissionConfig); err == nil {
				t.Fatal("unsafe admission topology was accepted")
			}
		})
	}
	if err := os.WriteFile(config.GateBinaryPath, []byte("replaced gate binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateAdmissionBarrier(paper, gate, config, admissionConfig); err == nil {
		t.Fatal("replaced gate binary was accepted")
	}
}

func TestAdmissionBarrierConfigRejectsNonLoopbackBinding(t *testing.T) {
	dataRoot := makeDataRoot(t)
	barrier, _ := testAdmissionBarrierConfig(t)
	barrier.PublishedBindings = []PublishedBinding{{HostIP: "0.0.0.0", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"}}
	config := ObserverConfig{
		SchemaVersion: ObserverConfigSchemaVersion, EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
		ContainerID: testContainerID, ExpectedImageID: testImageID, DataRootPath: dataRoot,
		ExpectedDataRootIdentity: "dev:1/inode:1", ExpectedBootstrapFingerprint: strings.Repeat("e", 64),
		ManagedPluginSlots: map[string]string{}, DockerSocketPath: "/var/run/docker.sock",
		SnapshotPath: filepath.Join(t.TempDir(), "host.json"), IntervalSeconds: 1,
		AdmissionBarrier: &barrier,
	}
	if err := config.Validate(); err == nil {
		t.Fatal("non-loopback admission binding was accepted")
	}
}

func TestReferenceComposeKeepsOnlyEntrypointIdentityCapabilities(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "itzg-paper", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{"cap_drop:\n      - ALL", "cap_add:\n      - CHOWN\n      - SETGID\n      - SETUID", `restart: "no"`, `SKIP_DOWNLOAD_DEFAULTS: "TRUE"`} {
		if !strings.Contains(text, required) {
			t.Fatalf("reference fixture lacks lifecycle capability invariant %q", required)
		}
	}
	if strings.Contains(text, "ports:") {
		t.Fatal("reference fixture unexpectedly publishes a port")
	}
}

func TestReferenceAdmissionComposePreservesBarrierIsolation(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "itzg-paper", "compose.admission.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, required := range []string{
		`SERVER_PORT: "25566"`,
		`"127.0.0.1:25565:25565/tcp"`,
		`"[::1]:25565:25565/tcp"`,
		"network_mode: service:paper",
		"read_only: true",
		"no-new-privileges:true",
		"cap_drop:\n      - ALL",
		"./evidence/admission:${GAR_ADMISSION_DIRECTORY",
		"./data/plugins/GARGuard:${GAR_PAPER_RUNTIME_DIRECTORY",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("reference admission fixture lacks invariant %q", required)
		}
	}
	for _, forbidden := range []string{"25566:25566", "/var/run/docker.sock", "/run/docker.sock"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("reference admission fixture exposes forbidden value %q", forbidden)
		}
	}
}

func TestReferenceHostSnapshotUsesDedicatedObservationDirectory(t *testing.T) {
	for _, name := range []string{"host-enrollment.example.json", "host-observer.example.json", "server-config.example.json"} {
		payload, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "itzg-paper", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(payload), "/evidence/observation/host-observation.json") {
			t.Fatalf("%s does not isolate the atomically replaced host snapshot", name)
		}
	}
}

func makeDataRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(filepath.Join(root, "plugins"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "logs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plugins", "GARGuard.jar"), []byte("plugin artifact"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "logs", "latest.log"), []byte("[INFO] ok\n[ERROR] bounded failure\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	return root
}

func testInspection(dataRoot string) dockerInspection {
	var inspection dockerInspection
	inspection.ID = testContainerID
	inspection.Image = testImageID
	inspection.Config.Image = "itzg/minecraft-server:java25"
	inspection.Config.Env = []string{"ENABLE_AUTOPAUSE=FALSE", "ENABLE_AUTOSTOP=FALSE", "SKIP_DOWNLOAD_DEFAULTS=TRUE", "TYPE=PAPER"}
	inspection.State.Status = "running"
	inspection.State.Running = true
	inspection.State.Health = &struct {
		Status string `json:"Status"`
	}{Status: "healthy"}
	inspection.HostConfig.RestartPolicy.Name = "no"
	inspection.Mounts = []dockerMount{{Type: "bind", Source: dataRoot, Destination: "/data", RW: true}}
	return inspection
}

func testGateInspection(config AdmissionBarrierConfig, admissionConfig admission.Config) dockerInspection {
	var inspection dockerInspection
	inspection.ID = testGateContainerID
	inspection.Image = testGateImageID
	inspection.Config.Entrypoint = []string{"/gar-gate"}
	inspection.Config.Cmd = []string{"serve", "--config", config.AdmissionConfigPath}
	inspection.State.Status = "running"
	inspection.State.Running = true
	inspection.HostConfig.RestartPolicy.Name = "no"
	inspection.HostConfig.NetworkMode = "container:" + testContainerID
	inspection.HostConfig.ReadonlyRootfs = true
	inspection.HostConfig.CapDrop = []string{"ALL"}
	inspection.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	inspection.Mounts = []dockerMount{
		{Type: "bind", Source: config.GateBinaryPath, Destination: "/gar-gate", RW: false},
		{Type: "bind", Source: filepath.Dir(config.AdmissionConfigPath), Destination: filepath.Dir(config.AdmissionConfigPath), RW: false},
		{Type: "bind", Source: filepath.Dir(admissionConfig.RuntimeSnapshotPath), Destination: filepath.Dir(admissionConfig.RuntimeSnapshotPath), RW: false},
	}
	return inspection
}

func testAdmissionBarrierConfig(t *testing.T) (AdmissionBarrierConfig, admission.Config) {
	t.Helper()
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "gar-gate")
	if err := os.WriteFile(binaryPath, []byte("test gate binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	digest, err := hashGateBinary(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	admissionDirectory := filepath.Join(directory, "admission")
	runtimeDirectory := filepath.Join(directory, "runtime")
	if err := os.MkdirAll(admissionDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	barrier := AdmissionBarrierConfig{
		GateContainerID:          testGateContainerID,
		ExpectedGateImageID:      testGateImageID,
		GateBinaryPath:           binaryPath,
		ExpectedGateBinarySHA256: digest,
		AdmissionConfigPath:      filepath.Join(admissionDirectory, "config.json"),
		PublishedBindings: []PublishedBinding{
			{HostIP: "127.0.0.1", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"},
			{HostIP: "::1", HostPort: 25565, ContainerPort: 25565, Protocol: "tcp"},
		},
	}
	admissionConfig := admission.Config{
		StatePath:           filepath.Join(admissionDirectory, "state.json"),
		RuntimeSnapshotPath: filepath.Join(runtimeDirectory, "runtime-observation.json"),
	}
	return barrier, admissionConfig
}

func setPublishedBindings(inspection *dockerInspection, bindings []PublishedBinding) {
	inspection.NetworkSettings.Ports = make(map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	})
	for _, binding := range bindings {
		key := fmt.Sprintf("%d/%s", binding.ContainerPort, binding.Protocol)
		inspection.NetworkSettings.Ports[key] = append(inspection.NetworkSettings.Ports[key], struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		}{HostIP: binding.HostIP, HostPort: fmt.Sprintf("%d", binding.HostPort)})
	}
}

func serveDockerInspect(t *testing.T, inspection dockerInspection) (string, func()) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/containers/"+testContainerID+"/json" {
			http.NotFound(response, request)
			return
		}
		_ = json.NewEncoder(response).Encode(inspection)
	})}
	go func() { _ = server.Serve(listener) }()
	return socket, func() {
		_ = server.Close()
		_ = listener.Close()
	}
}
