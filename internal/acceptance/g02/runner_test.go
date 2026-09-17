package g02

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	hostadapter "guarded-agent-runner/internal/adapters/host"
	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/runtimeconfig"
)

func TestMinecraftLoginCloseRecordsCorrelatedEvidence(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	upstream, upstreamDone := startMinecraftServer(t)
	defer upstream.Close()
	listenerAddress := freeAddress(t)
	admissionConfig := admission.Config{
		SchemaVersion: admission.ConfigSchemaVersion, PairingID: "g02-test-pairing",
		DeploymentGeneration: 7, ListenAddresses: []string{listenerAddress},
		UpstreamAddress: upstream.Addr().String(), StatePath: filepath.Join(directory, "state.json"),
		RuntimeSnapshotPath:      filepath.Join(directory, "runtime.json"),
		PollIntervalMilliseconds: 25, DialTimeoutMilliseconds: 500, MaxConnections: 16,
	}
	admissionConfigPath := filepath.Join(directory, "admission.json")
	writeJSONFile(t, admissionConfigPath, admissionConfig)
	serverConfigPath := filepath.Join(directory, "server.json")
	writeServerConfig(t, serverConfigPath, admissionConfig, "enrollment-test", "container-full-identity", "dev:1/inode:2", "paper-test/java-test/image-test")
	if _, err := admission.WriteState(admissionConfig, admission.ModeClosed, "test-start", 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	writeRuntime(t, admissionConfig, "MAINTENANCE")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate, err := admission.NewGate(admissionConfig, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	gateDone := make(chan error, 1)
	go func() { gateDone <- gate.Run(ctx) }()
	waitForListener(t, listenerAddress)

	publisherDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		defer close(publisherDone)
		for {
			decision := admission.EvaluateState(admissionConfig, time.Now().UTC())
			state := "MAINTENANCE"
			if decision.Open {
				state = "OPEN_READ_ONLY_ALPHA"
			}
			_ = writeRuntimeAtomic(admissionConfig, state)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	config := Config{
		SchemaVersion: ConfigSchemaVersion, AdmissionConfigPath: admissionConfigPath,
		ServerConfigPath: serverConfigPath,
		EvidencePath:     filepath.Join(directory, "g02-evidence.json"), MinecraftAddresses: []string{listenerAddress},
		EnrollmentID: "enrollment-test", ContainerIdentity: "container-full-identity",
		DataRootIdentity: "dev:1/inode:2", PaperTuple: "paper-test/java-test/image-test",
		ConnectionDeadlineMS: 1000, RuntimeSettleTimeoutMS: 3000,
	}
	runner, err := NewRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	runContext, stopRun := context.WithTimeout(context.Background(), 8*time.Second)
	defer stopRun()
	evidence, err := runner.MinecraftLoginClose(runContext)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.MinecraftLogins) != 1 || evidence.MinecraftLogins[0].Result != "PASS" ||
		!evidence.MinecraftLogins[0].LoginStartSent || !evidence.MinecraftLogins[0].ConnectionAliveBeforeClose ||
		evidence.MinecraftLogins[0].PlayerCountAfter != 0 {
		t.Fatalf("incomplete Minecraft login-close evidence: %+v", evidence.MinecraftLogins)
	}
	reopened, err := loadEvidence(config.EvidencePath)
	if err != nil || len(reopened.MinecraftLogins) != 1 || reopened.MinecraftLogins[0].Result != "PASS" {
		t.Fatalf("durable evidence did not reopen: %+v err=%v", reopened, err)
	}
	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake Minecraft server did not observe login connection termination")
	}
	cancel()
	if err := <-gateDone; err != nil {
		t.Fatal(err)
	}
	<-publisherDone
}

func TestHostRebootCheckpointRequiresChangedKernelBootID(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	minecraftAddress := freeAddress(t)
	admissionConfig := admission.Config{
		SchemaVersion: admission.ConfigSchemaVersion, PairingID: "g02-reboot-pairing",
		DeploymentGeneration: 3, ListenAddresses: []string{minecraftAddress},
		UpstreamAddress: "127.0.0.1:25566", StatePath: filepath.Join(directory, "state.json"),
		RuntimeSnapshotPath:      filepath.Join(directory, "runtime.json"),
		PollIntervalMilliseconds: 25, DialTimeoutMilliseconds: 200, MaxConnections: 16,
	}
	admissionConfigPath := filepath.Join(directory, "admission.json")
	writeJSONFile(t, admissionConfigPath, admissionConfig)
	serverConfigPath := filepath.Join(directory, "server.json")
	writeServerConfig(t, serverConfigPath, admissionConfig, "enrollment", "container", "root", "tuple")
	if _, err := admission.WriteState(admissionConfig, admission.ModeClosed, "test", 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	writeRuntime(t, admissionConfig, "MAINTENANCE")
	config := Config{
		SchemaVersion: ConfigSchemaVersion, AdmissionConfigPath: admissionConfigPath,
		ServerConfigPath: serverConfigPath,
		EvidencePath:     filepath.Join(directory, "evidence.json"), MinecraftAddresses: []string{minecraftAddress},
		EnrollmentID: "enrollment", ContainerIdentity: "container", DataRootIdentity: "root",
		PaperTuple: "tuple", ConnectionDeadlineMS: 250, RuntimeSettleTimeoutMS: 1000,
	}
	runner, err := NewRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	startClosedGate(t, admissionConfig)
	runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
	prepared, err := runner.PrepareHostReboot(context.Background())
	if err != nil || prepared.HostReboot == nil || prepared.HostReboot.Result != "PREPARED" {
		t.Fatalf("prepare failed: %+v err=%v", prepared.HostReboot, err)
	}
	if _, err := runner.VerifyHostReboot(context.Background()); err == nil {
		t.Fatal("unchanged boot ID must not pass host reboot evidence")
	}
	if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
		t.Fatalf("re-prepare after a premature verification failed: %v", err)
	}
	runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
	refreshHostObservation(t, runner)
	writeRuntime(t, admissionConfig, "MAINTENANCE")
	verified, err := runner.VerifyHostReboot(context.Background())
	if err != nil || verified.HostReboot.Result != "PASS" || !verified.HostReboot.EndpointClosedAfter {
		t.Fatalf("verify failed: %+v err=%v", verified.HostReboot, err)
	}
}

func TestHostRebootCheckpointRejectsReopenedAdmissionAndReachableEndpoint(t *testing.T) {
	t.Run("admission reopened", func(t *testing.T) {
		runner, admissionConfig := newNegativeRebootRunner(t)
		runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
		if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
			t.Fatal(err)
		}
		runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
		now := time.Now().UTC()
		if _, err := admission.WriteState(admissionConfig, admission.ModeOpen, "unsafe-reopen", 20*time.Second, now); err != nil {
			t.Fatal(err)
		}
		writeRuntime(t, admissionConfig, "OPEN_READ_ONLY_ALPHA")
		evidence, err := runner.VerifyHostReboot(context.Background())
		if err == nil || evidence.HostReboot.Result != "FAIL" || evidence.HostReboot.PostAdmissionReason != "ADMISSION_OPEN_GUARD_CONFIRMED" {
			t.Fatalf("reopened admission must fail reboot evidence: %+v err=%v", evidence.HostReboot, err)
		}
	})

	t.Run("endpoint reachable while state is closed", func(t *testing.T) {
		runner, _ := newNegativeRebootRunner(t)
		runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
		if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
			t.Fatal(err)
		}
		runner.probeClosedGate = func(string, time.Duration) error {
			return fmt.Errorf("closed gate returned Minecraft protocol data")
		}
		runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
		refreshHostObservation(t, runner)
		writeRuntime(t, runner.admission, "MAINTENANCE")
		evidence, err := runner.VerifyHostReboot(context.Background())
		if err == nil || evidence.HostReboot.Result != "FAIL" || evidence.HostReboot.EndpointClosedAfter {
			t.Fatalf("reachable endpoint must fail reboot evidence: %+v err=%v", evidence.HostReboot, err)
		}
	})

	t.Run("host observation missing after reboot", func(t *testing.T) {
		runner, _ := newNegativeRebootRunner(t)
		runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
		if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(runner.server.HostObservation.SnapshotPath); err != nil {
			t.Fatal(err)
		}
		runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
		evidence, err := runner.VerifyHostReboot(context.Background())
		if err == nil || evidence.HostReboot.Result != "FAIL" || evidence.HostReboot.EndpointClosedAfter {
			t.Fatalf("missing live host observation must fail reboot evidence: %+v err=%v", evidence.HostReboot, err)
		}
	})

	t.Run("host observation not refreshed after reboot", func(t *testing.T) {
		runner, _ := newNegativeRebootRunner(t)
		runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
		if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
			t.Fatal(err)
		}
		runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
		evidence, err := runner.VerifyHostReboot(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not refreshed") || evidence.HostReboot.Result != "FAIL" {
			t.Fatalf("pre-reboot host observation must not prove recovery: %+v err=%v", evidence.HostReboot, err)
		}
	})

	t.Run("Paper runtime not in maintenance after reboot", func(t *testing.T) {
		runner, admissionConfig := newNegativeRebootRunner(t)
		runner.bootID = func() (string, error) { return "boot-before-000000000000", nil }
		if _, err := runner.PrepareHostReboot(context.Background()); err != nil {
			t.Fatal(err)
		}
		refreshHostObservation(t, runner)
		writeRuntime(t, admissionConfig, "OPEN_READ_ONLY_ALPHA")
		runner.bootID = func() (string, error) { return "boot-after-0000000000000", nil }
		evidence, err := runner.VerifyHostReboot(context.Background())
		if err == nil || evidence.HostReboot.Result != "FAIL" || evidence.HostReboot.EndpointClosedAfter {
			t.Fatalf("non-maintenance runtime must fail reboot evidence: %+v err=%v", evidence.HostReboot, err)
		}
	})
}

func TestProbeClosedGateRequiresReachableGateDrivenClose(t *testing.T) {
	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closedListener.Addr().String()
	go func() {
		connection, acceptErr := closedListener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()
	if err := probeClosedGate(closedAddress, 250*time.Millisecond); err != nil {
		t.Fatalf("reachable gate-driven close rejected: %v", err)
	}
	_ = closedListener.Close()

	refusedAddress := freeAddress(t)
	if err := probeClosedGate(refusedAddress, 100*time.Millisecond); err == nil {
		t.Fatal("connection refusal must not count as gate-driven closure")
	}

	statusListener := startStatusServerAt(t, freeAddress(t))
	defer statusListener.Close()
	if err := probeClosedGate(statusListener.Addr().String(), 250*time.Millisecond); err == nil {
		t.Fatal("a reachable Minecraft status endpoint must not count as closed")
	}

	hangingListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hangingListener.Close()
	hangingDone := make(chan struct{})
	go func() {
		defer close(hangingDone)
		connection, acceptErr := hangingListener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		<-time.After(300 * time.Millisecond)
	}()
	if err := probeClosedGate(hangingListener.Addr().String(), 50*time.Millisecond); err == nil {
		t.Fatal("a hanging listener must not count as gate-driven closure")
	}
	<-hangingDone
}

func newNegativeRebootRunner(t *testing.T) (*Runner, admission.Config) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	minecraftAddress := freeAddress(t)
	admissionConfig := admission.Config{
		SchemaVersion: admission.ConfigSchemaVersion, PairingID: "g02-negative-pairing",
		DeploymentGeneration: 3, ListenAddresses: []string{minecraftAddress},
		UpstreamAddress: "127.0.0.1:25566", StatePath: filepath.Join(directory, "state.json"),
		RuntimeSnapshotPath:      filepath.Join(directory, "runtime.json"),
		PollIntervalMilliseconds: 25, DialTimeoutMilliseconds: 200, MaxConnections: 16,
	}
	admissionConfigPath := filepath.Join(directory, "admission.json")
	writeJSONFile(t, admissionConfigPath, admissionConfig)
	serverConfigPath := filepath.Join(directory, "server.json")
	writeServerConfig(t, serverConfigPath, admissionConfig, "enrollment", "container", "root", "tuple")
	if _, err := admission.WriteState(admissionConfig, admission.ModeClosed, "test", 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	writeRuntime(t, admissionConfig, "MAINTENANCE")
	config := Config{
		SchemaVersion: ConfigSchemaVersion, AdmissionConfigPath: admissionConfigPath,
		ServerConfigPath: serverConfigPath,
		EvidencePath:     filepath.Join(directory, "evidence.json"), MinecraftAddresses: []string{minecraftAddress},
		EnrollmentID: "enrollment", ContainerIdentity: "container", DataRootIdentity: "root",
		PaperTuple: "tuple", ConnectionDeadlineMS: 250, RuntimeSettleTimeoutMS: 1000,
	}
	runner, err := NewRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	startClosedGate(t, admissionConfig)
	return runner, admissionConfig
}

func startStatusServerAt(t *testing.T, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		if _, _, readErr := readPacket(reader); readErr != nil {
			return
		}
		if _, _, readErr := readPacket(reader); readErr != nil {
			return
		}
		status := `{"version":{"name":"Paper 26.2","protocol":776},"players":{"max":20,"online":0}}`
		_ = writePacket(connection, 0, appendString(nil, status))
	}()
	return listener
}

func startMinecraftServer(t *testing.T) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for connectionNumber := 0; connectionNumber < 2; connectionNumber++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				done <- acceptErr
				return
			}
			reader := bufio.NewReader(connection)
			packetID, handshake, readErr := readPacket(reader)
			if readErr != nil || packetID != 0 {
				connection.Close()
				done <- readErr
				return
			}
			_, remaining, readErr := consumeVarInt(handshake)
			if readErr != nil {
				connection.Close()
				done <- readErr
				return
			}
			_, remaining, readErr = consumeString(remaining)
			if readErr != nil || len(remaining) < 3 {
				connection.Close()
				done <- readErr
				return
			}
			remaining = remaining[2:]
			nextState, _, readErr := consumeVarInt(remaining)
			if readErr != nil {
				connection.Close()
				done <- readErr
				return
			}
			if connectionNumber == 0 && nextState == 1 {
				_, _, _ = readPacket(reader)
				status := `{"version":{"name":"Paper 26.2","protocol":774},"players":{"max":20,"online":0}}`
				_ = writePacket(connection, 0, appendString(nil, status))
				connection.Close()
				continue
			}
			if connectionNumber != 1 || nextState != 2 {
				connection.Close()
				done <- io.ErrUnexpectedEOF
				return
			}
			if _, _, readErr = readPacket(reader); readErr != nil {
				connection.Close()
				done <- readErr
				return
			}
			_, readErr = io.Copy(io.Discard, reader)
			connection.Close()
			done <- readErr
			return
		}
	}()
	return listener, done
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", address, 25*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startClosedGate(t *testing.T, config admission.Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	gate, err := admission.NewGate(config, io.Discard)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { _ = gate.Run(ctx) }()
	for _, address := range config.ListenAddresses {
		waitForListener(t, address)
	}
	t.Cleanup(cancel)
}

func refreshHostObservation(t *testing.T, runner *Runner) {
	t.Helper()
	path := runner.server.HostObservation.SnapshotPath
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot hostadapter.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.ObservedAt = time.Now().UTC()
	writeJSONFile(t, path, snapshot)
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeServerConfig(
	t *testing.T,
	path string,
	admissionConfig admission.Config,
	enrollmentID, containerIdentity, dataRootIdentity, paperTuple string,
) {
	t.Helper()
	publishedBindings := make([]hostadapter.PublishedBinding, 0, len(admissionConfig.ListenAddresses))
	for _, address := range admissionConfig.ListenAddresses {
		hostIP, portText, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			t.Fatal(err)
		}
		publishedBindings = append(publishedBindings, hostadapter.PublishedBinding{
			HostIP: hostIP, HostPort: port, ContainerPort: port, Protocol: "tcp",
		})
	}
	hostSnapshotPath := filepath.Join(filepath.Dir(path), "host-observation.json")
	config := runtimeconfig.Config{
		SchemaVersion: runtimeconfig.SchemaVersion,
		Enrollment: domain.Enrollment{
			TargetID: "target", EnrollmentID: enrollmentID,
			DeploymentGeneration: admissionConfig.DeploymentGeneration,
			ContainerID:          containerIdentity, ImageDigest: "test-image", DataRootIdentity: dataRootIdentity,
			RuntimeGuardPairing: admissionConfig.PairingID, SupportProfileID: "read-only-test",
			PaperTuple: paperTuple, BootstrapFingerprint: strings.Repeat("0", 64),
			AllowedPlugins: []string{"gar-guard"},
		},
		Artifacts: map[string]domain.ArtifactRecord{}, Profiles: map[string]domain.TransitionProfile{},
		Support:                policy.SupportProfile{ProfileID: "read-only-test", Mode: policy.ModeReadOnly},
		CurrentRevocationEpoch: 1,
		PaperRuntime:           &runtimeconfig.PaperRuntimeSource{SnapshotPath: admissionConfig.RuntimeSnapshotPath},
		HostObservation:        &runtimeconfig.HostObservationSource{SnapshotPath: hostSnapshotPath},
	}
	writeJSONFile(t, hostSnapshotPath, hostadapter.Snapshot{
		SchemaVersion: hostadapter.SnapshotSchemaVersion, Availability: domain.Available,
		ObservedAt: time.Now().UTC(), EnrollmentID: enrollmentID,
		DeploymentGeneration: admissionConfig.DeploymentGeneration, ContainerID: containerIdentity,
		ImageID: "test-image", ContainerStatus: "running", Running: true, HealthStatus: "healthy",
		RestartPolicy: "no", DataRootIdentity: dataRootIdentity,
		BootstrapFingerprint: strings.Repeat("0", 64), InventoryDigest: strings.Repeat("1", 64),
		PluginArtifacts: []hostadapter.PluginArtifact{}, CompetingStartupWriters: []string{}, DiskFreeBytes: 1,
		RecentErrorsAvailability: domain.Unavailable, RecentErrorsReasonCode: "PAPER_LOG_UNAVAILABLE",
		RecentErrors: []string{}, AdmissionBarrierAvailability: domain.Available,
		AdmissionBarrierReasonCode: "ADMISSION_CLOSED", AdmissionOpen: false,
		AdmissionGateContainerID: strings.Repeat("2", 64), AdmissionPublishedBindings: publishedBindings,
	})
	writeJSONFile(t, path, config)
}

func writeRuntime(t *testing.T, config admission.Config, state string) {
	t.Helper()
	if err := writeRuntimeAtomic(config, state); err != nil {
		t.Fatal(err)
	}
}

var runtimeWriteMu sync.Mutex

func writeRuntimeAtomic(config admission.Config, state string) error {
	runtimeWriteMu.Lock()
	defer runtimeWriteMu.Unlock()
	payload, err := json.Marshal(map[string]any{
		"schema_version": "gar.paper-runtime-observation.v1", "pairing_id": config.PairingID,
		"boot_id": "paper-boot-00000001", "observed_at": time.Now().UTC(), "ready": true,
		"admission_state": state, "player_count": 0, "tps": []float64{20, 20, 20},
		"mspt": 1.0, "heap_used_bytes": 1024, "heap_max_bytes": 2048, "plugins": []any{},
	})
	if err != nil {
		return err
	}
	temporary := config.RuntimeSnapshotPath + ".tmp"
	if err := os.WriteFile(temporary, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, config.RuntimeSnapshotPath)
}
