package g02

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
		EvidencePath:     filepath.Join(directory, "g02-evidence.json"), MinecraftAddress: listenerAddress,
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
	if evidence.MinecraftLogin == nil || evidence.MinecraftLogin.Result != "PASS" ||
		!evidence.MinecraftLogin.LoginStartSent || !evidence.MinecraftLogin.ConnectionAliveBeforeClose ||
		evidence.MinecraftLogin.PlayerCountAfter != 0 {
		t.Fatalf("incomplete Minecraft login-close evidence: %+v", evidence.MinecraftLogin)
	}
	reopened, err := loadEvidence(config.EvidencePath)
	if err != nil || reopened.MinecraftLogin == nil || reopened.MinecraftLogin.Result != "PASS" {
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
		EvidencePath:     filepath.Join(directory, "evidence.json"), MinecraftAddress: minecraftAddress,
		EnrollmentID: "enrollment", ContainerIdentity: "container", DataRootIdentity: "root",
		PaperTuple: "tuple", ConnectionDeadlineMS: 250, RuntimeSettleTimeoutMS: 1000,
	}
	runner, err := NewRunner(config)
	if err != nil {
		t.Fatal(err)
	}
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
	verified, err := runner.VerifyHostReboot(context.Background())
	if err != nil || verified.HostReboot.Result != "PASS" || !verified.HostReboot.EndpointClosedAfter {
		t.Fatalf("verify failed: %+v err=%v", verified.HostReboot, err)
	}
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
	config := runtimeconfig.Config{
		SchemaVersion: runtimeconfig.SchemaVersion,
		Enrollment: domain.Enrollment{
			TargetID: "target", EnrollmentID: enrollmentID,
			DeploymentGeneration: admissionConfig.DeploymentGeneration,
			ContainerID:          containerIdentity, DataRootIdentity: dataRootIdentity,
			RuntimeGuardPairing: admissionConfig.PairingID, SupportProfileID: "read-only-test",
			PaperTuple: paperTuple, AllowedPlugins: []string{"gar-guard"},
		},
		Artifacts: map[string]domain.ArtifactRecord{}, Profiles: map[string]domain.TransitionProfile{},
		Support:                policy.SupportProfile{ProfileID: "read-only-test", Mode: policy.ModeReadOnly},
		CurrentRevocationEpoch: 1,
	}
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
