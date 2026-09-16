package admission

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluateStateFailsClosedForMissingExpiredAndMismatchedState(t *testing.T) {
	now := time.Date(2026, 9, 16, 16, 0, 0, 0, time.UTC)
	config := testConfig(t, freeAddress(t), freeAddress(t))

	if decision := EvaluateState(config, now); decision.Open || decision.ReasonCode != "ADMISSION_STATE_MISSING" {
		t.Fatalf("missing state must close barrier, got %+v", decision)
	}
	if _, err := WriteState(config, ModeOpen, "test", 2*time.Second, now.Add(-3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if decision := EvaluateState(config, now); decision.Open || decision.ReasonCode != "ADMISSION_LEASE_EXPIRED" {
		t.Fatalf("expired lease must close barrier, got %+v", decision)
	}

	state, err := WriteState(config, ModeOpen, "test", 10*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	state.PairingID = "wrong-pairing"
	writeRawState(t, config.StatePath, state)
	if decision := EvaluateState(config, now); decision.Open || decision.ReasonCode != "ADMISSION_IDENTITY_MISMATCH" {
		t.Fatalf("mismatched state must close barrier, got %+v", decision)
	}
}

func TestEvaluateStateRejectsInvalidLeaseAndDuplicateJSON(t *testing.T) {
	now := time.Date(2026, 9, 16, 16, 0, 0, 0, time.UTC)
	config := testConfig(t, freeAddress(t), freeAddress(t))
	if _, err := WriteState(config, ModeOpen, "too long", MaxOpenLease+time.Second, now); err == nil {
		t.Fatal("expected overlong lease rejection")
	}
	payload := []byte(`{"schema_version":"gar.admission-state.v1","schema_version":"gar.admission-state.v1"}`)
	if err := os.WriteFile(config.StatePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := EvaluateState(config, now); decision.Open || decision.ReasonCode != "ADMISSION_STATE_INVALID" {
		t.Fatalf("duplicate JSON must close barrier, got %+v", decision)
	}
}

func TestConfigRequiresLiteralFixedAddressesAndLoopbackUpstream(t *testing.T) {
	config := Config{
		SchemaVersion: ConfigSchemaVersion, PairingID: "pairing", DeploymentGeneration: 1,
		ListenAddresses: []string{"localhost:25565"}, UpstreamAddress: "127.0.0.1:25566",
		StatePath: "/tmp/admission-state.json", RuntimeSnapshotPath: "/tmp/runtime-observation.json",
		PollIntervalMilliseconds: 25,
		DialTimeoutMilliseconds:  200, MaxConnections: 10,
	}
	if err := config.Validate(); err == nil {
		t.Fatal("expected hostname listener rejection")
	}
	config.ListenAddresses = []string{"0.0.0.0:25565"}
	config.UpstreamAddress = "192.0.2.10:25566"
	if err := config.Validate(); err == nil {
		t.Fatal("expected non-loopback upstream rejection")
	}
}

func TestEvaluateAccessRequiresFreshOpenRuntimeGuard(t *testing.T) {
	now := time.Date(2026, 9, 16, 16, 0, 0, 0, time.UTC)
	config := testConfig(t, freeAddress(t), freeAddress(t))
	if _, err := WriteState(config, ModeOpen, "test", 20*time.Second, now); err != nil {
		t.Fatal(err)
	}
	if decision := EvaluateAccess(config, now); decision.Open || decision.ReasonCode != "RUNTIME_GUARD_UNAVAILABLE" {
		t.Fatalf("missing runtime guard must close barrier, got %+v", decision)
	}
	writeRuntimeSnapshot(t, config, now, "MAINTENANCE")
	if decision := EvaluateAccess(config, now); decision.Open || decision.ReasonCode != "RUNTIME_GUARD_NOT_OPEN" {
		t.Fatalf("closed runtime guard must close barrier, got %+v", decision)
	}
	writeRuntimeSnapshot(t, config, now.Add(-4*time.Second), "OPEN_READ_ONLY_ALPHA")
	if decision := EvaluateAccess(config, now); decision.Open || decision.ReasonCode != "RUNTIME_GUARD_NOT_READY" {
		t.Fatalf("stale runtime guard must close barrier, got %+v", decision)
	}
	writeRuntimeSnapshot(t, config, now, "OPEN_READ_ONLY_ALPHA")
	if decision := EvaluateAccess(config, now); !decision.Open || decision.ReasonCode != "ADMISSION_OPEN_GUARD_CONFIRMED" {
		t.Fatalf("fresh paired open runtime guard should open barrier, got %+v", decision)
	}
}

func TestGateProxiesOnlyDuringValidLeaseAndDropsInflightOnClose(t *testing.T) {
	upstream := startEchoServer(t)
	listenerAddress := freeAddress(t)
	config := testConfig(t, listenerAddress, upstream.Addr().String())
	if _, err := WriteState(config, ModeOpen, "integration test", 10*time.Second, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	writeRuntimeSnapshot(t, config, time.Now().UTC(), "OPEN_READ_ONLY_ALPHA")

	gate, err := NewGate(config, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gate.Run(ctx) }()
	connection := dialEventually(t, listenerAddress)
	defer connection.Close()

	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "ping" {
		t.Fatalf("expected proxied echo, got %q err=%v", buffer, err)
	}
	if _, err := WriteState(config, ModeClosed, "maintenance", 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = connection.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("in-flight connection remained open after fail-closed transition")
	}
	if netError, ok := err.(net.Error); ok && netError.Timeout() {
		t.Fatal("barrier did not close in-flight connection before deadline")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGateRejectsConnectionWhenStateMissing(t *testing.T) {
	upstream := startEchoServer(t)
	listenerAddress := freeAddress(t)
	config := testConfig(t, listenerAddress, upstream.Addr().String())
	gate, err := NewGate(config, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gate.Run(ctx) }()
	connection := dialEventually(t, listenerAddress)
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	_, _ = connection.Write([]byte("blocked"))
	buffer := make([]byte, 7)
	_, err = io.ReadFull(connection, buffer)
	if err == nil || string(buffer) == "blocked" {
		t.Fatal("missing state unexpectedly reached upstream")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testConfig(t *testing.T, listenAddress, upstreamAddress string) Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		SchemaVersion: ConfigSchemaVersion, PairingID: "pairing-a", DeploymentGeneration: 2,
		ListenAddresses: []string{listenAddress}, UpstreamAddress: upstreamAddress,
		StatePath: filepath.Join(directory, "state.json"), PollIntervalMilliseconds: 25,
		RuntimeSnapshotPath:     filepath.Join(directory, "runtime-observation.json"),
		DialTimeoutMilliseconds: 500, MaxConnections: 16,
	}
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

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener
}

func dialEventually(t *testing.T, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			return connection
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func writeRawState(t *testing.T, path string, state State) {
	t.Helper()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeSnapshot(t *testing.T, config Config, observedAt time.Time, admissionState string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"schema_version":  paperRuntimeSchemaVersion,
		"pairing_id":      config.PairingID,
		"boot_id":         "boot-0123456789abcdef",
		"observed_at":     observedAt,
		"ready":           true,
		"admission_state": admissionState,
		"player_count":    0,
		"tps":             []float64{20, 20, 20},
		"mspt":            1.0,
		"heap_used_bytes": 1024,
		"heap_max_bytes":  2048,
		"plugins":         []any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.RuntimeSnapshotPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}
