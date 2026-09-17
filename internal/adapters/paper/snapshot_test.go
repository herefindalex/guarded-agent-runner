package paper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"guarded-agent-runner/internal/domain"
)

func testSnapshot(now time.Time) Snapshot {
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion, PairingID: "pairing-0123456789",
		BootID: "boot-0123456789abcdef", ObservedAt: now, Ready: true,
		AdmissionState: "OPEN_READ_ONLY_ALPHA", PlayerCount: 0,
		TPS: []float64{20, 19.9, 19.8}, MSPT: 12.5,
		HeapUsedBytes: 100, HeapMaxBytes: 1000,
		Plugins: []PluginObservation{{
			Name: "GARGuard", Version: "0.1.0", Enabled: true, SourceAttribution: "UNAVAILABLE",
		}},
	}
}

func writeSnapshot(t *testing.T, path string, snapshot Snapshot) {
	t.Helper()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
}

func newTarget(t *testing.T, now time.Time) (*SnapshotTarget, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime-observation.json")
	writeSnapshot(t, path, testSnapshot(now))
	target, err := NewSnapshotTarget(path, domain.Enrollment{
		EnrollmentID: "enrollment-a", DeploymentGeneration: 1,
		ContainerID: "container-a", RuntimeGuardPairing: "pairing-0123456789",
	})
	if err != nil {
		t.Fatal(err)
	}
	target.SetClockForTest(func() time.Time { return now })
	return target, path
}

func TestSnapshotTargetReturnsBoundedRuntimeEvidence(t *testing.T) {
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	target, _ := newTarget(t, now)
	players, err := target.ReadTool(context.Background(), "get_players", nil)
	if err != nil {
		t.Fatal(err)
	}
	playerResult := players.(map[string]any)
	if playerResult["availability"] != domain.Available || playerResult["player_count"] != 0 {
		t.Fatalf("unexpected player evidence: %#v", playerResult)
	}
	if _, exposed := playerResult["players"]; exposed {
		t.Fatal("runtime adapter exposed player identities")
	}
	plugins, err := target.ReadTool(context.Background(), "list_plugins", nil)
	if err != nil {
		t.Fatal(err)
	}
	pluginResult := plugins.(map[string]any)
	if pluginResult["artifact_hashes_available"] != false {
		t.Fatal("runtime-only adapter claimed artifact attribution")
	}
	bundle, err := target.Observe(context.Background(), target.enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.BootID == "" || bundle.InventoryDigest != "" || len(bundle.ActiveArtifacts) != 0 {
		t.Fatal("runtime-only bundle fabricated host artifact evidence")
	}
}

func TestSnapshotFreshnessAndPairingFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	target, path := newTarget(t, now)
	target.SetClockForTest(func() time.Time { return now.Add(6 * time.Second) })
	result, err := target.ReadTool(context.Background(), "get_health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["availability"] != domain.Stale {
		t.Fatal("old runtime snapshot was not marked STALE")
	}
	snapshot := testSnapshot(now)
	snapshot.PairingID = "different-pairing-id"
	writeSnapshot(t, path, snapshot)
	result, err = target.ReadTool(context.Background(), "get_health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["availability"] != domain.Unavailable {
		t.Fatal("pairing mismatch was not hidden behind unavailable evidence")
	}
	if _, err := target.Observe(context.Background(), target.enrollment); err == nil {
		t.Fatal("pairing mismatch produced an executable observation bundle")
	}
}

func TestSnapshotRejectsDuplicateUnknownAndSymlinkInput(t *testing.T) {
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	target, path := newTarget(t, now)
	duplicate := `{"schema_version":"gar.paper-runtime-observation.v1","schema_version":"gar.paper-runtime-observation.v1"}`
	if err := os.WriteFile(path, []byte(duplicate), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Observe(context.Background(), target.enrollment); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	snapshot := testSnapshot(now)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"unexpected":"authority"}`)...)
	if err := os.WriteFile(path, payload, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Observe(context.Background(), target.enrollment); err == nil {
		t.Fatal("unknown runtime snapshot field was accepted")
	}
	realPath := filepath.Join(filepath.Dir(path), "real.json")
	writeSnapshot(t, realPath, snapshot)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, path); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Observe(context.Background(), target.enrollment); err == nil {
		t.Fatal("symlinked runtime snapshot was accepted")
	}
}
