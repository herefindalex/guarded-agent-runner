// Package paper implements the read-only half of the Paper runtime adapter.
// It consumes bounded atomic snapshots emitted by GARGuard. Container/process,
// filesystem attribution, backup, and mutation remain separate host concerns.
package paper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/strictjson"
)

const SnapshotSchemaVersion = "gar.paper-runtime-observation.v1"
const maxSnapshotBytes = 256 * 1024
const defaultFreshness = 5 * time.Second

type Snapshot struct {
	SchemaVersion  string              `json:"schema_version"`
	PairingID      string              `json:"pairing_id"`
	BootID         string              `json:"boot_id"`
	ObservedAt     time.Time           `json:"observed_at"`
	Ready          bool                `json:"ready"`
	AdmissionState string              `json:"admission_state"`
	PlayerCount    int                 `json:"player_count"`
	TPS            []float64           `json:"tps"`
	MSPT           float64             `json:"mspt"`
	HeapUsedBytes  int64               `json:"heap_used_bytes"`
	HeapMaxBytes   int64               `json:"heap_max_bytes"`
	Plugins        []PluginObservation `json:"plugins"`
}

type PluginObservation struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	Enabled           bool   `json:"enabled"`
	SourceAttribution string `json:"source_attribution"`
}

type SnapshotTarget struct {
	path       string
	enrollment domain.Enrollment
	now        func() time.Time
}

func NewSnapshotTarget(path string, enrollment domain.Enrollment) (*SnapshotTarget, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("Paper runtime snapshot path must be a clean absolute path")
	}
	if enrollment.RuntimeGuardPairing == "" {
		return nil, fmt.Errorf("enrollment runtime_guard_pairing is required")
	}
	return &SnapshotTarget{path: path, enrollment: enrollment, now: time.Now}, nil
}

func (target *SnapshotTarget) SetClockForTest(now func() time.Time) { target.now = now }

// ReadSnapshot returns the strictly decoded runtime snapshot together with its
// content digest and freshness classification. Owner-side lifecycle adapters
// use this to correlate the last terminal GARGuard publication with a fixed
// container stop. Agent-facing callers continue to use Observe/ReadTool.
func (target *SnapshotTarget) ReadSnapshot() (Snapshot, string, domain.Availability, error) {
	return target.read()
}

func (target *SnapshotTarget) Observe(_ context.Context, enrollment domain.Enrollment) (domain.ObservationBundle, error) {
	if enrollment.EnrollmentID != target.enrollment.EnrollmentID ||
		enrollment.DeploymentGeneration != target.enrollment.DeploymentGeneration {
		return domain.ObservationBundle{}, fmt.Errorf("requested enrollment does not match runtime adapter")
	}
	snapshot, digest, quality, err := target.read()
	if err != nil {
		return domain.ObservationBundle{}, err
	}
	return domain.ObservationBundle{
		BundleID:             "runtime_" + digest,
		EnrollmentID:         enrollment.EnrollmentID,
		DeploymentGeneration: enrollment.DeploymentGeneration,
		ContainerID:          enrollment.ContainerID,
		BootID:               snapshot.BootID,
		CreatedAt:            snapshot.ObservedAt,
		ActiveArtifacts:      map[string]string{},
		Readings: map[string]domain.ObservationValue{
			"players": {
				Availability: quality, Value: snapshot.PlayerCount, Unit: "count",
				Source: "paper-guard", ObservedAt: snapshot.ObservedAt, BootID: snapshot.BootID,
			},
			"guard_ready": {
				Availability: quality, Value: snapshot.Ready,
				Source: "paper-guard", ObservedAt: snapshot.ObservedAt, BootID: snapshot.BootID,
			},
		},
	}, nil
}

func (target *SnapshotTarget) ReadTool(_ context.Context, name string, _ map[string]any) (any, error) {
	snapshot, digest, quality, err := target.read()
	if err != nil {
		return unavailable(name, "PAPER_SNAPSHOT_UNAVAILABLE", target.now().UTC()), nil
	}
	base := map[string]any{
		"availability": quality,
		"source":       "paper-guard",
		"observed_at":  snapshot.ObservedAt,
		"boot_id":      snapshot.BootID,
		"evidence_id":  "runtime_" + digest,
	}
	switch name {
	case "get_health":
		base["runtime_ready"] = snapshot.Ready
		base["admission_state"] = snapshot.AdmissionState
		base["process"] = map[string]any{
			"availability": domain.Unavailable,
			"reason_code":  "HOST_OBSERVER_REQUIRED",
		}
		return base, nil
	case "get_players":
		base["player_count"] = snapshot.PlayerCount
		base["unit"] = "count"
		return base, nil
	case "get_performance":
		base["tps"] = observationMetric(quality, snapshot.TPS, "ticks_per_second")
		base["mspt"] = observationMetric(quality, snapshot.MSPT, "milliseconds")
		base["heap_used_bytes"] = observationMetric(quality, snapshot.HeapUsedBytes, "bytes")
		base["heap_max_bytes"] = observationMetric(quality, snapshot.HeapMaxBytes, "bytes")
		base["host_cpu"] = unavailableMetric("HOST_OBSERVER_REQUIRED")
		base["host_disk"] = unavailableMetric("HOST_OBSERVER_REQUIRED")
		return base, nil
	case "list_plugins":
		plugins := make([]map[string]any, 0, len(snapshot.Plugins))
		for _, plugin := range snapshot.Plugins {
			plugins = append(plugins, map[string]any{
				"name": plugin.Name, "version": plugin.Version, "enabled": plugin.Enabled,
				"source_attribution": plugin.SourceAttribution,
			})
		}
		base["plugins"] = plugins
		base["artifact_hashes_available"] = false
		return base, nil
	case "get_recent_errors":
		return unavailable(name, "PAPER_LOGS_NOT_OBSERVED", target.now().UTC()), nil
	case "get_recent_changes":
		return map[string]any{
			"availability": domain.Unavailable, "changes": []any{},
			"reason_code": "HOST_CHANGE_JOURNAL_NOT_IMPLEMENTED",
			"source":      "gar", "observed_at": target.now().UTC(),
		}, nil
	case "get_backup_status":
		return unavailable(name, "HOST_BACKUP_ADAPTER_NOT_IMPLEMENTED", target.now().UTC()), nil
	default:
		return nil, domain.NewError(domain.ErrInvalidRequest, "unsupported Paper read tool")
	}
}

func (target *SnapshotTarget) read() (Snapshot, string, domain.Availability, error) {
	payload, err := readNoFollow(target.path)
	if err != nil {
		return Snapshot{}, "", domain.Unavailable, err
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Snapshot{}, "", domain.Conflicting, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, "", domain.Conflicting, fmt.Errorf("decode Paper runtime snapshot: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Snapshot{}, "", domain.Conflicting, fmt.Errorf("Paper runtime snapshot contains trailing JSON")
	}
	if err := validateSnapshot(snapshot, target.enrollment.RuntimeGuardPairing, target.now().UTC()); err != nil {
		return Snapshot{}, "", domain.Conflicting, err
	}
	quality := domain.Available
	if target.now().UTC().Sub(snapshot.ObservedAt) > defaultFreshness {
		quality = domain.Stale
	}
	digest := sha256.Sum256(payload)
	return snapshot, hex.EncodeToString(digest[:]), quality, nil
}

func readNoFollow(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("Paper runtime snapshot unavailable: %w", err)
	}
	if resolved != path {
		return nil, fmt.Errorf("Paper runtime snapshot path traverses a symlink")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open Paper runtime snapshot: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Paper runtime snapshot must be a regular file")
	}
	if info.Size() < 1 || info.Size() > maxSnapshotBytes {
		return nil, fmt.Errorf("Paper runtime snapshot size is outside 1..256 KiB")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded Paper runtime snapshot: %w", err)
	}
	if len(payload) > maxSnapshotBytes {
		return nil, fmt.Errorf("Paper runtime snapshot exceeds 256 KiB")
	}
	return payload, nil
}

func validateSnapshot(snapshot Snapshot, expectedPairing string, now time.Time) error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported Paper runtime snapshot schema")
	}
	if snapshot.PairingID != expectedPairing {
		return fmt.Errorf("Paper runtime guard pairing mismatch")
	}
	if len(snapshot.BootID) < 16 || len(snapshot.BootID) > 128 {
		return fmt.Errorf("Paper runtime boot ID is invalid")
	}
	if snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.After(now.Add(2*time.Second)) {
		return fmt.Errorf("Paper runtime observation timestamp is invalid")
	}
	if snapshot.AdmissionState != "OPEN_READ_ONLY_ALPHA" && snapshot.AdmissionState != "MAINTENANCE" {
		return fmt.Errorf("Paper runtime admission state is unknown")
	}
	if snapshot.PlayerCount < 0 || snapshot.PlayerCount > 200_000 {
		return fmt.Errorf("Paper runtime player count is outside bounds")
	}
	if len(snapshot.TPS) != 3 {
		return fmt.Errorf("Paper runtime TPS must contain 1m, 5m, and 15m values")
	}
	for _, value := range snapshot.TPS {
		if !finiteBetween(value, 0, 100) {
			return fmt.Errorf("Paper runtime TPS is outside bounds")
		}
	}
	if !finiteBetween(snapshot.MSPT, 0, 60_000) {
		return fmt.Errorf("Paper runtime MSPT is outside bounds")
	}
	if snapshot.HeapUsedBytes < 0 || snapshot.HeapMaxBytes < 1 || snapshot.HeapUsedBytes > snapshot.HeapMaxBytes {
		return fmt.Errorf("Paper runtime heap observation is invalid")
	}
	if len(snapshot.Plugins) > 512 {
		return fmt.Errorf("Paper runtime plugin inventory exceeds 512 entries")
	}
	seen := make(map[string]struct{}, len(snapshot.Plugins))
	for _, plugin := range snapshot.Plugins {
		if plugin.Name == "" || len(plugin.Name) > 128 || len(plugin.Version) > 128 ||
			plugin.SourceAttribution != "UNAVAILABLE" {
			return fmt.Errorf("Paper runtime plugin observation is invalid")
		}
		key := strings.ToLower(plugin.Name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("Paper runtime plugin names conflict")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func finiteBetween(value, minimum, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= minimum && value <= maximum
}

func unavailable(tool, reason string, observedAt time.Time) map[string]any {
	return map[string]any{
		"availability": domain.Unavailable, "source": "paper-guard",
		"observed_at": observedAt, "reason_code": reason, "tool": tool,
	}
}

func observationMetric(quality domain.Availability, value any, unit string) map[string]any {
	return map[string]any{"availability": quality, "value": value, "unit": unit}
}

func unavailableMetric(reason string) map[string]any {
	return map[string]any{"availability": domain.Unavailable, "reason_code": reason}
}
