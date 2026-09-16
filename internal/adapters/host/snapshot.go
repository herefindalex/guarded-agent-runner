// Package host contains the fixed-target, host-side observation contract. The
// GAR frontend reads its snapshot and never receives a Docker socket or host
// filesystem path.
package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/strictjson"
)

const SnapshotSchemaVersion = "gar.host-observation.v1"
const maxSnapshotBytes = 256 * 1024
const defaultFreshness = 5 * time.Second

type PluginArtifact struct {
	PluginID string `json:"plugin_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

type Snapshot struct {
	SchemaVersion                string              `json:"schema_version"`
	Availability                 domain.Availability `json:"availability"`
	ReasonCode                   string              `json:"reason_code,omitempty"`
	ObservedAt                   time.Time           `json:"observed_at"`
	EnrollmentID                 string              `json:"enrollment_id"`
	DeploymentGeneration         int64               `json:"deployment_generation"`
	ContainerID                  string              `json:"container_id"`
	ImageID                      string              `json:"image_id"`
	ContainerStatus              string              `json:"container_status"`
	Running                      bool                `json:"running"`
	HealthStatus                 string              `json:"health_status"`
	RestartPolicy                string              `json:"restart_policy"`
	DataRootIdentity             string              `json:"data_root_identity"`
	BootstrapFingerprint         string              `json:"bootstrap_fingerprint"`
	InventoryDigest              string              `json:"inventory_digest"`
	PluginArtifacts              []PluginArtifact    `json:"plugin_artifacts"`
	CompetingStartupWriters      []string            `json:"competing_startup_writers"`
	DiskFreeBytes                uint64              `json:"disk_free_bytes"`
	RecentErrorsAvailability     domain.Availability `json:"recent_errors_availability"`
	RecentErrorsReasonCode       string              `json:"recent_errors_reason_code,omitempty"`
	ErrorCursor                  string              `json:"error_cursor,omitempty"`
	RecentErrors                 []string            `json:"recent_errors"`
	AdmissionBarrierAvailability domain.Availability `json:"admission_barrier_availability"`
	AdmissionBarrierReasonCode   string              `json:"admission_barrier_reason_code"`
	AdmissionOpen                bool                `json:"admission_open"`
	AdmissionGateContainerID     string              `json:"admission_gate_container_id,omitempty"`
	AdmissionPublishedBindings   []PublishedBinding  `json:"admission_published_bindings"`
}

type SnapshotTarget struct {
	path       string
	enrollment domain.Enrollment
	registered map[string]string
	now        func() time.Time
}

func NewSnapshotTarget(path string, enrollment domain.Enrollment, artifacts map[string]domain.ArtifactRecord) (*SnapshotTarget, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("host snapshot path must be a clean absolute path")
	}
	registered := make(map[string]string, len(artifacts))
	for artifactID, artifact := range artifacts {
		key := artifact.PluginID + "\x00" + artifact.SHA256
		if existing, exists := registered[key]; exists && existing != artifactID {
			return nil, fmt.Errorf("artifact registry ambiguously maps one plugin SHA-256")
		}
		registered[key] = artifactID
	}
	return &SnapshotTarget{path: path, enrollment: enrollment, registered: registered, now: time.Now}, nil
}

func (target *SnapshotTarget) SetClockForTest(now func() time.Time) { target.now = now }

func (target *SnapshotTarget) Observe(_ context.Context, enrollment domain.Enrollment) (domain.ObservationBundle, error) {
	snapshot, digest, err := target.read()
	if err != nil {
		return domain.ObservationBundle{}, err
	}
	if snapshot.Availability != domain.Available {
		return domain.ObservationBundle{}, fmt.Errorf("host observation unavailable: %s", snapshot.ReasonCode)
	}
	if enrollment.EnrollmentID != snapshot.EnrollmentID ||
		enrollment.DeploymentGeneration != snapshot.DeploymentGeneration {
		return domain.ObservationBundle{}, fmt.Errorf("host observation enrollment identity mismatch")
	}
	activeArtifacts := make(map[string]string, len(snapshot.PluginArtifacts))
	for _, observed := range snapshot.PluginArtifacts {
		artifactID := "unregistered_sha256:" + observed.SHA256
		if registered, exists := target.registered[observed.PluginID+"\x00"+observed.SHA256]; exists {
			artifactID = registered
		}
		activeArtifacts[observed.PluginID] = artifactID
	}
	return domain.ObservationBundle{
		BundleID:             "host_" + digest,
		EnrollmentID:         snapshot.EnrollmentID,
		DeploymentGeneration: snapshot.DeploymentGeneration,
		ContainerID:          snapshot.ContainerID,
		InventoryDigest:      snapshot.InventoryDigest,
		ConfigDigest:         snapshot.BootstrapFingerprint,
		ActiveArtifacts:      activeArtifacts,
		CreatedAt:            snapshot.ObservedAt,
		Readings: map[string]domain.ObservationValue{
			"process": {
				Availability: domain.Available, Value: snapshot.ContainerStatus,
				Source: "gar-host", ObservedAt: snapshot.ObservedAt,
			},
		},
	}, nil
}

func (target *SnapshotTarget) ReadTool(_ context.Context, name string, arguments map[string]any) (any, error) {
	snapshot, digest, err := target.read()
	if err != nil {
		return unavailable(name, "HOST_SNAPSHOT_UNAVAILABLE", target.now().UTC()), nil
	}
	base := map[string]any{
		"availability": snapshot.Availability, "reason_code": snapshot.ReasonCode,
		"source": "gar-host", "observed_at": snapshot.ObservedAt,
		"evidence_id": "host_" + digest,
	}
	switch name {
	case "get_health":
		base["container_status"] = snapshot.ContainerStatus
		base["running"] = snapshot.Running
		base["health_status"] = snapshot.HealthStatus
		base["restart_policy"] = snapshot.RestartPolicy
		base["competing_startup_writers"] = snapshot.CompetingStartupWriters
		base["admission_barrier"] = map[string]any{
			"availability":       snapshot.AdmissionBarrierAvailability,
			"reason_code":        snapshot.AdmissionBarrierReasonCode,
			"open":               snapshot.AdmissionOpen,
			"gate_container_id":  snapshot.AdmissionGateContainerID,
			"published_bindings": snapshot.AdmissionPublishedBindings,
		}
		return base, nil
	case "get_performance":
		base["disk_free"] = map[string]any{
			"availability": snapshot.Availability, "value": snapshot.DiskFreeBytes, "unit": "bytes",
		}
		base["container_cpu"] = unavailableMetric("DOCKER_STATS_NOT_IMPLEMENTED")
		base["container_memory"] = unavailableMetric("DOCKER_STATS_NOT_IMPLEMENTED")
		return base, nil
	case "list_plugins":
		plugins := make([]map[string]any, 0, len(snapshot.PluginArtifacts))
		for _, plugin := range snapshot.PluginArtifacts {
			plugins = append(plugins, map[string]any{
				"plugin_id": plugin.PluginID, "sha256": plugin.SHA256, "size": plugin.Size,
			})
		}
		base["plugin_artifacts"] = plugins
		return base, nil
	case "get_recent_errors":
		base["availability"] = snapshot.RecentErrorsAvailability
		base["reason_code"] = snapshot.RecentErrorsReasonCode
		limit := 50
		if raw, ok := arguments["limit"].(int); ok {
			limit = raw
		}
		if limit > len(snapshot.RecentErrors) {
			limit = len(snapshot.RecentErrors)
		}
		base["errors"] = append([]string(nil), snapshot.RecentErrors[len(snapshot.RecentErrors)-limit:]...)
		base["untrusted"] = true
		base["next_cursor"] = snapshot.ErrorCursor
		if cursor, ok := arguments["cursor"].(string); ok && cursor != "" && cursor != snapshot.ErrorCursor {
			base["cursor_reset"] = true
		}
		return base, nil
	case "get_recent_changes":
		return unavailable(name, "HOST_CHANGE_JOURNAL_NOT_IMPLEMENTED", target.now().UTC()), nil
	case "get_backup_status":
		return unavailable(name, "HOST_BACKUP_ADAPTER_NOT_IMPLEMENTED", target.now().UTC()), nil
	case "get_players":
		return unavailable(name, "PAPER_RUNTIME_REQUIRED", target.now().UTC()), nil
	default:
		return nil, domain.NewError(domain.ErrInvalidRequest, "unsupported host read tool")
	}
}

func (target *SnapshotTarget) read() (Snapshot, string, error) {
	payload, err := readNoFollow(target.path)
	if err != nil {
		return Snapshot{}, "", err
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Snapshot{}, "", fmt.Errorf("invalid host snapshot JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, "", fmt.Errorf("decode host snapshot: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Snapshot{}, "", fmt.Errorf("host snapshot contains trailing JSON")
	}
	if err := validateSnapshot(snapshot, target.enrollment, target.now().UTC()); err != nil {
		return Snapshot{}, "", err
	}
	digest := sha256.Sum256(payload)
	return snapshot, hex.EncodeToString(digest[:]), nil
}

func validateSnapshot(snapshot Snapshot, enrollment domain.Enrollment, now time.Time) error {
	if snapshot.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported host snapshot schema")
	}
	if snapshot.Availability != domain.Available && snapshot.Availability != domain.Unavailable {
		return fmt.Errorf("host snapshot availability is invalid")
	}
	if snapshot.ObservedAt.IsZero() || snapshot.ObservedAt.After(now.Add(2*time.Second)) ||
		now.Sub(snapshot.ObservedAt) > defaultFreshness {
		return fmt.Errorf("host snapshot is stale or has an invalid timestamp")
	}
	if snapshot.EnrollmentID != enrollment.EnrollmentID ||
		snapshot.DeploymentGeneration != enrollment.DeploymentGeneration {
		return fmt.Errorf("host snapshot enrollment identity mismatch")
	}
	if snapshot.Availability != domain.Available {
		if !knownUnavailableReason(snapshot.ReasonCode) {
			return fmt.Errorf("unavailable host snapshot requires a known reason code")
		}
		return nil
	}
	if snapshot.ContainerID != enrollment.ContainerID || snapshot.ImageID != enrollment.ImageDigest ||
		snapshot.DataRootIdentity != enrollment.DataRootIdentity {
		return fmt.Errorf("host snapshot fixed target identity mismatch")
	}
	if snapshot.BootstrapFingerprint != enrollment.BootstrapFingerprint {
		return fmt.Errorf("host snapshot bootstrap fingerprint mismatch")
	}
	if snapshot.RestartPolicy != "no" {
		return fmt.Errorf("host snapshot restart policy is not 'no'")
	}
	if !snapshot.Running || snapshot.ContainerStatus != "running" {
		return fmt.Errorf("host snapshot container is not running")
	}
	if snapshot.HealthStatus == "unhealthy" {
		return fmt.Errorf("host snapshot container is unhealthy")
	}
	if len(snapshot.CompetingStartupWriters) != 0 {
		return fmt.Errorf("host snapshot reports competing startup writers")
	}
	if snapshot.AdmissionBarrierAvailability != domain.Available &&
		snapshot.AdmissionBarrierAvailability != domain.Unavailable {
		return fmt.Errorf("host admission barrier availability is invalid")
	}
	if snapshot.AdmissionBarrierAvailability == domain.Available {
		if len(snapshot.AdmissionGateContainerID) != 64 || snapshot.AdmissionBarrierReasonCode == "" ||
			len(snapshot.AdmissionPublishedBindings) < 1 {
			return fmt.Errorf("available admission barrier evidence is incomplete")
		}
	} else if snapshot.AdmissionBarrierReasonCode != "ADMISSION_BARRIER_NOT_CONFIGURED" {
		return fmt.Errorf("unavailable admission barrier evidence lacks a stable reason")
	}
	if len(snapshot.PluginArtifacts) > 512 || len(snapshot.RecentErrors) > 200 {
		return fmt.Errorf("host snapshot evidence exceeds bounded collections")
	}
	if snapshot.RecentErrorsAvailability != domain.Available && snapshot.RecentErrorsAvailability != domain.Unavailable {
		return fmt.Errorf("host recent-error availability is invalid")
	}
	if snapshot.RecentErrorsAvailability == domain.Available {
		if !validSnapshotDigest(snapshot.ErrorCursor) || snapshot.RecentErrorsReasonCode != "" {
			return fmt.Errorf("available host recent-error evidence is malformed")
		}
	} else if snapshot.RecentErrorsReasonCode != "PAPER_LOG_UNAVAILABLE" &&
		snapshot.RecentErrorsReasonCode != "PAPER_LOG_IDENTITY_UNAVAILABLE" {
		return fmt.Errorf("unavailable host recent-error evidence lacks a stable reason")
	}
	seen := make(map[string]struct{}, len(snapshot.PluginArtifacts))
	for _, plugin := range snapshot.PluginArtifacts {
		decoded, err := hex.DecodeString(plugin.SHA256)
		if plugin.PluginID == "" || len(plugin.PluginID) > 128 || err != nil || len(decoded) != sha256.Size ||
			plugin.SHA256 != strings.ToLower(plugin.SHA256) || plugin.Size < 1 || plugin.Size > 100<<20 {
			return fmt.Errorf("host plugin artifact evidence is invalid")
		}
		if _, exists := seen[plugin.PluginID]; exists {
			return fmt.Errorf("host plugin artifact IDs conflict")
		}
		seen[plugin.PluginID] = struct{}{}
	}
	return nil
}

func knownUnavailableReason(reason string) bool {
	switch reason {
	case "DOCKER_INSPECT_UNAVAILABLE", "CONTAINER_ID_MISMATCH", "CONTAINER_NOT_RUNNING",
		"CONTAINER_UNHEALTHY", "RESTART_POLICY_MISMATCH", "DATA_ROOT_UNAVAILABLE",
		"BOOTSTRAP_FINGERPRINT_UNAVAILABLE", "COMPETING_STARTUP_WRITERS", "IMAGE_ID_MISMATCH",
		"DATA_ROOT_IDENTITY_MISMATCH", "BOOTSTRAP_FINGERPRINT_MISMATCH", "DATA_MOUNT_MISMATCH",
		"PLUGIN_ATTRIBUTION_UNAVAILABLE", "INVENTORY_DIGEST_UNAVAILABLE", "DISK_OBSERVATION_UNAVAILABLE",
		"ADMISSION_BARRIER_UNAVAILABLE":
		return true
	default:
		return false
	}
}

func validSnapshotDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func readNoFollow(path string) ([]byte, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, fmt.Errorf("host snapshot path is unavailable or traverses a symlink")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxSnapshotBytes {
		return nil, fmt.Errorf("host snapshot must be a bounded regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil || len(payload) > maxSnapshotBytes {
		return nil, fmt.Errorf("read bounded host snapshot failed")
	}
	return payload, nil
}

func unavailable(tool, reason string, observedAt time.Time) map[string]any {
	return map[string]any{
		"availability": domain.Unavailable, "reason_code": reason,
		"source": "gar-host", "observed_at": observedAt, "tool": tool,
	}
}

func unavailableMetric(reason string) map[string]any {
	return map[string]any{"availability": domain.Unavailable, "reason_code": reason}
}
