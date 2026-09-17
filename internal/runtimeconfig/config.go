// Package runtimeconfig loads the owner-controlled, fixed GAR enrollment and
// registry used by the MCP frontend. Agent calls can reference IDs in this
// registry but cannot supply paths, URLs, container IDs, or policy.
package runtimeconfig

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/strictjson"
	"guarded-agent-runner/internal/workflow"
)

const SchemaVersion = "gar.server-config.v1"

type Config struct {
	SchemaVersion          string                              `json:"schema_version"`
	Enrollment             domain.Enrollment                   `json:"enrollment"`
	Artifacts              map[string]domain.ArtifactRecord    `json:"artifacts"`
	Profiles               map[string]domain.TransitionProfile `json:"profiles"`
	Support                policy.SupportProfile               `json:"support_profile"`
	CurrentRevocationEpoch int64                               `json:"current_revocation_epoch"`
	PaperRuntime           *PaperRuntimeSource                 `json:"paper_runtime,omitempty"`
	HostObservation        *HostObservationSource              `json:"host_observation,omitempty"`
}

type PaperRuntimeSource struct {
	SnapshotPath string `json:"snapshot_path"`
}

type HostObservationSource struct {
	SnapshotPath string `json:"snapshot_path"`
}

func Load(path string) (Config, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return Config{}, fmt.Errorf("runtime config security check: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(payload) > 1<<20 {
		return Config{}, fmt.Errorf("runtime config exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Config{}, fmt.Errorf("decode runtime config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode runtime config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, fmt.Errorf("runtime config contains trailing JSON")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported runtime config schema %q", config.SchemaVersion)
	}
	if config.Enrollment.EnrollmentID == "" || config.Enrollment.TargetID == "" ||
		config.Enrollment.DeploymentGeneration < 1 {
		return fmt.Errorf("runtime config requires a fixed enrollment identity")
	}
	if config.CurrentRevocationEpoch < 1 {
		return fmt.Errorf("current_revocation_epoch must be at least 1")
	}
	if config.PaperRuntime != nil {
		if config.PaperRuntime.SnapshotPath == "" || !filepath.IsAbs(config.PaperRuntime.SnapshotPath) ||
			filepath.Clean(config.PaperRuntime.SnapshotPath) != config.PaperRuntime.SnapshotPath {
			return fmt.Errorf("paper_runtime.snapshot_path must be a clean absolute path")
		}
	}
	if config.HostObservation != nil {
		if config.HostObservation.SnapshotPath == "" || !filepath.IsAbs(config.HostObservation.SnapshotPath) ||
			filepath.Clean(config.HostObservation.SnapshotPath) != config.HostObservation.SnapshotPath {
			return fmt.Errorf("host_observation.snapshot_path must be a clean absolute path")
		}
	}
	if config.Support.ProfileID == "" {
		return fmt.Errorf("support_profile.profile_id is required")
	}
	if config.Support.ProfileID != config.Enrollment.SupportProfileID {
		return fmt.Errorf("support profile does not match enrollment")
	}
	allowedPlugins := make(map[string]struct{}, len(config.Enrollment.AllowedPlugins))
	for _, pluginID := range config.Enrollment.AllowedPlugins {
		if pluginID == "" {
			return fmt.Errorf("allowed plugin IDs must not be empty")
		}
		if _, exists := allowedPlugins[pluginID]; exists {
			return fmt.Errorf("duplicate allowed plugin ID %q", pluginID)
		}
		allowedPlugins[pluginID] = struct{}{}
	}
	for id, artifact := range config.Artifacts {
		if id == "" || artifact.ArtifactID != id || artifact.PluginID == "" {
			return fmt.Errorf("artifact registry key and artifact_id must match")
		}
		if _, allowed := allowedPlugins[artifact.PluginID]; !allowed {
			return fmt.Errorf("artifact %q belongs to a plugin outside the enrollment", id)
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != 32 || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
			return fmt.Errorf("artifact %q requires a full SHA-256", id)
		}
	}
	for id, profile := range config.Profiles {
		if id == "" || profile.ProfileID != id || profile.PluginID == "" {
			return fmt.Errorf("profile registry key and profile_id must match")
		}
		if profile.PaperTuple != config.Enrollment.PaperTuple {
			return fmt.Errorf("profile %q Paper tuple does not match enrollment", id)
		}
		from, fromOK := config.Artifacts[profile.FromArtifactID]
		to, toOK := config.Artifacts[profile.ToArtifactID]
		if !fromOK || !toOK || from.PluginID != profile.PluginID || to.PluginID != profile.PluginID {
			return fmt.Errorf("profile %q must reference two catalog artifacts for its plugin", id)
		}
	}
	return nil
}

func (config Config) Registry() workflow.Registry {
	return workflow.Registry{
		Enrollment: config.Enrollment,
		Artifacts:  config.Artifacts,
		Profiles:   config.Profiles,
	}
}
