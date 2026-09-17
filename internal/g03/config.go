// Package g03 contains the owner-only acceptance configuration for the G-03
// stop and offline-backup boundary. It is not loaded by the MCP server.
package g03

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/strictjson"
)

const ConfigSchemaVersion = "gar.g03-acceptance-config.v1"

type Config struct {
	SchemaVersion          string `json:"schema_version"`
	RuntimeConfigPath      string `json:"runtime_config_path"`
	HostObserverConfigPath string `json:"host_observer_config_path"`
	DatabasePath           string `json:"database_path"`
	BackupDirectory        string `json:"backup_directory"`
	EvidencePath           string `json:"evidence_path"`
	PluginID               string `json:"plugin_id"`
	TargetArtifactID       string `json:"target_artifact_id"`
	ProfileID              string `json:"profile_id"`
	PrincipalID            string `json:"principal_id"`
	ClientRequestID        string `json:"client_request_id"`
	StopTimeoutSeconds     int    `json:"stop_timeout_seconds"`
	MaxBackupBytes         int64  `json:"max_backup_bytes"`
	MaxBackupFiles         int    `json:"max_backup_files"`
}

func Load(path string) (Config, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return Config{}, fmt.Errorf("G-03 config security check: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(payload) > 1<<20 {
		return Config{}, fmt.Errorf("G-03 config exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Config{}, fmt.Errorf("decode G-03 config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode G-03 config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, fmt.Errorf("G-03 config contains trailing JSON")
	}
	return config, config.Validate()
}

func (config Config) Validate() error {
	if config.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("unsupported G-03 config schema %q", config.SchemaVersion)
	}
	for _, path := range []string{
		config.RuntimeConfigPath, config.HostObserverConfigPath, config.DatabasePath,
		config.BackupDirectory, config.EvidencePath,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("G-03 paths must be clean owner-controlled absolute paths")
		}
	}
	if config.PluginID == "" || config.TargetArtifactID == "" || config.ProfileID == "" ||
		config.PrincipalID == "" || len(config.PrincipalID) > 128 ||
		config.ClientRequestID == "" || len(config.ClientRequestID) > 128 {
		return fmt.Errorf("G-03 proposal identifiers are required and bounded")
	}
	if config.StopTimeoutSeconds < 5 || config.StopTimeoutSeconds > 120 {
		return fmt.Errorf("stop_timeout_seconds must be from 5 through 120")
	}
	if config.MaxBackupBytes < 1<<20 || config.MaxBackupBytes > 1<<40 ||
		config.MaxBackupFiles < 1 || config.MaxBackupFiles > 1_000_000 {
		return fmt.Errorf("G-03 backup resource limits are invalid")
	}
	if filepath.Dir(config.EvidencePath) == config.BackupDirectory {
		return fmt.Errorf("evidence metadata must be outside the backup artifact directory")
	}
	return nil
}

func (config Config) StopTimeout() time.Duration {
	return time.Duration(config.StopTimeoutSeconds) * time.Second
}
