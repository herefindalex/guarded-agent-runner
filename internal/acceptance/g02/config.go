// Package g02 implements owner-local acceptance evidence for the admission
// barrier. It is deliberately not reachable from MCP or the agent workflow.
package g02

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/strictjson"
)

const ConfigSchemaVersion = "gar.g02-acceptance-config.v2"

type Config struct {
	SchemaVersion          string   `json:"schema_version"`
	AdmissionConfigPath    string   `json:"admission_config_path"`
	ServerConfigPath       string   `json:"server_config_path"`
	EvidencePath           string   `json:"evidence_path"`
	MinecraftAddresses     []string `json:"minecraft_addresses"`
	EnrollmentID           string   `json:"enrollment_id"`
	ContainerIdentity      string   `json:"container_identity"`
	DataRootIdentity       string   `json:"data_root_identity"`
	PaperTuple             string   `json:"paper_tuple"`
	ConnectionDeadlineMS   int      `json:"connection_deadline_milliseconds"`
	RuntimeSettleTimeoutMS int      `json:"runtime_settle_timeout_milliseconds"`
}

func LoadConfig(path string) (Config, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return Config{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if len(payload) > 1<<20 {
		return Config{}, fmt.Errorf("G-02 acceptance config exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode G-02 acceptance config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, fmt.Errorf("G-02 acceptance config contains trailing JSON")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != ConfigSchemaVersion {
		return fmt.Errorf("unsupported G-02 acceptance config schema %q", config.SchemaVersion)
	}
	for name, value := range map[string]string{
		"admission_config_path": config.AdmissionConfigPath,
		"server_config_path":    config.ServerConfigPath,
		"evidence_path":         config.EvidencePath,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be a clean absolute path", name)
		}
	}
	if config.AdmissionConfigPath == config.EvidencePath || config.ServerConfigPath == config.EvidencePath ||
		config.AdmissionConfigPath == config.ServerConfigPath {
		return fmt.Errorf("admission, server, and evidence paths must be distinct")
	}
	if len(config.MinecraftAddresses) < 1 || len(config.MinecraftAddresses) > 4 {
		return fmt.Errorf("minecraft_addresses must contain one through four fixed bindings")
	}
	seenAddresses := make(map[string]struct{}, len(config.MinecraftAddresses))
	for _, address := range config.MinecraftAddresses {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("minecraft_addresses: %w", err)
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() || port == "" || port == "0" {
			return fmt.Errorf("minecraft_addresses must use literal loopback addresses and non-zero ports")
		}
		if _, exists := seenAddresses[address]; exists {
			return fmt.Errorf("duplicate minecraft address %q", address)
		}
		seenAddresses[address] = struct{}{}
	}
	for name, value := range map[string]string{
		"enrollment_id":      config.EnrollmentID,
		"container_identity": config.ContainerIdentity,
		"data_root_identity": config.DataRootIdentity,
		"paper_tuple":        config.PaperTuple,
	} {
		if strings.TrimSpace(value) != value || value == "" || len(value) > 512 {
			return fmt.Errorf("%s must be non-empty, trimmed, and at most 512 bytes", name)
		}
	}
	if config.ConnectionDeadlineMS < 250 || config.ConnectionDeadlineMS > 10_000 {
		return fmt.Errorf("connection_deadline_milliseconds must be 250 through 10000")
	}
	if config.RuntimeSettleTimeoutMS < 1_000 || config.RuntimeSettleTimeoutMS > 30_000 {
		return fmt.Errorf("runtime_settle_timeout_milliseconds must be 1000 through 30000")
	}
	return nil
}

func (config Config) ConnectionDeadline() time.Duration {
	return time.Duration(config.ConnectionDeadlineMS) * time.Millisecond
}

func (config Config) RuntimeSettleTimeout() time.Duration {
	return time.Duration(config.RuntimeSettleTimeoutMS) * time.Millisecond
}
