// Package admission implements the fixed-target, fail-closed TCP admission
// barrier used by the Paper reference deployment. It is an owner-local host
// primitive and is never exposed as an agent or MCP capability.
package admission

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

const ConfigSchemaVersion = "gar.admission-config.v1"

type Config struct {
	SchemaVersion            string   `json:"schema_version"`
	PairingID                string   `json:"pairing_id"`
	DeploymentGeneration     int64    `json:"deployment_generation"`
	ListenAddresses          []string `json:"listen_addresses"`
	UpstreamAddress          string   `json:"upstream_address"`
	StatePath                string   `json:"state_path"`
	RuntimeSnapshotPath      string   `json:"runtime_snapshot_path"`
	PollIntervalMilliseconds int      `json:"poll_interval_milliseconds"`
	DialTimeoutMilliseconds  int      `json:"dial_timeout_milliseconds"`
	MaxConnections           int      `json:"max_connections"`
}

func LoadConfig(path string) (Config, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return Config{}, fmt.Errorf("admission config security check: %w", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if len(payload) > 1<<20 {
		return Config{}, fmt.Errorf("admission config exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Config{}, fmt.Errorf("decode admission config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode admission config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Config{}, fmt.Errorf("admission config contains trailing JSON")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != ConfigSchemaVersion || config.PairingID == "" ||
		len(config.PairingID) > 128 || config.DeploymentGeneration < 1 {
		return fmt.Errorf("admission schema and fixed deployment identity are required")
	}
	if len(config.ListenAddresses) < 1 || len(config.ListenAddresses) > 4 {
		return fmt.Errorf("admission requires one through four fixed listeners")
	}
	seen := make(map[string]struct{}, len(config.ListenAddresses))
	for _, address := range config.ListenAddresses {
		if err := validateLiteralAddress(address, false); err != nil {
			return fmt.Errorf("invalid admission listener %q: %w", address, err)
		}
		if _, exists := seen[address]; exists {
			return fmt.Errorf("duplicate admission listener %q", address)
		}
		seen[address] = struct{}{}
	}
	if err := validateLiteralAddress(config.UpstreamAddress, true); err != nil {
		return fmt.Errorf("invalid admission upstream: %w", err)
	}
	for name, path := range map[string]string{
		"state_path": config.StatePath, "runtime_snapshot_path": config.RuntimeSnapshotPath,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("admission %s must be a clean absolute path", name)
		}
	}
	if config.PollIntervalMilliseconds < 25 || config.PollIntervalMilliseconds > 1000 {
		return fmt.Errorf("poll_interval_milliseconds must be from 25 through 1000")
	}
	if config.DialTimeoutMilliseconds < 100 || config.DialTimeoutMilliseconds > 5000 {
		return fmt.Errorf("dial_timeout_milliseconds must be from 100 through 5000")
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4096 {
		return fmt.Errorf("max_connections must be from 1 through 4096")
	}
	return nil
}

func (config Config) PollInterval() time.Duration {
	return time.Duration(config.PollIntervalMilliseconds) * time.Millisecond
}

func (config Config) DialTimeout() time.Duration {
	return time.Duration(config.DialTimeoutMilliseconds) * time.Millisecond
}

func validateLiteralAddress(address string, requireLoopback bool) error {
	if strings.TrimSpace(address) != address {
		return fmt.Errorf("address must not contain surrounding whitespace")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host must be a literal IP")
	}
	if requireLoopback && !ip.IsLoopback() {
		return fmt.Errorf("upstream must be literal loopback in the shared Paper network namespace")
	}
	if port == "" || port == "0" {
		return fmt.Errorf("port must be fixed and non-zero")
	}
	return nil
}
