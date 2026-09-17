package g03

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	evidence := filepath.Join(root, "evidence")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		SchemaVersion: ConfigSchemaVersion, RuntimeConfigPath: filepath.Join(root, "runtime.json"),
		HostObserverConfigPath: filepath.Join(root, "host.json"), DatabasePath: filepath.Join(root, "gar.db"),
		BackupDirectory: backup, EvidencePath: filepath.Join(evidence, "result.json"),
		PluginID: "gar-guard", TargetArtifactID: "candidate", ProfileID: "g03-only",
		PrincipalID: "g03-agent", ClientRequestID: "g03-run", StopTimeoutSeconds: 120,
		MaxBackupBytes: 1 << 30, MaxBackupFiles: 100_000,
	}
}

func TestConfigRejectsUnknownFieldsAndSharedEvidenceDirectory(t *testing.T) {
	config := validConfig(t)
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.EvidencePath = filepath.Join(config.BackupDirectory, "result.json")
	if err := config.Validate(); err == nil {
		t.Fatal("evidence inside artifact directory was accepted")
	}
	config = validConfig(t)
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"agent_path":"/tmp/untrusted"}`)...)
	path := filepath.Join(t.TempDir(), "g03.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown caller-controlled path was accepted")
	}
}

func TestConfigValidateRejectsEveryUnboundedOwnerInputClass(t *testing.T) {
	tests := map[string]func(*Config){
		"schema":             func(config *Config) { config.SchemaVersion = "other" },
		"relative path":      func(config *Config) { config.DatabasePath = "gar.db" },
		"unclean path":       func(config *Config) { config.DatabasePath += "/../gar.db" },
		"missing identifier": func(config *Config) { config.PluginID = "" },
		"long principal":     func(config *Config) { config.PrincipalID = string(make([]byte, 129)) },
		"short timeout":      func(config *Config) { config.StopTimeoutSeconds = 4 },
		"long timeout":       func(config *Config) { config.StopTimeoutSeconds = 121 },
		"small byte limit":   func(config *Config) { config.MaxBackupBytes = (1 << 20) - 1 },
		"large byte limit":   func(config *Config) { config.MaxBackupBytes = (1 << 40) + 1 },
		"zero file limit":    func(config *Config) { config.MaxBackupFiles = 0 },
		"large file limit":   func(config *Config) { config.MaxBackupFiles = 1_000_001 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig(t)
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid owner input was accepted")
			}
		})
	}
}
