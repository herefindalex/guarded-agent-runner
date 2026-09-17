package g02

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigRejectsUnsafeAndAmbiguousOwnerInput(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config.json")
	valid := `{
		"schema_version":"gar.g02-acceptance-config.v2",
  "admission_config_path":"/owner/admission.json",
  "server_config_path":"/owner/server.json",
  "evidence_path":"/owner/evidence.json",
		"minecraft_addresses":["127.0.0.1:25565","[::1]:25565"],
  "enrollment_id":"enrollment",
  "container_identity":"container",
  "data_root_identity":"root",
  "paper_tuple":"tuple",
  "connection_deadline_milliseconds":1000,
  "runtime_settle_timeout_milliseconds":5000
}`
	if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("group-readable owner config must be rejected")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("valid owner-only config rejected: %v", err)
	}

	unknown := valid[:len(valid)-1] + `,"agent_selected_path":"/tmp/escape"}`
	if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown escape-hatch field must be rejected")
	}

	duplicate := `{"schema_version":"gar.g02-acceptance-config.v2","schema_version":"gar.g02-acceptance-config.v2"}`
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("duplicate config fields must be rejected")
	}
}
