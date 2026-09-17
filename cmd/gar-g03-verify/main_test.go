package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteEvidenceAtomicallyCreatesAndNeverOverwrites(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "evidence.json")
	value := map[string]any{"gate": "G-03", "result": "PASS"}
	if err := writeEvidence(path, value); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["gate"] != "G-03" || stored["result"] != "PASS" {
		t.Fatalf("evidence changed during finalization: %#v", stored)
	}
	if err := writeEvidence(path, map[string]any{"result": "REPLACED"}); err == nil {
		t.Fatal("existing acceptance evidence was overwritten")
	}
}

func TestWriteEvidenceRejectsNonOwnerOnlyDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeEvidence(filepath.Join(directory, "evidence.json"), map[string]any{"gate": "G-03"}); err == nil {
		t.Fatal("evidence was written to a non-owner-only directory")
	}
}
