package admission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"guarded-agent-runner/internal/strictjson"
)

const paperRuntimeSchemaVersion = "gar.paper-runtime-observation.v1"
const maxRuntimeSnapshotBytes = 256 * 1024
const runtimeFreshness = 3 * time.Second

type runtimeAdmissionSnapshot struct {
	SchemaVersion  string            `json:"schema_version"`
	PairingID      string            `json:"pairing_id"`
	BootID         string            `json:"boot_id"`
	ObservedAt     time.Time         `json:"observed_at"`
	Ready          bool              `json:"ready"`
	AdmissionState string            `json:"admission_state"`
	PlayerCount    int               `json:"player_count"`
	TPS            []json.RawMessage `json:"tps"`
	MSPT           json.RawMessage   `json:"mspt"`
	HeapUsedBytes  int64             `json:"heap_used_bytes"`
	HeapMaxBytes   int64             `json:"heap_max_bytes"`
	Plugins        []json.RawMessage `json:"plugins"`
}

func EvaluateAccess(config Config, now time.Time) Decision {
	decision := EvaluateState(config, now)
	if !decision.Open {
		return decision
	}
	runtime, err := readRuntimeSnapshot(config.RuntimeSnapshotPath)
	if err != nil {
		decision.Open = false
		decision.ReasonCode = "RUNTIME_GUARD_UNAVAILABLE"
		return decision
	}
	if runtime.SchemaVersion != paperRuntimeSchemaVersion || runtime.PairingID != config.PairingID ||
		runtime.BootID == "" || !runtime.Ready || runtime.ObservedAt.IsZero() ||
		runtime.ObservedAt.After(now.Add(2*time.Second)) || now.Sub(runtime.ObservedAt) > runtimeFreshness {
		decision.Open = false
		decision.ReasonCode = "RUNTIME_GUARD_NOT_READY"
		return decision
	}
	if runtime.AdmissionState != "OPEN_READ_ONLY_ALPHA" {
		decision.Open = false
		decision.ReasonCode = "RUNTIME_GUARD_NOT_OPEN"
		return decision
	}
	decision.ReasonCode = "ADMISSION_OPEN_GUARD_CONFIRMED"
	return decision
}

func readRuntimeSnapshot(path string) (runtimeAdmissionSnapshot, error) {
	payload, err := readNoFollow(path, maxRuntimeSnapshotBytes)
	if err != nil {
		return runtimeAdmissionSnapshot{}, err
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return runtimeAdmissionSnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot runtimeAdmissionSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return runtimeAdmissionSnapshot{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return runtimeAdmissionSnapshot{}, fmt.Errorf("runtime snapshot contains trailing JSON")
	}
	return snapshot, nil
}

func readNoFollow(path string, maximum int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size > int64(maximum) {
		return nil, fmt.Errorf("runtime snapshot must be a bounded regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil || len(payload) > maximum {
		return nil, fmt.Errorf("runtime snapshot exceeds limit")
	}
	return payload, nil
}
