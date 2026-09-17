package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/strictjson"
)

const StateSchemaVersion = "gar.admission-state.v1"
const MaxOpenLease = 30 * time.Second

type Mode string

const (
	ModeClosed Mode = "CLOSED"
	ModeOpen   Mode = "OPEN"
)

type State struct {
	SchemaVersion        string    `json:"schema_version"`
	PairingID            string    `json:"pairing_id"`
	DeploymentGeneration int64     `json:"deployment_generation"`
	Mode                 Mode      `json:"mode"`
	Reason               string    `json:"reason"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
}

type Decision struct {
	Open       bool
	ReasonCode string
	State      State
}

func EvaluateState(config Config, now time.Time) Decision {
	state, err := readState(config.StatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Decision{ReasonCode: "ADMISSION_STATE_MISSING"}
		}
		return Decision{ReasonCode: "ADMISSION_STATE_INVALID"}
	}
	if state.PairingID != config.PairingID || state.DeploymentGeneration != config.DeploymentGeneration {
		return Decision{ReasonCode: "ADMISSION_IDENTITY_MISMATCH", State: state}
	}
	if state.IssuedAt.IsZero() || state.IssuedAt.After(now.Add(2*time.Second)) || len(state.Reason) > 256 {
		return Decision{ReasonCode: "ADMISSION_STATE_INVALID", State: state}
	}
	switch state.Mode {
	case ModeClosed:
		return Decision{ReasonCode: "ADMISSION_CLOSED", State: state}
	case ModeOpen:
		if state.ExpiresAt.IsZero() || !now.Before(state.ExpiresAt) {
			return Decision{ReasonCode: "ADMISSION_LEASE_EXPIRED", State: state}
		}
		if state.ExpiresAt.Sub(state.IssuedAt) > MaxOpenLease || !state.ExpiresAt.After(state.IssuedAt) {
			return Decision{ReasonCode: "ADMISSION_LEASE_INVALID", State: state}
		}
		return Decision{Open: true, ReasonCode: "ADMISSION_OPEN", State: state}
	default:
		return Decision{ReasonCode: "ADMISSION_STATE_INVALID", State: state}
	}
}

func WriteState(config Config, mode Mode, reason string, lease time.Duration, now time.Time) (State, error) {
	if len(reason) > 256 {
		return State{}, fmt.Errorf("admission reason exceeds 256 characters")
	}
	state := State{
		SchemaVersion: StateSchemaVersion, PairingID: config.PairingID,
		DeploymentGeneration: config.DeploymentGeneration, Mode: mode,
		Reason: reason, IssuedAt: now.UTC(),
	}
	switch mode {
	case ModeClosed:
		if lease != 0 {
			return State{}, fmt.Errorf("closed admission state cannot have a lease")
		}
	case ModeOpen:
		if lease <= 0 || lease > MaxOpenLease {
			return State{}, fmt.Errorf("open admission lease must be greater than zero and at most %s", MaxOpenLease)
		}
		state.ExpiresAt = state.IssuedAt.Add(lease)
	default:
		return State{}, fmt.Errorf("unsupported admission mode %q", mode)
	}
	if err := validateOwnerDirectory(filepath.Dir(config.StatePath)); err != nil {
		return State{}, err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return State{}, err
	}
	directory := filepath.Dir(config.StatePath)
	temporary, err := os.CreateTemp(directory, ".gar-admission-*.tmp")
	if err != nil {
		return State{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return State{}, err
	}
	if _, err := temporary.Write(append(payload, '\n')); err != nil {
		temporary.Close()
		return State{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return State{}, err
	}
	if err := temporary.Close(); err != nil {
		return State{}, err
	}
	if err := os.Rename(temporaryPath, config.StatePath); err != nil {
		return State{}, err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return State{}, err
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return State{}, err
	}
	return state, nil
}

func readState(path string) (State, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return State{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	if len(payload) > 64<<10 {
		return State{}, fmt.Errorf("admission state exceeds 64 KiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || state.SchemaVersion != StateSchemaVersion {
		return State{}, fmt.Errorf("invalid admission state schema or trailing JSON")
	}
	return state, nil
}

func validateOwnerDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a non-symlink directory", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not grant group or other access", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must be owned by current OS user", path)
	}
	return nil
}
