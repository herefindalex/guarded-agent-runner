package g02

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/strictjson"
)

const EvidenceSchemaVersion = "gar.g02-acceptance-evidence.v2"

type MinecraftLoginEvidence struct {
	EvidenceLevel              string    `json:"evidence_level"`
	MinecraftAddress           string    `json:"minecraft_address"`
	ObservedAt                 time.Time `json:"observed_at"`
	ProtocolVersion            int32     `json:"protocol_version"`
	ProtocolName               string    `json:"protocol_name"`
	PlayerCountBefore          int       `json:"player_count_before"`
	PlayerCountAfter           int       `json:"player_count_after"`
	StatusProbePassed          bool      `json:"status_probe_passed"`
	LoginHandshakeSent         bool      `json:"login_handshake_sent"`
	LoginStartSent             bool      `json:"login_start_sent"`
	ConnectionAliveBeforeClose bool      `json:"connection_alive_before_close"`
	CloseIssuedAt              time.Time `json:"close_issued_at"`
	ConnectionClosedAt         time.Time `json:"connection_closed_at"`
	CloseLatencyMilliseconds   int64     `json:"close_latency_milliseconds"`
	FinalAdmissionReason       string    `json:"final_admission_reason"`
	Result                     string    `json:"result"`
	Failure                    string    `json:"failure,omitempty"`
}

type HostRebootEvidence struct {
	EvidenceLevel        string    `json:"evidence_level"`
	PreparedAt           time.Time `json:"prepared_at"`
	VerifiedAt           time.Time `json:"verified_at,omitempty"`
	PreRebootBootID      string    `json:"pre_reboot_boot_id"`
	PostRebootBootID     string    `json:"post_reboot_boot_id,omitempty"`
	PreAdmissionReason   string    `json:"pre_admission_reason"`
	PostAdmissionReason  string    `json:"post_admission_reason,omitempty"`
	EndpointClosedBefore bool      `json:"endpoint_closed_before"`
	EndpointClosedAfter  bool      `json:"endpoint_closed_after,omitempty"`
	Result               string    `json:"result"`
	Failure              string    `json:"failure,omitempty"`
}

type Evidence struct {
	SchemaVersion        string                   `json:"schema_version"`
	EnrollmentID         string                   `json:"enrollment_id"`
	DeploymentGeneration int64                    `json:"deployment_generation"`
	ContainerIdentity    string                   `json:"container_identity"`
	DataRootIdentity     string                   `json:"data_root_identity"`
	PaperTuple           string                   `json:"paper_tuple"`
	PairingID            string                   `json:"pairing_id"`
	MinecraftAddresses   []string                 `json:"minecraft_addresses"`
	UpdatedAt            time.Time                `json:"updated_at"`
	MinecraftLogins      []MinecraftLoginEvidence `json:"minecraft_inflight_logins,omitempty"`
	HostReboot           *HostRebootEvidence      `json:"host_reboot,omitempty"`
}

func newEvidence(config Config, deploymentGeneration int64, pairingID string, now time.Time) Evidence {
	return Evidence{
		SchemaVersion: EvidenceSchemaVersion, EnrollmentID: config.EnrollmentID,
		DeploymentGeneration: deploymentGeneration, ContainerIdentity: config.ContainerIdentity,
		DataRootIdentity: config.DataRootIdentity, PaperTuple: config.PaperTuple,
		PairingID: pairingID, MinecraftAddresses: append([]string(nil), config.MinecraftAddresses...), UpdatedAt: now.UTC(),
	}
}

func loadEvidence(path string) (Evidence, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return Evidence{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Evidence{}, err
	}
	if len(payload) > 1<<20 {
		return Evidence{}, fmt.Errorf("G-02 evidence exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return Evidence{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var evidence Evidence
	if err := decoder.Decode(&evidence); err != nil {
		return Evidence{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || evidence.SchemaVersion != EvidenceSchemaVersion {
		return Evidence{}, fmt.Errorf("invalid G-02 evidence schema or trailing JSON")
	}
	return evidence, nil
}

func writeEvidence(path string, evidence Evidence) error {
	directory := filepath.Dir(path)
	if err := validateOwnerDirectory(directory); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gar-g02-evidence-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(payload, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
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
