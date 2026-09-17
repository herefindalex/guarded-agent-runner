package g02

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/runtimeconfig"
	"guarded-agent-runner/internal/strictjson"
)

const bootIDPath = "/proc/sys/kernel/random/boot_id"

type Runner struct {
	config    Config
	admission admission.Config
	now       func() time.Time
	bootID    func() (string, error)
}

func NewRunner(config Config) (*Runner, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	admissionConfig, err := admission.LoadConfig(config.AdmissionConfigPath)
	if err != nil {
		return nil, err
	}
	if !matchesAdmissionListener(config.MinecraftAddress, admissionConfig.ListenAddresses) {
		return nil, fmt.Errorf("minecraft_address does not match a configured admission listener")
	}
	serverConfig, err := runtimeconfig.Load(config.ServerConfigPath)
	if err != nil {
		return nil, err
	}
	enrollment := serverConfig.Enrollment
	if enrollment.EnrollmentID != config.EnrollmentID || enrollment.ContainerID != config.ContainerIdentity ||
		enrollment.DataRootIdentity != config.DataRootIdentity || enrollment.PaperTuple != config.PaperTuple ||
		enrollment.DeploymentGeneration != admissionConfig.DeploymentGeneration ||
		enrollment.RuntimeGuardPairing != admissionConfig.PairingID {
		return nil, fmt.Errorf("G-02 config identity does not match the owner-controlled GAR enrollment")
	}
	return &Runner{
		config: config, admission: admissionConfig, now: time.Now,
		bootID: readBootID,
	}, nil
}

func matchesAdmissionListener(address string, listeners []string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	targetIP := net.ParseIP(host)
	for _, listener := range listeners {
		listenerHost, listenerPort, splitErr := net.SplitHostPort(listener)
		if splitErr != nil || listenerPort != port {
			continue
		}
		listenerIP := net.ParseIP(listenerHost)
		if listenerIP == nil || targetIP == nil || (listenerIP.To4() == nil) != (targetIP.To4() == nil) {
			continue
		}
		if listenerIP.IsUnspecified() || listenerIP.Equal(targetIP) {
			return true
		}
	}
	return false
}

func (runner *Runner) MinecraftLoginClose(ctx context.Context) (evidence Evidence, returnErr error) {
	now := runner.now().UTC()
	evidence = runner.baseEvidence(now)
	result := &MinecraftLoginEvidence{EvidenceLevel: "LOCAL_PAPER", ObservedAt: now, Result: "FAIL"}
	evidence.MinecraftLogin = result
	defer func() {
		evidence.UpdatedAt = runner.now().UTC()
		if returnErr != nil {
			result.Failure = returnErr.Error()
		}
		if writeErr := writeEvidence(runner.config.EvidencePath, evidence); returnErr == nil && writeErr != nil {
			returnErr = writeErr
		}
	}()

	decision := admission.EvaluateAccess(runner.admission, now)
	if decision.Open || decision.ReasonCode != "ADMISSION_CLOSED" {
		return evidence, fmt.Errorf("precondition requires explicit CLOSED admission, got %s", decision.ReasonCode)
	}
	before, err := runner.readRuntime(now)
	if err != nil {
		return evidence, err
	}
	if before.PlayerCount != 0 {
		return evidence, fmt.Errorf("precondition requires zero players, got %d", before.PlayerCount)
	}
	result.PlayerCountBefore = before.PlayerCount

	if _, err := admission.WriteState(runner.admission, admission.ModeOpen, "g02-minecraft-login-probe", 20*time.Second, now); err != nil {
		return evidence, err
	}
	defer func() {
		_, _ = admission.WriteState(runner.admission, admission.ModeClosed, "g02-probe-cleanup", 0, runner.now().UTC())
	}()
	if err := runner.waitForDecision(ctx, true); err != nil {
		return evidence, err
	}

	protocol, protocolName, err := discoverProtocol(runner.config.MinecraftAddress, runner.config.ConnectionDeadline())
	if err != nil {
		return evidence, fmt.Errorf("Minecraft status probe: %w", err)
	}
	result.StatusProbePassed = true
	result.ProtocolVersion = protocol
	result.ProtocolName = protocolName

	connection, err := beginLogin(runner.config.MinecraftAddress, protocol, runner.config.ConnectionDeadline())
	if err != nil {
		return evidence, fmt.Errorf("begin Minecraft login: %w", err)
	}
	defer connection.Close()
	result.LoginHandshakeSent = true
	result.LoginStartSent = true
	if err := proveConnectionAlive(connection, 50*time.Millisecond); err != nil {
		return evidence, fmt.Errorf("login connection did not remain in flight before close: %w", err)
	}
	result.ConnectionAliveBeforeClose = true

	closeIssuedAt := runner.now().UTC()
	result.CloseIssuedAt = closeIssuedAt
	if _, err := admission.WriteState(runner.admission, admission.ModeClosed, "g02-minecraft-login-close", 0, closeIssuedAt); err != nil {
		return evidence, err
	}
	closedAt, err := waitForConnectionClose(connection, runner.config.ConnectionDeadline())
	if err != nil {
		return evidence, err
	}
	result.ConnectionClosedAt = closedAt
	result.CloseLatencyMilliseconds = closedAt.Sub(closeIssuedAt).Milliseconds()

	finalDecision, runtime, err := runner.waitForClosedRuntime(ctx)
	if err != nil {
		return evidence, err
	}
	result.FinalAdmissionReason = finalDecision.ReasonCode
	result.PlayerCountAfter = runtime.PlayerCount
	if runtime.PlayerCount != 0 {
		return evidence, fmt.Errorf("probe player became active after close: %d", runtime.PlayerCount)
	}
	result.Result = "PASS"
	return evidence, nil
}

func (runner *Runner) PrepareHostReboot(ctx context.Context) (Evidence, error) {
	now := runner.now().UTC()
	evidence := runner.baseEvidence(now)
	decision := admission.EvaluateAccess(runner.admission, now)
	if decision.Open || decision.ReasonCode != "ADMISSION_CLOSED" {
		return evidence, fmt.Errorf("host reboot checkpoint requires explicit CLOSED admission, got %s", decision.ReasonCode)
	}
	if _, err := runner.readRuntime(now); err != nil {
		return evidence, err
	}
	endpointClosed := runner.endpointClosed()
	if !endpointClosed {
		return evidence, fmt.Errorf("Minecraft endpoint answered while admission was expected closed")
	}
	bootID, err := runner.bootID()
	if err != nil {
		return evidence, err
	}
	evidence.HostReboot = &HostRebootEvidence{
		EvidenceLevel: "HOST_RECOVERY", PreparedAt: now, PreRebootBootID: bootID,
		PreAdmissionReason: decision.ReasonCode, EndpointClosedBefore: true, Result: "PREPARED",
	}
	evidence.UpdatedAt = now
	if err := writeEvidence(runner.config.EvidencePath, evidence); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func (runner *Runner) VerifyHostReboot(ctx context.Context) (Evidence, error) {
	evidence, err := loadEvidence(runner.config.EvidencePath)
	if err != nil {
		return Evidence{}, err
	}
	if err := runner.matches(evidence); err != nil {
		return evidence, err
	}
	if evidence.HostReboot == nil || evidence.HostReboot.Result != "PREPARED" {
		return evidence, fmt.Errorf("host reboot evidence is not in PREPARED state")
	}
	now := runner.now().UTC()
	currentBootID, err := runner.bootID()
	if err != nil {
		return evidence, err
	}
	result := evidence.HostReboot
	result.VerifiedAt = now
	result.PostRebootBootID = currentBootID
	result.Result = "FAIL"
	if currentBootID == result.PreRebootBootID {
		result.Failure = "kernel boot ID did not change"
		evidence.UpdatedAt = now
		_ = writeEvidence(runner.config.EvidencePath, evidence)
		return evidence, fmt.Errorf("host reboot not observed: kernel boot ID is unchanged")
	}
	decision := admission.EvaluateAccess(runner.admission, now)
	result.PostAdmissionReason = decision.ReasonCode
	result.EndpointClosedAfter = runner.endpointClosed()
	if decision.Open || !result.EndpointClosedAfter {
		result.Failure = "admission reopened after host reboot"
		evidence.UpdatedAt = now
		_ = writeEvidence(runner.config.EvidencePath, evidence)
		return evidence, fmt.Errorf("admission did not fail closed after host reboot")
	}
	result.Result = "PASS"
	result.Failure = ""
	evidence.UpdatedAt = now
	if err := writeEvidence(runner.config.EvidencePath, evidence); err != nil {
		return evidence, err
	}
	return evidence, nil
}

func (runner *Runner) baseEvidence(now time.Time) Evidence {
	evidence := newEvidence(runner.config, runner.admission.DeploymentGeneration, runner.admission.PairingID, now)
	if existing, err := loadEvidence(runner.config.EvidencePath); err == nil && runner.matches(existing) == nil {
		evidence.MinecraftLogin = existing.MinecraftLogin
		evidence.HostReboot = existing.HostReboot
	}
	return evidence
}

func (runner *Runner) matches(evidence Evidence) error {
	if evidence.SchemaVersion != EvidenceSchemaVersion || evidence.EnrollmentID != runner.config.EnrollmentID ||
		evidence.DeploymentGeneration != runner.admission.DeploymentGeneration ||
		evidence.ContainerIdentity != runner.config.ContainerIdentity ||
		evidence.DataRootIdentity != runner.config.DataRootIdentity || evidence.PaperTuple != runner.config.PaperTuple ||
		evidence.PairingID != runner.admission.PairingID || evidence.MinecraftAddress != runner.config.MinecraftAddress {
		return fmt.Errorf("G-02 evidence belongs to another target or generation")
	}
	return nil
}

func (runner *Runner) waitForDecision(ctx context.Context, expectedOpen bool) error {
	deadline := runner.now().Add(runner.config.RuntimeSettleTimeout())
	for {
		decision := admission.EvaluateAccess(runner.admission, runner.now().UTC())
		if decision.Open == expectedOpen {
			return nil
		}
		if !runner.now().Before(deadline) {
			return fmt.Errorf("admission did not reach open=%t before deadline; last reason=%s", expectedOpen, decision.ReasonCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (runner *Runner) waitForClosedRuntime(ctx context.Context) (admission.Decision, runtimeProbeSnapshot, error) {
	deadline := runner.now().Add(runner.config.RuntimeSettleTimeout())
	for {
		now := runner.now().UTC()
		decision := admission.EvaluateAccess(runner.admission, now)
		runtime, err := runner.readRuntime(now)
		if !decision.Open && decision.ReasonCode == "ADMISSION_CLOSED" && err == nil && runtime.AdmissionState == "MAINTENANCE" {
			return decision, runtime, nil
		}
		if !runner.now().Before(deadline) {
			return decision, runtime, fmt.Errorf("closed runtime acknowledgment unavailable before deadline")
		}
		select {
		case <-ctx.Done():
			return decision, runtime, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (runner *Runner) endpointClosed() bool {
	_, _, err := discoverProtocol(runner.config.MinecraftAddress, runner.config.ConnectionDeadline())
	return err != nil
}

type runtimeProbeSnapshot struct {
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

func (runner *Runner) readRuntime(now time.Time) (runtimeProbeSnapshot, error) {
	payload, err := readNoFollow(runner.admission.RuntimeSnapshotPath, 256*1024)
	if err != nil {
		return runtimeProbeSnapshot{}, err
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return runtimeProbeSnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var snapshot runtimeProbeSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return runtimeProbeSnapshot{}, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return runtimeProbeSnapshot{}, fmt.Errorf("runtime snapshot contains trailing JSON")
	}
	if snapshot.SchemaVersion != "gar.paper-runtime-observation.v1" || snapshot.PairingID != runner.admission.PairingID ||
		snapshot.BootID == "" || !snapshot.Ready || snapshot.ObservedAt.IsZero() ||
		snapshot.ObservedAt.After(now.Add(2*time.Second)) || now.Sub(snapshot.ObservedAt) > 3*time.Second || snapshot.PlayerCount < 0 {
		return runtimeProbeSnapshot{}, fmt.Errorf("runtime snapshot is stale, unavailable, or belongs to another pairing")
	}
	return snapshot, nil
}

func proveConnectionAlive(connection net.Conn, duration time.Duration) error {
	deadline := time.Now().Add(duration)
	if err := connection.SetReadDeadline(deadline); err != nil {
		return err
	}
	buffer := make([]byte, 1)
	for {
		_, err := connection.Read(buffer)
		if err == nil {
			continue
		}
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			return connection.SetReadDeadline(time.Time{})
		}
		return err
	}
}

func waitForConnectionClose(connection net.Conn, timeout time.Duration) (time.Time, error) {
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return time.Time{}, err
	}
	buffer := make([]byte, 4096)
	for {
		_, err := connection.Read(buffer)
		if err == nil {
			continue
		}
		var netError net.Error
		if errors.As(err, &netError) && netError.Timeout() {
			return time.Time{}, fmt.Errorf("in-flight Minecraft login was not closed before deadline")
		}
		return time.Now().UTC(), nil
	}
}

func readBootID() (string, error) {
	payload, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", err
	}
	bootID := strings.TrimSpace(string(payload))
	if len(bootID) < 16 || len(bootID) > 128 {
		return "", fmt.Errorf("kernel boot ID is invalid")
	}
	return bootID, nil
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
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return payload, nil
}
