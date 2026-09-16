package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/strictjson"
)

const ObserverConfigSchemaVersion = "gar.host-observer-config.v1"

type ObserverConfig struct {
	SchemaVersion                string                  `json:"schema_version"`
	EnrollmentID                 string                  `json:"enrollment_id"`
	DeploymentGeneration         int64                   `json:"deployment_generation"`
	ContainerID                  string                  `json:"container_id"`
	ExpectedImageID              string                  `json:"expected_image_id,omitempty"`
	DataRootPath                 string                  `json:"data_root_path"`
	ExpectedDataRootIdentity     string                  `json:"expected_data_root_identity,omitempty"`
	ExpectedBootstrapFingerprint string                  `json:"expected_bootstrap_fingerprint,omitempty"`
	ManagedPluginSlots           map[string]string       `json:"managed_plugin_slots"`
	DockerSocketPath             string                  `json:"docker_socket_path"`
	SnapshotPath                 string                  `json:"snapshot_path"`
	IntervalSeconds              int                     `json:"interval_seconds"`
	AdmissionBarrier             *AdmissionBarrierConfig `json:"admission_barrier,omitempty"`
}

type AdmissionBarrierConfig struct {
	GateContainerID          string             `json:"gate_container_id"`
	ExpectedGateImageID      string             `json:"expected_gate_image_id"`
	GateBinaryPath           string             `json:"gate_binary_path"`
	ExpectedGateBinarySHA256 string             `json:"expected_gate_binary_sha256"`
	AdmissionConfigPath      string             `json:"admission_config_path"`
	PublishedBindings        []PublishedBinding `json:"published_bindings"`
}

type PublishedBinding struct {
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"`
}

func LoadObserverConfig(path string) (ObserverConfig, error) {
	return loadObserverConfig(path, true)
}

// LoadEnrollmentConfig loads the same fixed-target schema while allowing the
// three observed identity pins to be absent. It is only for the owner-local
// enrollment-facts command; serving always uses LoadObserverConfig.
func LoadEnrollmentConfig(path string) (ObserverConfig, error) {
	return loadObserverConfig(path, false)
}

func loadObserverConfig(path string, requirePins bool) (ObserverConfig, error) {
	if err := localfile.ValidateOwnerOnlyRegular(path); err != nil {
		return ObserverConfig{}, fmt.Errorf("host observer config security check: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return ObserverConfig{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(payload) > 1<<20 {
		return ObserverConfig{}, fmt.Errorf("host observer config exceeds 1 MiB")
	}
	if err := strictjson.RejectDuplicateKeys(payload); err != nil {
		return ObserverConfig{}, fmt.Errorf("decode host observer config: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var config ObserverConfig
	if err := decoder.Decode(&config); err != nil {
		return ObserverConfig{}, fmt.Errorf("decode host observer config: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ObserverConfig{}, fmt.Errorf("host observer config contains trailing JSON")
	}
	return config, config.validate(requirePins)
}

func (config ObserverConfig) Validate() error {
	return config.validate(true)
}

func (config ObserverConfig) validate(requirePins bool) error {
	if config.SchemaVersion != ObserverConfigSchemaVersion || config.EnrollmentID == "" ||
		config.DeploymentGeneration < 1 {
		return fmt.Errorf("host observer schema and enrollment identity are required")
	}
	if len(config.ContainerID) != 64 {
		return fmt.Errorf("host observer requires a full 64-character container ID")
	}
	if _, err := hex.DecodeString(config.ContainerID); err != nil || config.ContainerID != strings.ToLower(config.ContainerID) {
		return fmt.Errorf("host observer container ID must be lowercase hexadecimal")
	}
	if requirePins && !validImageID(config.ExpectedImageID) {
		return fmt.Errorf("host observer expected_image_id must be a full sha256 image ID")
	}
	if !requirePins && config.ExpectedImageID != "" && !validImageID(config.ExpectedImageID) {
		return fmt.Errorf("host observer expected_image_id must be empty or a full sha256 image ID")
	}
	if requirePins && config.ExpectedDataRootIdentity == "" {
		return fmt.Errorf("host observer expected_data_root_identity is required")
	}
	if requirePins && !validSHA256(config.ExpectedBootstrapFingerprint) {
		return fmt.Errorf("host observer expected_bootstrap_fingerprint must be a full SHA-256")
	}
	if !requirePins && config.ExpectedBootstrapFingerprint != "" && !validSHA256(config.ExpectedBootstrapFingerprint) {
		return fmt.Errorf("host observer expected_bootstrap_fingerprint must be empty or a full SHA-256")
	}
	for _, path := range []string{config.DataRootPath, config.DockerSocketPath, config.SnapshotPath} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("host observer paths must be clean and absolute")
		}
	}
	if within(config.SnapshotPath, config.DataRootPath) {
		return fmt.Errorf("host snapshot must be outside the Paper data root")
	}
	if config.IntervalSeconds < 1 || config.IntervalSeconds > 5 {
		return fmt.Errorf("host observer interval_seconds must be from 1 through 5")
	}
	for pluginID, fileName := range config.ManagedPluginSlots {
		if pluginID == "" || len(pluginID) > 128 || !safeBaseName(fileName) {
			return fmt.Errorf("managed plugin slots require bounded IDs and basenames")
		}
	}
	if barrier := config.AdmissionBarrier; barrier != nil {
		if len(barrier.GateContainerID) != 64 || barrier.GateContainerID == config.ContainerID {
			return fmt.Errorf("admission barrier requires a distinct full gate container ID")
		}
		if _, err := hex.DecodeString(barrier.GateContainerID); err != nil ||
			barrier.GateContainerID != strings.ToLower(barrier.GateContainerID) ||
			!validImageID(barrier.ExpectedGateImageID) {
			return fmt.Errorf("admission barrier container and image identities are invalid")
		}
		if barrier.GateBinaryPath == "" || !filepath.IsAbs(barrier.GateBinaryPath) ||
			filepath.Clean(barrier.GateBinaryPath) != barrier.GateBinaryPath ||
			!validSHA256(barrier.ExpectedGateBinarySHA256) {
			return fmt.Errorf("admission barrier binary path and digest are invalid")
		}
		if barrier.AdmissionConfigPath == "" || !filepath.IsAbs(barrier.AdmissionConfigPath) ||
			filepath.Clean(barrier.AdmissionConfigPath) != barrier.AdmissionConfigPath {
			return fmt.Errorf("admission barrier config path must be clean and absolute")
		}
		if len(barrier.PublishedBindings) < 1 || len(barrier.PublishedBindings) > 8 {
			return fmt.Errorf("admission barrier requires one through eight fixed published bindings")
		}
		seenBindings := make(map[string]struct{}, len(barrier.PublishedBindings))
		for _, binding := range barrier.PublishedBindings {
			ip := net.ParseIP(binding.HostIP)
			if ip == nil || !ip.IsLoopback() || binding.HostPort < 1 || binding.HostPort > 65535 ||
				binding.ContainerPort < 1 || binding.ContainerPort > 65535 || binding.Protocol != "tcp" {
				return fmt.Errorf("admission published bindings must be fixed loopback TCP ports")
			}
			key := bindingKey(binding)
			if _, exists := seenBindings[key]; exists {
				return fmt.Errorf("duplicate admission published binding")
			}
			seenBindings[key] = struct{}{}
		}
	}
	fileNames := make(map[string]struct{}, len(config.ManagedPluginSlots))
	for _, fileName := range config.ManagedPluginSlots {
		if _, exists := fileNames[fileName]; exists {
			return fmt.Errorf("managed plugin filenames must be unique")
		}
		fileNames[fileName] = struct{}{}
	}
	return nil
}

type Observer struct {
	config    ObserverConfig
	client    *http.Client
	now       func() time.Time
	admission *admission.Config
}

func NewObserver(config ObserverConfig) (*Observer, error) {
	return newObserver(config, true)
}

// NewEnrollmentObserver creates a read-only observer that can derive the
// missing image/data/bootstrap pins for initial owner enrollment.
func NewEnrollmentObserver(config ObserverConfig) (*Observer, error) {
	return newObserver(config, false)
}

func newObserver(config ObserverConfig, requirePins bool) (*Observer, error) {
	if err := config.validate(requirePins); err != nil {
		return nil, err
	}
	if err := validateDockerSocket(config.DockerSocketPath); err != nil {
		return nil, err
	}
	if err := validateOutputDirectory(filepath.Dir(config.SnapshotPath)); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, "unix", config.DockerSocketPath)
		},
	}
	var admissionConfig *admission.Config
	if config.AdmissionBarrier != nil {
		loaded, err := admission.LoadConfig(config.AdmissionBarrier.AdmissionConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load admission barrier config: %w", err)
		}
		if loaded.DeploymentGeneration != config.DeploymentGeneration {
			return nil, fmt.Errorf("admission barrier deployment generation mismatch")
		}
		admissionConfig = &loaded
	}
	return &Observer{
		config:    config,
		client:    &http.Client{Transport: transport, Timeout: 3 * time.Second},
		now:       time.Now,
		admission: admissionConfig,
	}, nil
}

func (observer *Observer) SetClockForTest(now func() time.Time) { observer.now = now }

func (observer *Observer) Observe(ctx context.Context) (Snapshot, error) {
	now := observer.now().UTC()
	inspection, err := observer.inspectContainer(ctx)
	if err != nil {
		return observer.unavailable(now, "DOCKER_INSPECT_UNAVAILABLE"), err
	}
	if inspection.ID != observer.config.ContainerID {
		return observer.unavailable(now, "CONTAINER_ID_MISMATCH"), fmt.Errorf("container ID mismatch")
	}
	if !inspection.State.Running || inspection.State.Status != "running" {
		return observer.unavailable(now, "CONTAINER_NOT_RUNNING"), fmt.Errorf("container is not running")
	}
	if inspection.State.Health != nil && inspection.State.Health.Status == "unhealthy" {
		return observer.unavailable(now, "CONTAINER_UNHEALTHY"), fmt.Errorf("container is unhealthy")
	}
	if inspection.HostConfig.RestartPolicy.Name != "no" {
		return observer.unavailable(now, "RESTART_POLICY_MISMATCH"), fmt.Errorf("container restart policy is not 'no'")
	}
	dataIdentity, err := dataRootIdentity(observer.config.DataRootPath)
	if err != nil {
		return observer.unavailable(now, "DATA_ROOT_UNAVAILABLE"), err
	}
	fingerprint, competing, err := bootstrapFingerprint(inspection)
	if err != nil {
		return observer.unavailable(now, "BOOTSTRAP_FINGERPRINT_UNAVAILABLE"), err
	}
	if len(competing) != 0 {
		return observer.unavailable(now, "COMPETING_STARTUP_WRITERS"), fmt.Errorf("competing startup writers are configured")
	}
	if observer.config.ExpectedImageID != "" && inspection.Image != observer.config.ExpectedImageID {
		return observer.unavailable(now, "IMAGE_ID_MISMATCH"), fmt.Errorf("image ID mismatch")
	}
	if observer.config.ExpectedDataRootIdentity != "" && dataIdentity != observer.config.ExpectedDataRootIdentity {
		return observer.unavailable(now, "DATA_ROOT_IDENTITY_MISMATCH"), fmt.Errorf("data root identity mismatch")
	}
	if observer.config.ExpectedBootstrapFingerprint != "" && fingerprint != observer.config.ExpectedBootstrapFingerprint {
		return observer.unavailable(now, "BOOTSTRAP_FINGERPRINT_MISMATCH"), fmt.Errorf("bootstrap fingerprint mismatch")
	}
	if !hasExpectedDataMount(inspection.Mounts, observer.config.DataRootPath) {
		return observer.unavailable(now, "DATA_MOUNT_MISMATCH"), fmt.Errorf("container /data mount mismatch")
	}
	plugins, err := observePluginArtifacts(observer.config.DataRootPath, observer.config.ManagedPluginSlots, inspection.Mounts)
	if err != nil {
		return observer.unavailable(now, "PLUGIN_ATTRIBUTION_UNAVAILABLE"), err
	}
	inventoryDigest, err := domain.Digest(plugins)
	if err != nil {
		return observer.unavailable(now, "INVENTORY_DIGEST_UNAVAILABLE"), err
	}
	diskFree, err := diskFreeBytes(observer.config.DataRootPath)
	if err != nil {
		return observer.unavailable(now, "DISK_OBSERVATION_UNAVAILABLE"), err
	}
	recentErrors, errorCursor, recentErrorAvailability, recentErrorReason := readRecentErrors(observer.config.DataRootPath)
	admissionAvailability := domain.Unavailable
	admissionReason := "ADMISSION_BARRIER_NOT_CONFIGURED"
	admissionOpen := false
	admissionGateContainerID := ""
	admissionBindings := []PublishedBinding{}
	if observer.config.AdmissionBarrier != nil {
		barrier := observer.config.AdmissionBarrier
		gateInspection, inspectErr := observer.inspectContainerID(ctx, barrier.GateContainerID)
		if inspectErr != nil {
			return observer.unavailable(now, "ADMISSION_BARRIER_UNAVAILABLE"), inspectErr
		}
		if err := validateAdmissionBarrier(inspection, gateInspection, *barrier, *observer.admission); err != nil {
			return observer.unavailable(now, "ADMISSION_BARRIER_UNAVAILABLE"), err
		}
		decision := admission.EvaluateAccess(*observer.admission, now)
		admissionAvailability = domain.Available
		admissionReason = decision.ReasonCode
		admissionOpen = decision.Open
		admissionGateContainerID = gateInspection.ID
		admissionBindings = append(admissionBindings, barrier.PublishedBindings...)
	}
	health := "UNAVAILABLE"
	if inspection.State.Health != nil && inspection.State.Health.Status != "" {
		health = inspection.State.Health.Status
	}
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion, Availability: domain.Available,
		ObservedAt: now, EnrollmentID: observer.config.EnrollmentID,
		DeploymentGeneration: observer.config.DeploymentGeneration,
		ContainerID:          inspection.ID, ImageID: inspection.Image,
		ContainerStatus: inspection.State.Status, Running: inspection.State.Running,
		HealthStatus: health, RestartPolicy: inspection.HostConfig.RestartPolicy.Name,
		DataRootIdentity: dataIdentity, BootstrapFingerprint: fingerprint,
		InventoryDigest: inventoryDigest, PluginArtifacts: plugins,
		CompetingStartupWriters: competing, DiskFreeBytes: diskFree,
		RecentErrorsAvailability: recentErrorAvailability, RecentErrorsReasonCode: recentErrorReason,
		ErrorCursor: errorCursor, RecentErrors: recentErrors,
		AdmissionBarrierAvailability: admissionAvailability,
		AdmissionBarrierReasonCode:   admissionReason,
		AdmissionOpen:                admissionOpen, AdmissionGateContainerID: admissionGateContainerID,
		AdmissionPublishedBindings: admissionBindings,
	}, nil
}

func (observer *Observer) Publish(snapshot Snapshot) error {
	directory := filepath.Dir(observer.config.SnapshotPath)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gar-host-snapshot-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o640); err != nil {
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
	if err := os.Rename(temporaryPath, observer.config.SnapshotPath); err != nil {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func (observer *Observer) Run(ctx context.Context) error {
	interval := time.Duration(observer.config.IntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		snapshot, observeErr := observer.Observe(ctx)
		if publishErr := observer.Publish(snapshot); publishErr != nil {
			return publishErr
		}
		if observeErr != nil {
			// The bounded unavailable snapshot is the public result. Continue
			// probing so transient Docker/read errors can recover.
			fmt.Fprintf(os.Stderr, "gar-host observation unavailable: %s\n", snapshot.ReasonCode)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (observer *Observer) unavailable(now time.Time, reason string) Snapshot {
	return Snapshot{
		SchemaVersion: SnapshotSchemaVersion, Availability: domain.Unavailable,
		ReasonCode: reason, ObservedAt: now,
		EnrollmentID:         observer.config.EnrollmentID,
		DeploymentGeneration: observer.config.DeploymentGeneration,
	}
}

type dockerInspection struct {
	ID     string `json:"Id"`
	Image  string `json:"Image"`
	Config struct {
		Image      string            `json:"Image"`
		Env        []string          `json:"Env"`
		Cmd        []string          `json:"Cmd"`
		Entrypoint []string          `json:"Entrypoint"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Health  *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		NetworkMode    string   `json:"NetworkMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Mounts []dockerMount `json:"Mounts"`
}

type dockerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

func (observer *Observer) inspectContainer(ctx context.Context) (dockerInspection, error) {
	return observer.inspectContainerID(ctx, observer.config.ContainerID)
}

func (observer *Observer) inspectContainerID(ctx context.Context, containerID string) (dockerInspection, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/containers/"+containerID+"/json", nil)
	if err != nil {
		return dockerInspection{}, err
	}
	response, err := observer.client.Do(request)
	if err != nil {
		return dockerInspection{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return dockerInspection{}, fmt.Errorf("Docker inspect returned status %d", response.StatusCode)
	}
	// Docker adds fields across API versions, so decode through a raw map first
	// is not appropriate here. Unknown response fields are expected; typed fields
	// below are the only ones trusted.
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	var inspection dockerInspection
	if err := decoder.Decode(&inspection); err != nil {
		return dockerInspection{}, err
	}
	return inspection, nil
}

func validateAdmissionBarrier(
	paper, gate dockerInspection,
	config AdmissionBarrierConfig,
	admissionConfig admission.Config,
) error {
	if gate.ID != config.GateContainerID || gate.Image != config.ExpectedGateImageID ||
		!gate.State.Running || gate.State.Status != "running" || gate.HostConfig.RestartPolicy.Name != "no" {
		return fmt.Errorf("admission gate lifecycle or identity mismatch")
	}
	if gate.HostConfig.NetworkMode != "container:"+paper.ID || !gate.HostConfig.ReadonlyRootfs ||
		!containsString(gate.HostConfig.CapDrop, "ALL") {
		return fmt.Errorf("admission gate isolation mismatch")
	}
	if !containsString(gate.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!equalStrings(gate.Config.Entrypoint, []string{"/gar-gate"}) ||
		!equalStrings(gate.Config.Cmd, []string{"serve", "--config", config.AdmissionConfigPath}) {
		return fmt.Errorf("admission gate command or security options mismatch")
	}
	for _, mount := range gate.Mounts {
		if mount.Destination == "/var/run/docker.sock" || mount.Destination == "/run/docker.sock" {
			return fmt.Errorf("admission gate must not receive Docker socket")
		}
	}
	digest, err := hashGateBinary(config.GateBinaryPath)
	if err != nil || digest != config.ExpectedGateBinarySHA256 {
		return fmt.Errorf("admission gate binary attribution mismatch")
	}
	if !hasExactReadonlyBind(gate.Mounts, config.GateBinaryPath, "/gar-gate") {
		return fmt.Errorf("admission gate binary mount mismatch")
	}
	for _, requiredPath := range []string{
		config.AdmissionConfigPath,
		admissionConfig.StatePath,
		admissionConfig.RuntimeSnapshotPath,
	} {
		if !hasReadonlyMirroredMount(gate.Mounts, requiredPath) {
			return fmt.Errorf("admission gate evidence mount mismatch")
		}
	}
	actual := make(map[string]struct{})
	for containerPort, bindings := range paper.NetworkSettings.Ports {
		port, protocol, ok := strings.Cut(containerPort, "/")
		if !ok {
			return fmt.Errorf("invalid Docker published port")
		}
		containerPortNumber, err := strconv.Atoi(port)
		if err != nil {
			return fmt.Errorf("invalid Docker container port")
		}
		for _, binding := range bindings {
			hostPort, err := strconv.Atoi(binding.HostPort)
			if err != nil {
				return fmt.Errorf("invalid Docker host port")
			}
			actual[bindingKey(PublishedBinding{HostIP: binding.HostIP, HostPort: hostPort, ContainerPort: containerPortNumber, Protocol: protocol})] = struct{}{}
		}
	}
	if len(actual) != len(config.PublishedBindings) {
		return fmt.Errorf("Paper published port set does not match admission enrollment")
	}
	for _, expected := range config.PublishedBindings {
		if _, exists := actual[bindingKey(expected)]; !exists {
			return fmt.Errorf("Paper published binding does not match admission enrollment")
		}
	}
	return nil
}

func bindingKey(binding PublishedBinding) string {
	return fmt.Sprintf("%s:%d->%d/%s", binding.HostIP, binding.HostPort, binding.ContainerPort, binding.Protocol)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasExactReadonlyBind(mounts []dockerMount, source, destination string) bool {
	for _, mount := range mounts {
		if mount.Type == "bind" && mount.Source == source && mount.Destination == destination && !mount.RW {
			return true
		}
	}
	return false
}

func hasReadonlyMirroredMount(mounts []dockerMount, path string) bool {
	for _, mount := range mounts {
		if mount.Type != "bind" || mount.RW || mount.Source != mount.Destination {
			continue
		}
		relative, err := filepath.Rel(mount.Source, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func hashGateBinary(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	digest, _, err := hashBoundedPlugin(file)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func bootstrapFingerprint(inspection dockerInspection) (string, []string, error) {
	environment := append([]string(nil), inspection.Config.Env...)
	sort.Strings(environment)
	mounts := append([]dockerMount(nil), inspection.Mounts...)
	sort.Slice(mounts, func(left, right int) bool { return mounts[left].Destination < mounts[right].Destination })
	competing := competingWriters(environment)
	digest, err := domain.Digest(struct {
		ImageID       string            `json:"image_id"`
		ImageRef      string            `json:"image_ref"`
		Environment   []string          `json:"environment"`
		Command       []string          `json:"command"`
		Entrypoint    []string          `json:"entrypoint"`
		Labels        map[string]string `json:"labels"`
		RestartPolicy string            `json:"restart_policy"`
		Mounts        []dockerMount     `json:"mounts"`
	}{
		inspection.Image, inspection.Config.Image, environment, inspection.Config.Cmd,
		inspection.Config.Entrypoint, inspection.Config.Labels,
		inspection.HostConfig.RestartPolicy.Name, mounts,
	})
	return digest, competing, err
}

func competingWriters(environment []string) []string {
	blocked := map[string]struct{}{
		"PLUGINS": {}, "PLUGINS_FILE": {}, "COPY_PLUGINS_SRC": {},
		"MODRINTH_PROJECTS": {}, "SPIGET_RESOURCES": {}, "CURSEFORGE_FILES": {},
		"CF_SERVER_MOD": {}, "PACKWIZ_URL": {}, "AUTO_CURSEFORGE": {},
		"REMOVE_OLD_MODS": {}, "RESTART_ON_CRASH": {},
	}
	var found []string
	hasPinnedDefaultConfigPolicy := false
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		if _, blockedKey := blocked[key]; blockedKey {
			found = append(found, key)
		}
		if (key == "ENABLE_AUTOPAUSE" || key == "ENABLE_AUTOSTOP") && !strings.HasSuffix(strings.ToUpper(entry), "=FALSE") {
			found = append(found, key)
		}
		if key == "SKIP_DOWNLOAD_DEFAULTS" {
			hasPinnedDefaultConfigPolicy = value == "TRUE"
			if !hasPinnedDefaultConfigPolicy {
				found = append(found, key)
			}
		}
	}
	if !hasPinnedDefaultConfigPolicy {
		found = append(found, "SKIP_DOWNLOAD_DEFAULTS")
	}
	sort.Strings(found)
	return compactStrings(found)
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func observePluginArtifacts(dataRoot string, slots map[string]string, mounts []dockerMount) ([]PluginArtifact, error) {
	root, err := openDirectoryNoFollow(dataRoot)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	pluginsDirectory, err := unix.Openat(root, "plugins", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if len(slots) == 0 && err == unix.ENOENT {
			return []PluginArtifact{}, nil
		}
		return nil, err
	}
	pluginsFile := os.NewFile(uintptr(pluginsDirectory), "plugins")
	defer pluginsFile.Close()
	allowedFiles := make(map[string]struct{}, len(slots))
	for _, fileName := range slots {
		allowedFiles[fileName] = struct{}{}
	}
	names, err := pluginsFile.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if strings.EqualFold(filepath.Ext(name), ".jar") {
			if _, allowed := allowedFiles[name]; !allowed {
				return nil, fmt.Errorf("unregistered plugin JAR exists in data root")
			}
		}
	}
	for _, mount := range mounts {
		name, pluginMount := pluginMountName(mount.Destination)
		if pluginMount && strings.EqualFold(filepath.Ext(name), ".jar") {
			if _, allowed := allowedFiles[name]; !allowed {
				return nil, fmt.Errorf("unregistered plugin JAR is mounted into container")
			}
		}
	}
	pluginIDs := make([]string, 0, len(slots))
	for pluginID := range slots {
		pluginIDs = append(pluginIDs, pluginID)
	}
	sort.Strings(pluginIDs)
	artifacts := make([]PluginArtifact, 0, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		fileName := slots[pluginID]
		file, err := openPluginArtifact(int(pluginsFile.Fd()), fileName, mounts)
		if err != nil {
			return nil, err
		}
		digest, size, err := hashBoundedPlugin(file)
		file.Close()
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, PluginArtifact{
			PluginID: pluginID, SHA256: digest, Size: size,
		})
	}
	return artifacts, nil
}

func openPluginArtifact(pluginsDirectory int, fileName string, mounts []dockerMount) (*os.File, error) {
	for _, mount := range mounts {
		name, pluginMount := pluginMountName(mount.Destination)
		if !pluginMount || name != fileName {
			continue
		}
		resolved, err := filepath.EvalSymlinks(mount.Source)
		if err != nil || resolved != mount.Source {
			return nil, fmt.Errorf("mounted plugin source is unavailable or traverses a symlink")
		}
		descriptor, err := unix.Open(mount.Source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(descriptor), fileName), nil
	}
	descriptor, err := unix.Openat(pluginsDirectory, fileName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), fileName), nil
}

func pluginMountName(destination string) (string, bool) {
	const prefix = "/data/plugins/"
	if !strings.HasPrefix(destination, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(destination, prefix)
	return name, safeBaseName(name)
}

func hashBoundedPlugin(file *os.File) (string, int64, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 100<<20 {
		return "", 0, fmt.Errorf("managed plugin artifact is missing, non-regular, or oversized")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, (100<<20)+1)); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), info.Size(), nil
}

func readRecentErrors(dataRoot string) ([]string, string, domain.Availability, string) {
	root, err := openDirectoryNoFollow(dataRoot)
	if err != nil {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	defer unix.Close(root)
	logsDirectory, err := unix.Openat(root, "logs", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	defer unix.Close(logsDirectory)
	descriptor, err := unix.Openat(logsDirectory, "latest.log", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	file := os.NewFile(uintptr(descriptor), "latest.log")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_IDENTITY_UNAVAILABLE"
	}
	cursorPayload := fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, info.Size())
	cursorDigest := sha256.Sum256([]byte(cursorPayload))
	cursor := hex.EncodeToString(cursorDigest[:])
	const tailBytes = int64(256 * 1024)
	start := info.Size() - tailBytes
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	payload, err := io.ReadAll(io.LimitReader(file, tailBytes))
	if err != nil {
		return []string{}, "", domain.Unavailable, "PAPER_LOG_UNAVAILABLE"
	}
	lines := strings.Split(string(payload), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	result := make([]string, 0, 50)
	for _, line := range lines {
		if strings.Contains(line, "[ERROR]") || strings.Contains(line, "Exception") || strings.Contains(line, "SEVERE") {
			result = append(result, fingerprintLogLine(line))
			if len(result) > 200 {
				result = result[len(result)-200:]
			}
		}
	}
	return result, cursor, domain.Available, ""
}

func fingerprintLogLine(line string) string {
	line = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) && character != '\t' {
			return -1
		}
		return character
	}, line)
	digest := sha256.Sum256([]byte(line))
	category := "PAPER_ERROR"
	if strings.Contains(line, "Exception") {
		category = "PAPER_EXCEPTION"
	} else if strings.Contains(line, "SEVERE") {
		category = "PAPER_SEVERE"
	}
	return category + " sha256:" + hex.EncodeToString(digest[:])
}

func openDirectoryNoFollow(path string) (int, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return -1, fmt.Errorf("data root is unavailable or traverses a symlink")
	}
	return unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func dataRootIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("data root must be a non-symlink directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("cannot determine data root identity")
	}
	return fmt.Sprintf("dev:%d/inode:%d", stat.Dev, stat.Ino), nil
}

func diskFreeBytes(path string) (uint64, error) {
	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return 0, err
	}
	return stats.Bavail * uint64(stats.Bsize), nil
}

func hasExpectedDataMount(mounts []dockerMount, dataRoot string) bool {
	for _, mount := range mounts {
		if mount.Destination == "/data" && mount.RW && filepath.Clean(mount.Source) == dataRoot {
			return true
		}
	}
	return false
}

func validateDockerSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("Docker endpoint must be a fixed non-symlink Unix socket")
	}
	return nil
}

func validateOutputDirectory(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("host snapshot directory must exist and contain no symlink traversal")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("host snapshot directory must be an existing directory")
	}
	return nil
}

func safeBaseName(name string) bool {
	return name != "" && len(name) <= 128 && filepath.Base(name) == name && name != "." && name != ".." &&
		!strings.ContainsRune(name, os.PathSeparator)
}

func validImageID(value string) bool {
	return strings.HasPrefix(value, "sha256:") && validSHA256(strings.TrimPrefix(value, "sha256:"))
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func within(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}
