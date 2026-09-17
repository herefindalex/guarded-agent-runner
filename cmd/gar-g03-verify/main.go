// gar-g03-verify is an owner-local acceptance harness for the S00-S05 review
// boundary. It never replaces an artifact, starts Paper or releases writer
// ownership. Proposal and exact owner approval remain separate commands.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"guarded-agent-runner/internal/adapters/composite"
	hostadapter "guarded-agent-runner/internal/adapters/host"
	paperadapter "guarded-agent-runner/internal/adapters/paper"
	"guarded-agent-runner/internal/adapters/paperops"
	"guarded-agent-runner/internal/admission"
	"guarded-agent-runner/internal/backup"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/g03"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/runtimeconfig"
	"guarded-agent-runner/internal/store"
	"guarded-agent-runner/internal/workflow"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "prepare":
		prepare(os.Args[2:])
	case "execute":
		execute(os.Args[2:])
	default:
		usage()
	}
}

func prepare(arguments []string) {
	flags := flag.NewFlagSet("prepare", flag.ExitOnError)
	configPath := flags.String("config", "", "owner-only fixed G-03 acceptance config")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		fatal("--config is required; no extra arguments are accepted")
	}
	config, runtime, hostConfig := load(*configPath)
	database := openStore(config.DatabasePath)
	defer database.Close()

	if existing, err := database.GetIntentByClientKey(context.Background(), config.PrincipalID,
		runtime.Enrollment.EnrollmentID, config.ClientRequestID); err == nil {
		writeJSON(map[string]any{
			"intent":            existing,
			"approval_required": true,
			"approval_command": map[string]string{
				"program": "garctl", "subcommand": "intent approve", "database": config.DatabasePath,
				"intent_id": existing.Intent.IntentID, "intent_digest": existing.Intent.IntentDigest,
			},
		})
		return
	} else if domain.CodeOf(err) != domain.ErrNotFound {
		fatal(err.Error())
	}

	observer, err := hostadapter.NewObserver(hostConfig)
	must(err)
	hostSnapshot, err := observer.Observe(context.Background())
	must(err)
	must(observer.Publish(hostSnapshot))
	hostTarget, err := hostadapter.NewSnapshotTarget(hostConfig.SnapshotPath, runtime.Enrollment, runtime.Artifacts)
	must(err)
	paperTarget, err := paperadapter.NewSnapshotTarget(runtime.PaperRuntime.SnapshotPath, runtime.Enrollment)
	must(err)
	target, err := composite.New(hostTarget, paperTarget)
	must(err)

	now := time.Now().UTC()
	scope := domain.AgentSessionScope{
		SchemaVersion: "gar.agent-scope.v1", PrincipalID: config.PrincipalID,
		SessionID: domain.NewID("session"), EnrollmentID: runtime.Enrollment.EnrollmentID,
		DeploymentGeneration: runtime.Enrollment.DeploymentGeneration,
		Capabilities:         []string{"propose_plugin_change"}, PluginIDs: []string{config.PluginID},
		ArtifactProfileIDs: []string{config.ProfileID}, IssuedAt: now,
		ExpiresAt: now.Add(time.Hour), RevocationEpoch: runtime.CurrentRevocationEpoch,
	}
	must(scope.Seal())
	must(database.SaveSession(context.Background(), scope))
	service := workflow.Service{
		Store: database, Registry: runtime.Registry(), Target: target, Support: runtime.Support,
		CurrentRevocationEpoch: runtime.CurrentRevocationEpoch, Now: func() time.Time { return time.Now().UTC() },
	}
	record, err := service.ProposeG03Acceptance(context.Background(), scope, domain.ProposalInput{
		PluginID: config.PluginID, TargetArtifactID: config.TargetArtifactID,
		ClientRequestID: config.ClientRequestID,
		Rationale:       "G-03 isolated Paper graceful stop and verified offline backup acceptance; stop after S05",
	})
	must(err)
	writeJSON(map[string]any{
		"intent":            record,
		"approval_required": true,
		"approval_command": map[string]string{
			"program": "garctl", "subcommand": "intent approve", "database": config.DatabasePath,
			"intent_id": record.Intent.IntentID, "intent_digest": record.Intent.IntentDigest,
		},
		"next_boundary": "owner must independently inspect and approve the exact intent digest",
	})
}

func execute(arguments []string) {
	flags := flag.NewFlagSet("execute", flag.ExitOnError)
	configPath := flags.String("config", "", "owner-only fixed G-03 acceptance config")
	intentID := flags.String("intent-id", "", "exact independently approved intent ID")
	flags.Parse(arguments)
	if *configPath == "" || *intentID == "" || flags.NArg() != 0 {
		fatal("--config and --intent-id are required; no extra arguments are accepted")
	}
	config, runtime, hostConfig := load(*configPath)
	database := openStore(config.DatabasePath)
	defer database.Close()
	record, err := database.GetIntent(context.Background(), *intentID)
	must(err)
	if record.Status != domain.IntentConsumed {
		fatal("intent has not been independently approved and consumed")
	}
	operation, err := database.OperationForIntent(context.Background(), *intentID)
	must(err)

	observer, err := hostadapter.NewObserver(hostConfig)
	must(err)
	paperTarget, err := paperadapter.NewSnapshotTarget(runtime.PaperRuntime.SnapshotPath, runtime.Enrollment)
	must(err)
	admissionConfig, err := admission.LoadConfig(hostConfig.AdmissionBarrier.AdmissionConfigPath)
	must(err)
	liveTarget, err := paperops.New(observer, paperTarget, admissionConfig,
		runtime.Enrollment, runtime.Artifacts, config.PluginID)
	must(err)
	logicalArtifact, sourceArtifact, err := observer.ManagedPluginSource(context.Background(), config.PluginID)
	must(err)
	engine, err := backup.New(backup.Config{
		DataRoot: hostConfig.DataRootPath, Destination: config.BackupDirectory,
		SourceArtifactPath: logicalArtifact, SourceArtifactFile: sourceArtifact,
		Enrollment: runtime.Enrollment, MaxBytes: config.MaxBackupBytes, MaxFiles: config.MaxBackupFiles,
	}, database)
	must(err)
	foundation := workflow.Foundation{
		Store: database, Enrollment: runtime.Enrollment, Target: liveTarget, Backup: engine,
		EvidenceLevel: "LOCAL_PAPER", StopTimeout: config.StopTimeout(),
	}
	must(foundation.Run(context.Background(), operation.OperationID))
	backupRecord, err := engine.Inspect(context.Background(), record.Intent.ReservedBackupID)
	must(err)
	operation, err = database.GetOperation(context.Background(), operation.OperationID)
	must(err)
	if operation.Status != domain.OperationExecuting || operation.OwnershipReleased || len(operation.Attempts) != 6 {
		fatal("S05 completed without retaining the active writer boundary")
	}

	evidence := map[string]any{
		"schema_version":   "gar.g03-acceptance-evidence.v1",
		"specification":    "GAR-PCS-001@v0.1-r1",
		"evidence_level":   "LOCAL_PAPER",
		"created_at":       time.Now().UTC(),
		"source":           buildSource(),
		"intent":           record.Intent,
		"operation":        operation,
		"backup":           backupRecord,
		"boundary":         "S05_CREATE_BACKUP_COMPLETE_S06_DISABLED",
		"mutation_enabled": false,
	}
	must(writeEvidence(config.EvidencePath, evidence))
	writeJSON(map[string]any{
		"result": "PASS", "gate": "G-03", "evidence_level": "LOCAL_PAPER",
		"intent_id": record.Intent.IntentID, "operation_id": operation.OperationID,
		"backup_id": backupRecord.BackupID, "archive_sha256": backupRecord.ArchiveSHA256,
		"archive_size_bytes": backupRecord.ArchiveSizeBytes,
		"operation_status":   operation.Status, "ownership_released": operation.OwnershipReleased,
		"next_step": "STOP_AFTER_S05", "evidence_path": config.EvidencePath,
	})
}

func load(path string) (g03.Config, runtimeconfig.Config, hostadapter.ObserverConfig) {
	config, err := g03.Load(path)
	must(err)
	runtime, err := runtimeconfig.Load(config.RuntimeConfigPath)
	must(err)
	hostConfig, err := hostadapter.LoadObserverConfig(config.HostObserverConfigPath)
	must(err)
	if runtime.PaperRuntime == nil || hostConfig.AdmissionBarrier == nil ||
		runtime.Enrollment.EnrollmentID != hostConfig.EnrollmentID ||
		runtime.Enrollment.DeploymentGeneration != hostConfig.DeploymentGeneration ||
		runtime.Enrollment.ContainerID != hostConfig.ContainerID ||
		runtime.Enrollment.DataRootIdentity != hostConfig.ExpectedDataRootIdentity {
		fatal("G-03 runtime and host enrollment do not identify the same fixed target")
	}
	profile, ok := runtime.Profiles[config.ProfileID]
	if !ok || profile.Eligibility != "G03_BACKUP_ONLY" || profile.PluginID != config.PluginID ||
		profile.ToArtifactID != config.TargetArtifactID {
		fatal("G-03 config requires a G03_BACKUP_ONLY transition profile")
	}
	if runtime.Support.Mode == policy.ModeMutation || runtime.Support.Gates["G-01"] != domain.GatePass ||
		runtime.Support.Gates["G-02"] != domain.GatePass || runtime.Support.Gates["G-03"] != domain.GateNotRun ||
		runtime.Support.Gates["G-04"] != domain.GateFail {
		fatal("G-03 acceptance requires the frozen pre-run gate vector and mutation disabled")
	}
	return config, runtime, hostConfig
}

func openStore(path string) *store.Store {
	database, err := store.Open(path)
	must(err)
	return database
}

func buildSource() map[string]any {
	result := map[string]any{"commit": "UNAVAILABLE", "modified": true}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				result["commit"] = setting.Value
			case "vcs.modified":
				result["modified"] = setting.Value == "true"
			}
		}
	}
	return result
}

func writeEvidence(path string, value any) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("evidence directory must be an owner-only non-symlink directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("evidence directory ownership mismatch")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing G-03 evidence")
	} else if !os.IsNotExist(err) {
		return err
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".g03-evidence-*.tmp")
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

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatal(err.Error())
	}
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gar-g03-verify prepare|execute --config /absolute/owner/g03.json [--intent-id <id>]")
	os.Exit(2)
}
