package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	hostadapter "guarded-agent-runner/internal/adapters/host"
	paperadapter "guarded-agent-runner/internal/adapters/paper"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/localfile"
	"guarded-agent-runner/internal/mcpserver"
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
	case "doctor":
		doctor(os.Args[2:])
	case "backup":
		if len(os.Args) < 3 || os.Args[2] != "show" {
			usage()
		}
		backupShow(os.Args[3:])
	case "agent":
		if len(os.Args) < 3 || os.Args[2] != "issue" {
			usage()
		}
		agentIssue(os.Args[3:])
	case "intent":
		if len(os.Args) < 3 {
			usage()
		}
		switch os.Args[2] {
		case "show":
			intentShow(os.Args[3:])
		case "approve":
			intentApprove(os.Args[3:])
		case "reject":
			intentReject(os.Args[3:])
		case "revoke":
			intentRevoke(os.Args[3:])
		default:
			usage()
		}
	case "operation":
		if len(os.Args) < 3 || os.Args[2] != "show" {
			usage()
		}
		operationShow(os.Args[3:])
	// M1 aliases remain for local scripts created before CLI grouping matched
	// GAR-PCS-001 section 9.2.
	case "intent-show":
		intentShow(os.Args[2:])
	case "intent-approve":
		intentApprove(os.Args[2:])
	case "intent-reject":
		intentReject(os.Args[2:])
	case "intent-revoke":
		intentRevoke(os.Args[2:])
	case "operation-show":
		operationShow(os.Args[2:])
	default:
		usage()
	}
}

type doctorCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func doctor(arguments []string) {
	flags := flag.NewFlagSet("doctor", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	configPath := flags.String("config", os.Getenv("GAR_CONFIG"), "owner-only fixed enrollment/registry JSON")
	credentialPath := flags.String("credentials", os.Getenv("GAR_CREDENTIALS"), "owner-only hashed agent credential JSON")
	listenAddress := flags.String("listen", envOr("GAR_LISTEN", "127.0.0.1:8787"), "literal loopback listen address")
	allowedOrigin := flags.String("allowed-origin", os.Getenv("GAR_ALLOWED_ORIGIN"), "exact allowed browser Origin")
	flags.Parse(arguments)

	database := mustOpen(*databasePath)
	defer database.Close()
	settings, err := database.JournalSettings(context.Background())
	must(err)
	name, uid := localIdentity()
	checks := map[string]doctorCheck{
		"database_owner_only": checkError(localfile.ValidateOwnerOnlyRegular(*databasePath), "database is regular, non-symlink, owner-only, and owned by current user"),
		"loopback_listener":   checkError(mcpserver.ValidateListenAddress(*listenAddress), "listener uses a literal loopback IP"),
		"origin_validation":   checkOrigin(*allowedOrigin),
		"runtime_config":      {Status: "NOT_CONFIGURED", Detail: "--config is required for MCP serving"},
		"paper_runtime":       {Status: "NOT_CONFIGURED", Detail: "paper_runtime.snapshot_path is not configured"},
		"host_observation":    {Status: "NOT_CONFIGURED", Detail: "host_observation.snapshot_path is not configured"},
		"agent_credentials":   {Status: "NOT_CONFIGURED", Detail: "--credentials is required for MCP serving"},
		"docker_host_env":     {Status: "PASS", Detail: "DOCKER_HOST is absent"},
		"docker_socket":       dockerSocketCheck(),
	}
	if os.Getenv("DOCKER_HOST") != "" {
		checks["docker_host_env"] = doctorCheck{Status: "FAIL", Detail: "DOCKER_HOST is present; run GAR under a service identity without Docker authority"}
	}

	var config runtimeconfig.Config
	configOK := false
	paperReady := false
	hostReady := false
	if *configPath != "" {
		loaded, loadErr := runtimeconfig.Load(*configPath)
		checks["runtime_config"] = checkError(loadErr, "runtime config is strict, owner-only, and fixed to one enrollment")
		if loadErr == nil {
			config, configOK = loaded, true
			if config.HostObservation != nil {
				target, targetErr := hostadapter.NewSnapshotTarget(config.HostObservation.SnapshotPath, config.Enrollment, config.Artifacts)
				if targetErr == nil {
					var bundle domain.ObservationBundle
					bundle, targetErr = target.Observe(context.Background(), config.Enrollment)
					if targetErr == nil && (bundle.InventoryDigest == "" || bundle.ConfigDigest == "") {
						targetErr = fmt.Errorf("host observation lacks fixed inventory or bootstrap evidence")
					}
				}
				checks["host_observation"] = checkError(targetErr, "fresh fixed-target host snapshot is available")
				hostReady = targetErr == nil
			}
			if config.PaperRuntime != nil {
				target, targetErr := paperadapter.NewSnapshotTarget(config.PaperRuntime.SnapshotPath, config.Enrollment)
				if targetErr == nil {
					var bundle domain.ObservationBundle
					bundle, targetErr = target.Observe(context.Background(), config.Enrollment)
					if targetErr == nil {
						players := bundle.Readings["players"]
						guard := bundle.Readings["guard_ready"]
						if players.Availability != domain.Available || guard.Availability != domain.Available || guard.Value != true {
							targetErr = fmt.Errorf("Paper guard observation is stale or not ready")
						}
					}
				}
				checks["paper_runtime"] = checkError(targetErr, "fresh paired Paper guard snapshot is available")
				paperReady = targetErr == nil
			}
		}
	}
	credentialOK := false
	credentialCount := 0
	if *credentialPath != "" {
		credentials, loadErr := mcpserver.LoadCredentials(*credentialPath)
		if loadErr == nil && configOK {
			loadErr = credentials.ValidateSessions(context.Background(), database,
				config.Enrollment.EnrollmentID, config.Enrollment.DeploymentGeneration,
				config.CurrentRevocationEpoch, time.Now().UTC())
		}
		checks["agent_credentials"] = checkError(loadErr, "all hashed bearer mappings resolve to current fixed session scopes")
		if loadErr == nil {
			credentialOK = true
			credentials, _ := mcpserver.LoadCredentials(*credentialPath)
			credentialCount = credentials.Len()
		}
	}
	mcpReady := configOK && credentialOK && hostReady && paperReady
	for _, name := range []string{"database_owner_only", "loopback_listener", "origin_validation", "docker_host_env", "docker_socket"} {
		mcpReady = mcpReady && checks[name].Status == "PASS"
	}
	profile := policy.DefaultM1Profile()
	if configOK {
		profile = config.Support
	}
	writeJSON(map[string]any{
		"specification":            "GAR-PCS-001@v0.1-r1",
		"milestone":                "M2_MCP_TRANSPORT_READ_ONLY_ALPHA",
		"current_user":             map[string]any{"name": name, "uid": uid},
		"journal":                  settings,
		"checks":                   checks,
		"credential_count":         credentialCount,
		"mcp_ready":                mcpReady,
		"paper_observations_ready": paperReady,
		"host_observations_ready":  hostReady,
		"support_profile":          profile,
		"mutation_enabled":         false,
		"blocking_reason":          "mutation is hard-disabled; the configured support profile has non-PASS gates and the M4 executor is absent",
	})
}

func checkOrigin(origin string) doctorCheck {
	if origin == "" {
		return doctorCheck{Status: "NOT_CONFIGURED", Detail: "an exact allowed Origin is required"}
	}
	_, err := mcpserver.ValidateAllowedOrigin(origin)
	return checkError(err, "exact HTTP(S) Origin is configured")
}

func dockerSocketCheck() doctorCheck {
	const socket = "/var/run/docker.sock"
	if _, err := os.Lstat(socket); os.IsNotExist(err) {
		return doctorCheck{Status: "PASS", Detail: "default Docker socket is absent"}
	}
	if err := unix.Access(socket, unix.R_OK|unix.W_OK); err == nil {
		return doctorCheck{Status: "FAIL", Detail: "current GAR user can access /var/run/docker.sock; use an isolated service identity"}
	}
	return doctorCheck{Status: "PASS", Detail: "current GAR user cannot read or write the default Docker socket"}
}

func checkError(err error, passDetail string) doctorCheck {
	if err != nil {
		return doctorCheck{Status: "FAIL", Detail: err.Error()}
	}
	return doctorCheck{Status: "PASS", Detail: passDetail}
}

func agentIssue(arguments []string) {
	flags := flag.NewFlagSet("agent issue", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	configPath := flags.String("config", "", "owner-only fixed enrollment/registry JSON")
	credentialOutput := flags.String("credentials-out", "", "new owner-only hashed credential registry")
	tokenOutput := flags.String("token-out", "", "new owner-only one-time bearer token file")
	principalID := flags.String("principal", "", "fixed agent principal ID")
	ttl := flags.Duration("ttl", time.Hour, "session lifetime from 5m through 24h")
	flags.Parse(arguments)
	if *configPath == "" || *credentialOutput == "" || *tokenOutput == "" || *principalID == "" {
		fatal("--config, --credentials-out, --token-out, and --principal are required")
	}
	if *credentialOutput == *tokenOutput {
		fatal("--credentials-out and --token-out must be different files")
	}
	if len(*principalID) > 128 {
		fatal("--principal exceeds 128 bytes")
	}
	if *ttl < 5*time.Minute || *ttl > 24*time.Hour {
		fatal("--ttl must be from 5m through 24h")
	}
	for _, path := range []string{*credentialOutput, *tokenOutput} {
		if _, err := os.Lstat(path); err == nil {
			fatal("refusing to overwrite existing output file: " + path)
		} else if !os.IsNotExist(err) {
			must(err)
		}
	}
	config, err := runtimeconfig.Load(*configPath)
	must(err)
	now := time.Now().UTC()
	profileIDs := make([]string, 0, len(config.Profiles))
	for _, profile := range config.Profiles {
		if profile.Eligibility == "VERIFIED_TRANSITION" && contains(config.Enrollment.AllowedPlugins, profile.PluginID) {
			profileIDs = append(profileIDs, profile.ProfileID)
		}
	}
	scope := domain.AgentSessionScope{
		SchemaVersion: "gar.agent-scope.v1", PrincipalID: *principalID,
		SessionID: domain.NewID("session"), EnrollmentID: config.Enrollment.EnrollmentID,
		DeploymentGeneration: config.Enrollment.DeploymentGeneration,
		Capabilities:         toolNames(), PluginIDs: append([]string(nil), config.Enrollment.AllowedPlugins...),
		ArtifactProfileIDs: profileIDs, IssuedAt: now, ExpiresAt: now.Add(*ttl),
		RevocationEpoch: config.CurrentRevocationEpoch,
	}
	must(scope.Seal())
	tokenBytes := make([]byte, 32)
	_, err = rand.Read(tokenBytes)
	must(err)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenDigest := sha256.Sum256([]byte(token))
	credentialFile := mcpserver.CredentialFile{
		SchemaVersion: mcpserver.CredentialSchemaVersion,
		Credentials: []mcpserver.CredentialRecord{{
			CredentialID: domain.NewID("credential"), TokenSHA256: hex.EncodeToString(tokenDigest[:]),
			SessionID: scope.SessionID,
		}},
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	must(database.SaveSession(context.Background(), scope))
	if err := writeNewFile(*credentialOutput, credentialFile); err != nil {
		fatal(err.Error())
	}
	if err := writeNewTokenFile(*tokenOutput, token); err != nil {
		_ = os.Remove(*credentialOutput)
		fatal(err.Error())
	}
	writeJSON(map[string]any{
		"principal_id": scope.PrincipalID, "session_id": scope.SessionID,
		"scope_digest": scope.ScopeDigest, "expires_at": scope.ExpiresAt,
		"credentials_file_created": *credentialOutput, "token_file_created": *tokenOutput,
		"note": "the raw bearer exists only in token-out; approval remains owner-local",
	})
}

func writeNewFile(path string, value any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func writeNewTokenFile(path, token string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, token); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func toolNames() []string {
	names := make([]string, 0, len(domain.AgentTools))
	for _, tool := range domain.AgentTools {
		names = append(names, tool.Name)
	}
	return names
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func intentShow(arguments []string) {
	flags := flag.NewFlagSet("intent show", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	intentID := flags.String("id", "", "exact intent ID")
	flags.Parse(arguments)
	if *intentID == "" {
		fatal("--id is required")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	record, err := database.GetIntent(context.Background(), *intentID)
	must(err)
	writeJSON(record)
}

func intentApprove(arguments []string) {
	flags := flag.NewFlagSet("intent approve", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	intentID := flags.String("id", "", "exact intent ID")
	digest := flags.String("digest", "", "full intent digest displayed by intent show")
	flags.Parse(arguments)
	if *intentID == "" || *digest == "" {
		fatal("--id and --digest are required")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	name, uid := localIdentity()
	operator := workflow.OperatorService{Store: database, Now: func() time.Time { return time.Now().UTC() }}
	approval, operation, err := operator.Approve(context.Background(), *intentID, *digest, name, uid)
	must(err)
	writeJSON(map[string]any{"approval": approval, "operation": operation})
}

func intentReject(arguments []string) {
	flags := flag.NewFlagSet("intent reject", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	intentID := flags.String("id", "", "exact intent ID")
	digest := flags.String("digest", "", "full intent digest displayed by intent show")
	flags.Parse(arguments)
	if *intentID == "" || *digest == "" {
		fatal("--id and --digest are required")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	name, uid := localIdentity()
	operator := workflow.OperatorService{Store: database, Now: func() time.Time { return time.Now().UTC() }}
	approval, err := operator.Reject(context.Background(), *intentID, *digest, name, uid)
	must(err)
	writeJSON(approval)
}

func intentRevoke(arguments []string) {
	flags := flag.NewFlagSet("intent revoke", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	intentID := flags.String("id", "", "exact intent ID")
	digest := flags.String("digest", "", "full intent digest displayed by intent show")
	flags.Parse(arguments)
	if *intentID == "" || *digest == "" {
		fatal("--id and --digest are required")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	name, uid := localIdentity()
	operator := workflow.OperatorService{Store: database, Now: func() time.Time { return time.Now().UTC() }}
	must(operator.Revoke(context.Background(), *intentID, *digest, name, uid))
	writeJSON(map[string]any{"intent_id": *intentID, "status": "REVOKED"})
}

func operationShow(arguments []string) {
	flags := flag.NewFlagSet("operation show", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	operationID := flags.String("id", "", "exact operation ID")
	flags.Parse(arguments)
	if *operationID == "" {
		fatal("--id is required")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	operation, err := database.GetOperation(context.Background(), *operationID)
	must(err)
	writeJSON(operation)
}

func backupShow(arguments []string) {
	flags := flag.NewFlagSet("backup show", flag.ExitOnError)
	databasePath := flags.String("db", defaultDB(), "owner-controlled SQLite database")
	backupID := flags.String("id", "", "exact reserved backup ID")
	flags.Parse(arguments)
	if *backupID == "" || flags.NArg() != 0 {
		fatal("--id is required; no paths or extra arguments are accepted")
	}
	database := mustOpen(*databasePath)
	defer database.Close()
	record, err := database.GetBackup(context.Background(), *backupID)
	must(err)
	writeJSON(map[string]any{"backup": record, "current_archive_integrity": "NOT_CHECKED", "note": "Metadata inspection only. VALID records require a fresh owner-side archive digest check before use."})
}

func defaultDB() string { return envOr("GAR_DB", "./gar-v01.db") }

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func mustOpen(path string) *store.Store {
	database, err := store.Open(path)
	must(err)
	return database
}

func localIdentity() (string, int) {
	identity, err := user.Current()
	must(err)
	uid, err := strconv.Atoi(identity.Uid)
	must(err)
	return identity.Username, uid
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
	fmt.Fprintln(os.Stderr, "usage: garctl doctor | agent issue | intent show|approve|reject|revoke | operation show | backup show")
	os.Exit(2)
}
