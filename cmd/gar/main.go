package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	compositeadapter "guarded-agent-runner/internal/adapters/composite"
	hostadapter "guarded-agent-runner/internal/adapters/host"
	paperadapter "guarded-agent-runner/internal/adapters/paper"
	"guarded-agent-runner/internal/domain"
	"guarded-agent-runner/internal/mcpserver"
	"guarded-agent-runner/internal/policy"
	"guarded-agent-runner/internal/runtimeconfig"
	"guarded-agent-runner/internal/store"
	"guarded-agent-runner/internal/workflow"
)

func main() {
	if len(os.Args) == 1 {
		status()
		return
	}
	switch os.Args[1] {
	case "status":
		status()
	case "serve":
		serve(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: gar [status | serve --config FILE --credentials FILE --allowed-origin ORIGIN]")
		os.Exit(2)
	}
}

func status() {
	profile := policy.DefaultM1Profile()
	writeJSON(map[string]any{
		"product":             "Guarded Agent Runner for Paper",
		"specification":       "GAR-PCS-001@v0.1-r1",
		"milestone":           "M2_MCP_TRANSPORT_READ_ONLY_ALPHA",
		"mutation_enabled":    profile.MutationAllowed(),
		"agent_tools":         domain.AgentTools,
		"mcp_transport":       "LOCAL_VERIFIED_CONFIG_REQUIRED",
		"paper_observations":  "CONFIG_REQUIRED; LOCAL_PAPER_READ_ONLY_TUPLE_RECORDED",
		"real_paper_evidence": "LOCAL_PAPER_READ_ONLY",
	})
}

func serve(arguments []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	databasePath := flags.String("db", envOr("GAR_DB", "./gar-v01.db"), "owner-controlled SQLite database")
	configPath := flags.String("config", os.Getenv("GAR_CONFIG"), "owner-only fixed enrollment/registry JSON")
	credentialPath := flags.String("credentials", os.Getenv("GAR_CREDENTIALS"), "owner-only hashed agent credential JSON")
	listenAddress := flags.String("listen", envOr("GAR_LISTEN", "127.0.0.1:8787"), "literal loopback listen address")
	allowedOrigin := flags.String("allowed-origin", os.Getenv("GAR_ALLOWED_ORIGIN"), "exact allowed browser Origin")
	flags.Parse(arguments)
	if *configPath == "" || *credentialPath == "" || *allowedOrigin == "" {
		fatal("--config, --credentials, and --allowed-origin are required")
	}
	if err := mcpserver.ValidateListenAddress(*listenAddress); err != nil {
		fatal(err.Error())
	}
	config, err := runtimeconfig.Load(*configPath)
	must(err)
	credentials, err := mcpserver.LoadCredentials(*credentialPath)
	must(err)
	database, err := store.Open(*databasePath)
	must(err)
	defer database.Close()
	must(credentials.ValidateSessions(context.Background(), database,
		config.Enrollment.EnrollmentID, config.Enrollment.DeploymentGeneration,
		config.CurrentRevocationEpoch, time.Now().UTC()))

	var target workflow.TargetReader = workflow.UnavailableTarget{
		Reason: "host and Paper observations are not configured; MCP transport has no live target evidence",
	}
	var hostTarget workflow.TargetReader
	var paperTarget workflow.TargetReader
	if config.HostObservation != nil {
		hostTarget, err = hostadapter.NewSnapshotTarget(config.HostObservation.SnapshotPath, config.Enrollment, config.Artifacts)
		must(err)
	}
	if config.PaperRuntime != nil {
		paperTarget, err = paperadapter.NewSnapshotTarget(config.PaperRuntime.SnapshotPath, config.Enrollment)
		must(err)
	}
	switch {
	case hostTarget != nil && paperTarget != nil:
		target, err = compositeadapter.New(hostTarget, paperTarget)
		must(err)
	case hostTarget != nil:
		target = hostTarget
	case paperTarget != nil:
		target = paperTarget
	}
	service := &workflow.Service{
		Store: database, Registry: config.Registry(),
		Target:  target,
		Support: config.Support, CurrentRevocationEpoch: config.CurrentRevocationEpoch,
		MutationExecutorEnabled: false,
	}
	handler, err := mcpserver.NewHandler(mcpserver.Options{
		Service: service, Store: database, Credentials: credentials, AllowedOrigin: *allowedOrigin,
	})
	must(err)
	listener, err := net.Listen("tcp", *listenAddress)
	must(err)

	httpServer := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 2 * time.Minute,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()
	fmt.Fprintf(os.Stderr, "GAR MCP read-only alpha listening on %s; mutation remains disabled\n", listener.Addr())
	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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
