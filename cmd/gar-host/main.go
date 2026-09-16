// gar-host is a fixed-target, host-side observer. It accepts no remote
// commands and publishes only bounded observation snapshots for GAR.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	hostadapter "guarded-agent-runner/internal/adapters/host"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "enrollment-facts":
		runEnrollmentFacts(os.Args[2:])
	case "once":
		runOnce(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	default:
		usage()
	}
}

func runEnrollmentFacts(arguments []string) {
	flags := flag.NewFlagSet("enrollment-facts", flag.ExitOnError)
	configPath := flags.String("config", os.Getenv("GAR_HOST_CONFIG"), "owner-only fixed host enrollment JSON")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		usage()
	}
	config, err := hostadapter.LoadEnrollmentConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	observer, err := hostadapter.NewEnrollmentObserver(config)
	if err != nil {
		fatal(err)
	}
	snapshot, err := observer.Observe(context.Background())
	if err != nil {
		fatal(fmt.Errorf("enrollment observation failed (%s)", snapshot.ReasonCode))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"container_id": snapshot.ContainerID, "expected_image_id": snapshot.ImageID,
		"expected_data_root_identity":    snapshot.DataRootIdentity,
		"expected_bootstrap_fingerprint": snapshot.BootstrapFingerprint,
		"inventory_digest":               snapshot.InventoryDigest,
	}); err != nil {
		fatal(err)
	}
}

func runOnce(arguments []string) {
	observer := loadObserver(arguments, "once")
	snapshot, observeErr := observer.Observe(context.Background())
	if err := observer.Publish(snapshot); err != nil {
		fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"availability": snapshot.Availability, "reason_code": snapshot.ReasonCode,
		"observed_at": snapshot.ObservedAt,
	}); err != nil {
		fatal(err)
	}
	if observeErr != nil {
		os.Exit(1)
	}
}

func runServe(arguments []string) {
	observer := loadObserver(arguments, "serve")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := observer.Run(ctx); err != nil {
		fatal(err)
	}
}

func loadObserver(arguments []string, command string) *hostadapter.Observer {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	configPath := flags.String("config", os.Getenv("GAR_HOST_CONFIG"), "owner-only fixed host observer JSON")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		usage()
	}
	config, err := hostadapter.LoadObserverConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	observer, err := hostadapter.NewObserver(config)
	if err != nil {
		fatal(err)
	}
	return observer
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gar-host [enrollment-facts|once|serve] --config FILE")
	os.Exit(2)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
