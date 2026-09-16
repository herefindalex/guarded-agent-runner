// gar-gate is an owner-controlled, fixed-target admission barrier. It accepts
// no listener, upstream, path, or target from an agent request.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"guarded-agent-runner/internal/admission"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "open":
		setOpen(os.Args[2:])
	case "close":
		setClosed(os.Args[2:])
	case "status":
		status(os.Args[2:])
	default:
		usage()
	}
}

func serve(arguments []string) {
	config := loadConfig(arguments, "serve")
	gate, err := admission.NewGate(config, os.Stdout)
	must(err)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	must(gate.Run(ctx))
}

func setOpen(arguments []string) {
	flags := flag.NewFlagSet("open", flag.ExitOnError)
	configPath := flags.String("config", os.Getenv("GAR_ADMISSION_CONFIG"), "owner-only fixed admission config")
	lease := flags.Duration("lease", 0, "short open lease, maximum 30s")
	reason := flags.String("reason", "owner-local lease", "bounded operator reason")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		usage()
	}
	config, err := admission.LoadConfig(*configPath)
	must(err)
	state, err := admission.WriteState(config, admission.ModeOpen, *reason, *lease, time.Now().UTC())
	must(err)
	writeJSON(state)
}

func setClosed(arguments []string) {
	flags := flag.NewFlagSet("close", flag.ExitOnError)
	configPath := flags.String("config", os.Getenv("GAR_ADMISSION_CONFIG"), "owner-only fixed admission config")
	reason := flags.String("reason", "owner-local close", "bounded operator reason")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		usage()
	}
	config, err := admission.LoadConfig(*configPath)
	must(err)
	state, err := admission.WriteState(config, admission.ModeClosed, *reason, 0, time.Now().UTC())
	must(err)
	writeJSON(state)
}

func status(arguments []string) {
	config := loadConfig(arguments, "status")
	writeJSON(admission.EvaluateAccess(config, time.Now().UTC()))
}

func loadConfig(arguments []string, command string) admission.Config {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	configPath := flags.String("config", os.Getenv("GAR_ADMISSION_CONFIG"), "owner-only fixed admission config")
	flags.Parse(arguments)
	if *configPath == "" || flags.NArg() != 0 {
		usage()
	}
	config, err := admission.LoadConfig(*configPath)
	must(err)
	return config
}

func writeJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(value))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gar-gate serve|status --config FILE | open --config FILE --lease DURATION | close --config FILE")
	os.Exit(2)
}
