// gar-g02-verify records owner-local admission-barrier acceptance evidence.
// It is intentionally separate from the agent-facing MCP server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"guarded-agent-runner/internal/acceptance/g02"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	configPath := commandConfig(os.Args[2:], os.Args[1])
	config, err := g02.LoadConfig(configPath)
	must(err)
	runner, err := g02.NewRunner(config)
	must(err)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var evidence g02.Evidence
	switch os.Args[1] {
	case "minecraft-login-close":
		evidence, err = runner.MinecraftLoginClose(ctx)
	case "host-reboot-prepare":
		evidence, err = runner.PrepareHostReboot(ctx)
	case "host-reboot-verify":
		evidence, err = runner.VerifyHostReboot(ctx)
	default:
		usage()
	}
	must(err)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(evidence))
}

func commandConfig(arguments []string, command string) string {
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	path := flags.String("config", os.Getenv("GAR_G02_ACCEPTANCE_CONFIG"), "owner-only fixed G-02 acceptance config")
	flags.Parse(arguments)
	if *path == "" || flags.NArg() != 0 {
		usage()
	}
	return *path
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gar-g02-verify minecraft-login-close|host-reboot-prepare|host-reboot-verify --config FILE")
	os.Exit(2)
}
