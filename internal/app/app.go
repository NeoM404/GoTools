// Package app implements the bankctl command dispatch. It is separated from
// main so the whole CLI is testable.
package app

import (
	"fmt"
	"io"
	"strings"
)

// Version is overridden at build time via -ldflags (see Makefile).
var Version = "dev"

// Exec is the process entry point. It returns a process exit code.
// stdout/stderr are injected for testability.
func Exec(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	// Split a leading global --config flag from the subcommand.
	cfgPath, rest := extractConfig(args)
	if len(rest) == 0 {
		printUsage(stdout)
		return 0
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "bankctl %s\n", Version)
		return 0
	case "init":
		return cmdInit(cmdArgs, stdout, stderr)
	case "doctor":
		return cmdDoctor(cfgPath, cmdArgs, stdout, stderr)
	case "clusters":
		return cmdClusters(cfgPath, cmdArgs, stdout, stderr)
	case "kubeconfig":
		return cmdKubeconfig(cfgPath, cmdArgs, stdout, stderr)
	case "login":
		return cmdLogin(cfgPath, cmdArgs, stdout, stderr)
	case "fleet":
		return cmdFleet(cfgPath, cmdArgs, stdout, stderr)
	case "guard":
		return cmdGuard(cfgPath, cmdArgs, stdout, stderr)
	case "current":
		return cmdCurrent(cfgPath, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		printUsage(stderr)
		return 2
	}
}

// extractConfig pulls a global "--config PATH" or "--config=PATH" appearing
// before the subcommand, returning the path and the remaining args.
func extractConfig(args []string) (string, []string) {
	var cfg string
	var rest []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--config" && i+1 < len(args):
			cfg = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--config="):
			cfg = strings.TrimPrefix(a, "--config=")
			i++
		default:
			// First non-global token starts the subcommand; stop consuming.
			rest = append(rest, args[i:]...)
			return cfg, rest
		}
	}
	return cfg, rest
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `bankctl — banking Kubernetes fleet CLI

Usage:
  bankctl [--config PATH] <command> [args]

Commands:
  init                        Write a starter config to ~/.config/bankctl
                              [--path PATH] [--force]
  clusters list [--cloud aws|azure] [--env ENV] [--owner NAME] [-o table|json]
                              List clusters in the fleet inventory
  clusters get <name> [-o table|json]
                              Show one cluster's details
  kubeconfig <cluster>        Fetch credentials for a cluster (aws/az CLI)
                              [--file PATH] [--dry-run]
  login <cluster>             kubeconfig + safety check for the target
                              [--file PATH] [--dry-run]
  fleet versions [-o table|json]
                              Version-drift report against the fleet target
                              [--fail-on-stale]  (exit 1 if any STALE cluster)
  guard                       Check the CURRENT kube-context for prod
                              [--block]  (exit 3 if prod — for prompts/CI)
  current                     Show current context + prod status
  doctor                      Check ecosystem tools are present & current
                              [--strict]  (exit 1 if any tool is below floor)
  version                     Print bankctl version
  help                        Show this help

Config: --config, $BANKCTL_CONFIG, ~/.config/bankctl/config.json, ./bankctl.json
First run:  bankctl init  then edit the config's inventory source.
See docs/bankctl.md for full documentation.
`)
}
