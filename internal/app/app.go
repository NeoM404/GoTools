// Package app implements the bankctl command dispatch. It is separated from
// main so the whole CLI is testable.
package app

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Version is overridden at build time via -ldflags (see Makefile).
var Version = "dev"

// Exec runs bankctl without cancellation. It returns a process exit code;
// stdout/stderr are injected for testability.
func Exec(args []string, stdout, stderr io.Writer) int {
	return ExecContext(context.Background(), args, stdout, stderr)
}

// ExecContext is the process entry point. Cancelling ctx (main wires it to
// SIGINT/SIGTERM) stops any running cloud CLI and yields ExitInterrupted.
func ExecContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	code := dispatch(ctx, args, stdout, stderr)
	if code != ExitOK && ctx.Err() != nil {
		fmt.Fprintln(stderr, "bankctl: interrupted")
		return ExitInterrupted
	}
	return code
}

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return ExitOK
	}

	// Split a leading global --config flag from the subcommand.
	cfgPath, rest := extractConfig(args)
	if len(rest) == 0 {
		printUsage(stdout)
		return ExitOK
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		printUsage(stdout)
		return ExitOK
	case "version", "--version":
		fmt.Fprintf(stdout, "bankctl %s\n", Version)
		return ExitOK
	case "init":
		return cmdInit(cmdArgs, stdout, stderr)
	case "doctor":
		return cmdDoctor(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "clusters":
		return cmdClusters(cfgPath, cmdArgs, stdout, stderr)
	case "kubeconfig":
		return cmdKubeconfig(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "login":
		return cmdLogin(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "fleet":
		return cmdFleet(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "inventory":
		return cmdInventory(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "sweep":
		return cmdSweep(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "audit":
		return cmdAudit(cfgPath, cmdArgs, stdout, stderr)
	case "evidence":
		return cmdEvidence(cfgPath, cmdArgs, stdout, stderr)
	case "guard":
		return cmdGuard(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "current":
		return cmdCurrent(ctx, cfgPath, cmdArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		printUsage(stderr)
		return ExitUsage
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
                              [--mode workstation|bastion]
  clusters list [--cloud aws|azure] [--env ENV] [--owner NAME] [-o table|json]
                              List clusters in the fleet inventory
  clusters get <name> [-o table|json]
                              Show one cluster's details
  kubeconfig <cluster>        Fetch credentials for a cluster (aws/az CLI)
                              [--file PATH] [--dry-run]
                              [--change-record CHG… | --break-glass REASON]
  login <cluster>             kubeconfig + safety check for the target
                              (same flags as kubeconfig). On a bastion:
                              switch to the cluster's provisioned context,
                              audited and change-controlled [--context NAME]
  fleet versions [-o table|json]
                              Version-drift report against the target for
                              each cluster's environment
                              [--fail-on-stale]  (exit 1 if any STALE cluster)
  fleet eol [-o table|json]   Support lifecycle + extended-support premium
                              [--warn-days N] [--by-cost-centre]
                              [--fail-on-risk]  (exit 1 if any cluster at risk)
  fleet calendar aws          Generate supportCalendar.aws from EKS
                              [--profile P] [--region R]
  inventory validate [--file PATH]
                              Check an inventory against the config
  inventory diff [-o table|json] [--report FILE]
                              Reconcile the inventory against the clouds:
                              shadow, missing and drifted clusters
                              (exit 1 unless complete and in sync)
  inventory sync [--out FILE] [--force]
                              Write the inventory the clouds imply
                              (refuses a partial scan or an invalid result)
  sweep [--apply] [--kubeconfig PATH] [-o table|json]
                              Remove EKS/AKS contexts the inventory proves
                              stale (dry run by default; backup first)
                              [--include-current]
  audit verify [--log PATH]...
                              Check the audit log's hash chain
  evidence --period 2026-Q3 | --from DATE --to DATE
                              Evidence pack: accesses, change records and
                              exceptions to review [--log PATH]...
                              [--production] [--out FILE] [-o table|json]
  guard [-o table|json]       Check the CURRENT kube-context for prod
                              [--block]  (exit 3 if prod — for prompts/CI)
  current [-o table|json]     Show current context + prod status
  doctor [-o table|json]      Check ecosystem tools are present & current
                              [--strict]  (exit 1 if any tool is below floor)
  version                     Print bankctl version
  help                        Show this help

Exit codes: 0 ok · 1 failed/check found a problem · 2 usage error
            3 production context (guard --block) · 130 interrupted
Config: --config, $BANKCTL_CONFIG, ~/.config/bankctl/config.json, ./bankctl.json
First run:  bankctl init  then edit the config's inventory source.
See docs/bankctl.md for full documentation.
`)
}
