// Package app implements the nedctl command dispatch. It is separated from
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

// Exec runs nedctl without cancellation. It returns a process exit code;
// stdout/stderr are injected for testability.
func Exec(args []string, stdout, stderr io.Writer) int {
	return ExecContext(context.Background(), args, stdout, stderr)
}

// ExecContext is the process entry point. Cancelling ctx (main wires it to
// SIGINT/SIGTERM) stops any running cloud CLI and yields ExitInterrupted.
func ExecContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	code := dispatch(ctx, args, stdout, stderr)
	if code != ExitOK && ctx.Err() != nil {
		fmt.Fprintln(stderr, "nedctl: interrupted")
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
		fmt.Fprintf(stdout, "nedctl %s\n", Version)
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
	case "aws":
		return cmdAWS(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "shell":
		return cmdShell(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "ec2":
		return cmdEC2(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "connect":
		return cmdConnect(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "kube":
		return cmdKube(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "eks":
		return cmdEKS(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "prompt":
		return cmdPrompt(ctx, cfgPath, cmdArgs, stdout, stderr)
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
	fmt.Fprint(w, `nedctl — banking Kubernetes fleet CLI

Usage:
  nedctl [--config PATH] <command> [args]

Commands:
  init                        Write a starter config to ~/.config/nedctl
                              [--path PATH] [--force]
                              [--mode workstation|bastion]
  clusters list [--cloud aws|azure] [--env ENV] [--owner NAME] [-o table|json]
                              List clusters in the fleet inventory; with no
                              inventory, the signed-in AWS account's EKS
                              clusters, live
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
  aws login [WORDS…]          Sign in with IAM Identity Center and pick ONE
                              account + role (picker; words such as "lms qa"
                              narrow it, one match goes straight in);
                              writes an AWS CLI profile, no keys handled
                              [--device-code] [--force] [--format sh|powershell|none]
                              [--all --break-glass REASON]  (break-glass roles only)
  aws whoami [--profile P] [-o table|json]
                              Who you act as, where, and sign-in time left
  aws env [--profile P] [--format sh|powershell]
                              Short-term credentials for tools that need
                              keys (sm, SSMshell):  eval "$(nedctl aws env)"
  shell [FILTER…]             Session Manager shell on an instance in the
                              profile's account: picker coloured by env,
                              audited [--instance ID|NAME] [--profile P]
                              [--tab] (Windows Terminal) [--via aws|legacy]
                              (legacy: launch sm/SSMshell already signed in)
                              [--change-record CHG… | --break-glass REASON]
  ec2 <start|stop> <instance> Start/stop an instance, audited [--yes]
  connect [eks-cluster]       Tunnel to a private EKS endpoint through the
                              devops instance (Session Manager); kubectl
                              runs locally as YOUR SSO role, TLS verified
                              [--via auto|direct|bastion] [--via-instance I]
                              [--port N] [--tab]
  kube [eks-cluster]          connect in one step: tunnel in the background,
                              a shell with KUBECONFIG set (prompt shows the
                              cluster); exit closes the tunnel. No name:
                              pick from the account's clusters
                              [-- command args…] run one command instead
                              [--via auto|direct|bastion] (auto: direct when
                              the endpoint answers from here, e.g. on VPN)
  eks auth [--profile P]… [--all-profiles] [-o table|json]
                              Authentication mode + endpoint exposure of
                              every EKS cluster; who still needs to move
                              off CONFIG_MAP [--fail-on-configmap]
  eks access <cluster>        Who can reach a cluster via access entries,
                              with which policy and scope
  guard [-o table|json]       Check the CURRENT kube-context for prod
                              [--block]  (exit 3 if prod — for prompts/CI)
  current [-o table|json]     Show current context + prod status
  prompt [--shell bash|zsh|powershell|plain] [--tab]
                              Prompt segment: kube-context and AWS profile
                              in their environment's colour (never fails);
                              --tab also colours the Windows Terminal tab
  prompt init <bash|zsh>      Shell code for ~/.bashrc: eval "$(nedctl prompt init bash)"
  doctor [-o table|json]      Check ecosystem tools are present & current
                              [--strict]  (exit 1 if any tool is below floor)
  version                     Print nedctl version
  help                        Show this help

Exit codes: 0 ok · 1 failed/check found a problem · 2 usage error
            3 production context (guard --block) · 130 interrupted
Config: --config, $NEDCTL_CONFIG, ~/.config/nedctl/config.json, ./nedctl.json
First run:  nedctl init  then edit the config's inventory source.
See docs/nedctl.md for full documentation.
`)
}
