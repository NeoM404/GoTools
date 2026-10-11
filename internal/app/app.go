// Package app implements the nedctl command dispatch. It is separated from
// main so the whole CLI is testable.
package app

import (
	"context"
	"fmt"
	"io"
	"os"
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
	// Split a leading global --config flag from the subcommand.
	cfgPath, rest := extractConfig(args)
	if len(rest) == 0 {
		// A person at a terminal gets their status and the daily commands;
		// anything else (a script, a pipe) gets the command list.
		if f, ok := stdout.(*os.File); ok && isTerminal(f) {
			return cmdStatus(cfgPath, stdout)
		}
		printUsage(stdout)
		return ExitOK
	}
	if wantsHelp(rest[1:]) && !rawHelp {
		return printCommandHelp(ctx, commandPath(rest), stdout)
	}
	if _, grouped := subcommands[rest[0]]; grouped && len(rest) == 1 && rest[0] != "prompt" && !rawHelp {
		printCommandHelp(ctx, rest, stderr)
		return ExitUsage
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		if len(cmdArgs) > 0 {
			return printCommandHelp(ctx, commandPath(cmdArgs), stdout)
		}
		printUsage(stdout)
		return ExitOK
	case "status":
		return cmdStatus(cfgPath, stdout)
	case "console":
		return cmdConsole(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "__open-url":
		return cmdOpenURL(cmdArgs, stderr)
	case "version", "--version":
		return cmdVersion(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "init":
		return cmdInit(cmdArgs, stdout, stderr)
	case "setup":
		return cmdSetup(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "__complete":
		return cmdComplete(ctx, cfgPath, cmdArgs, stdout)
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
	case "azure":
		return cmdAzure(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "debug":
		return cmdDebug(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "app":
		return cmdApp(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "logs":
		return cmdLogs(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "forward":
		return cmdForward(ctx, cfgPath, cmdArgs, stderr)
	case "health":
		return cmdHealth(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "run":
		return cmdRun(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "node":
		return cmdNode(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "cp":
		return cmdCp(ctx, cfgPath, cmdArgs, stderr)
	case "explain":
		return cmdExplain(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "eks":
		return cmdEKS(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "prompt":
		return cmdPrompt(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "guard":
		return cmdGuard(ctx, cfgPath, cmdArgs, stdout, stderr)
	case "current":
		return cmdCurrent(ctx, cfgPath, cmdArgs, stdout, stderr)
	default:
		return unknownCommand(cmd, stderr)
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
