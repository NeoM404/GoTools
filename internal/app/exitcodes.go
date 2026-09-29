package app

// Exit codes are a stable, documented contract (docs/bankctl.md, "Exit
// codes"): shell prompts, CI gates and wrapper scripts branch on them. Add new
// codes; never renumber or repurpose an existing one.
const (
	// ExitOK: the command succeeded, or the check passed.
	ExitOK = 0
	// ExitFailure: the command ran and failed, or a check found a problem
	// (stale cluster with --fail-on-stale, missing required tool, ...).
	ExitFailure = 1
	// ExitUsage: invalid invocation — unknown command, bad flag or argument.
	// Nothing was attempted.
	ExitUsage = 2
	// ExitProdContext: `guard --block` found the current context is
	// production. Distinct from ExitFailure so callers can tell "you are in
	// prod" apart from "the check itself broke".
	ExitProdContext = 3
	// ExitInterrupted: cancelled by SIGINT/SIGTERM (128 + SIGINT, the shell
	// convention). Child processes were stopped, not orphaned.
	ExitInterrupted = 130
)
