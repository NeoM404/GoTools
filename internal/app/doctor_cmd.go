package app

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/tools"
)

func cmdDoctor(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "exit 1 if any tool with a floor is below it (for CI)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Config is optional; used only for minVersions overrides. Ignore errors so
	// doctor always runs (its job is to diagnose a broken setup).
	cfg, _, _ := config.Load(cfgPath)
	results := tools.Inspect(cfg.MinVersions)

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tREQUIRED\tSTATUS\tVERSION\tMIN\tPURPOSE")
	for _, r := range results {
		status := "missing"
		switch {
		case r.Found && r.Outdated:
			status = "OUTDATED"
		case r.Found:
			status = "ok"
		}
		req := ""
		if r.Required {
			req = "required"
		}
		version := r.Detected
		if r.Found && version == "" {
			version = "-"
		}
		min := r.MinVersion
		if min == "" {
			min = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, req, status, version, min, r.Purpose)
	}
	tw.Flush()

	missing := tools.MissingRequired(results)
	outdatedReq := tools.OutdatedRequired(results)
	outdatedAll := tools.AnyOutdated(results)

	if len(missing) > 0 {
		fmt.Fprintln(stderr, "\nmissing REQUIRED tools:")
		for _, m := range missing {
			fmt.Fprintf(stderr, "  %s — install: %s\n", m.Name, m.Install)
		}
	}
	if len(outdatedAll) > 0 {
		fmt.Fprintln(stderr, "\nbelow version floor (update these):")
		for _, o := range outdatedAll {
			fmt.Fprintf(stderr, "  %s %s < %s — %s\n", o.Name, o.Detected, o.MinVersion, o.Install)
		}
	}

	// Exit policy: a missing REQUIRED tool always fails. An outdated REQUIRED
	// tool fails too (bankctl's own commands may misbehave). --strict escalates
	// ANY outdated tool (incl. optional) to a failure, for a CI hygiene gate.
	if len(missing) > 0 || len(outdatedReq) > 0 {
		return 1
	}
	if *strict && len(outdatedAll) > 0 {
		return 1
	}
	if len(missing) == 0 && len(outdatedAll) == 0 {
		fmt.Fprintln(stdout, "\nall required tools present and current")
	}
	return 0
}
