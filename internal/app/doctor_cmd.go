package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/tools"
)

// doctorTool is one row of `doctor -o json`.
type doctorTool struct {
	Name       string `json:"name"`
	Required   bool   `json:"required"`
	Status     string `json:"status"` // ok | missing | outdated
	Version    string `json:"version,omitempty"`
	MinVersion string `json:"minVersion,omitempty"`
	Purpose    string `json:"purpose"`
	Install    string `json:"install"`
}

// doctorReport is the `doctor -o json` document. Healthy mirrors the exit code
// (true ⇔ exit 0 under the same flags), so a CI step can read either.
type doctorReport struct {
	Healthy bool         `json:"healthy"`
	Strict  bool         `json:"strict"`
	Tools   []doctorTool `json:"tools"`
}

func toolStatus(r tools.Result) string {
	switch {
	case !r.Found:
		return "missing"
	case r.Outdated:
		return "outdated"
	default:
		return "ok"
	}
}

func cmdDoctor(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "exit 1 if any tool with a floor is below it (for CI)")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}

	// Config is optional; used only for minVersions overrides. Ignore errors so
	// doctor always runs (its job is to diagnose a broken setup).
	cfg, _, _ := config.Load(cfgPath)
	results := tools.Inspect(ctx, cfg.MinVersions)

	missing := tools.MissingRequired(results)
	outdatedReq := tools.OutdatedRequired(results)
	outdatedAll := tools.AnyOutdated(results)

	// Exit policy: a missing REQUIRED tool always fails. An outdated REQUIRED
	// tool fails too (bankctl's own commands may misbehave). --strict escalates
	// ANY outdated tool (incl. optional) to a failure, for a CI hygiene gate.
	code := ExitOK
	if len(missing) > 0 || len(outdatedReq) > 0 || (*strict && len(outdatedAll) > 0) {
		code = ExitFailure
	}

	if *output == "json" {
		rep := doctorReport{Healthy: code == ExitOK, Strict: *strict, Tools: make([]doctorTool, 0, len(results))}
		for _, r := range results {
			rep.Tools = append(rep.Tools, doctorTool{
				Name: r.Name, Required: r.Required, Status: toolStatus(r),
				Version: r.Detected, MinVersion: r.MinVersion, Purpose: r.Purpose, Install: r.Install,
			})
		}
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tREQUIRED\tSTATUS\tVERSION\tMIN\tPURPOSE")
	for _, r := range results {
		status := toolStatus(r)
		if status == "outdated" {
			status = "OUTDATED"
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
	if len(missing) == 0 && len(outdatedAll) == 0 {
		fmt.Fprintln(stdout, "\nall required tools present and current")
	}
	return code
}
