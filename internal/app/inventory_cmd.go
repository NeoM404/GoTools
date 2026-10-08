package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"nedctl/internal/config"
	"nedctl/internal/discovery"
	"nedctl/internal/inventory"
	"nedctl/internal/reconcile"
)

func cmdInventory(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl inventory <diff|sync|validate> ...")
		return ExitUsage
	}
	switch args[0] {
	case "validate":
		return inventoryValidate(cfgPath, args[1:], stdout, stderr)
	case "diff":
		return inventoryDiff(ctx, cfgPath, args[1:], stdout, stderr)
	case "sync":
		return inventorySync(ctx, cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown inventory subcommand %q\n", args[0])
		return ExitUsage
	}
}

// scan loads the validated declared fleet and scans the configured scope.
func scan(ctx context.Context, cfgPath string, stderr io.Writer, quiet bool) (config.Config, inventory.Fleet, discovery.Result, bool) {
	cfg, declared, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return cfg, declared, discovery.Result{}, false
	}
	if cfg.Bastion() {
		fmt.Fprintln(stderr, "inventory discovery does not run on a bastion (config mode \"bastion\"): it needs cloud CLI access the bastion does not have. "+
			"It runs in the inventory pipeline, which publishes the inventory bastions use — see docs/azure-devops.md")
		return cfg, declared, discovery.Result{}, false
	}
	d := cfg.Discovery
	if !d.Configured() {
		fmt.Fprintln(stderr, `no discovery scope configured — add a "discovery" block listing the AWS accounts/regions and Azure subscriptions to scan (see docs/nedctl.md)`)
		return cfg, declared, discovery.Result{}, false
	}
	if !quiet {
		regions := 0
		for _, t := range d.AWS {
			regions += len(t.Regions)
		}
		fmt.Fprintf(stderr, "scanning %d AWS account(s) across %d account-region scope(s) and %d Azure subscription(s)…\n",
			len(d.AWS), regions, len(d.Azure))
	}
	res := discovery.Scan(ctx, discovery.ExecRunner(cfg.Timeout()), d)
	return cfg, declared, res, true
}

func printScanErrors(w io.Writer, errs []discovery.ScanError) {
	if len(errs) == 0 {
		return
	}
	fmt.Fprintf(w, "\nscan INCOMPLETE — %d scope(s) failed; results cannot prove the inventory is complete:\n", len(errs))
	for _, e := range errs {
		fmt.Fprintf(w, "  %s: %s\n", e.Target, e.Error)
	}
}

func inventoryDiff(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	report := fs.String("report", "", "also write the JSON report to this file (for pipelines: a readable log and a machine-readable artifact from one scan)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	_, declared, res, ok := scan(ctx, cfgPath, stderr, *output == "json")
	if !ok {
		return ExitFailure
	}
	rep := reconcile.Diff(declared, res)
	code := ExitOK
	if !rep.InSync {
		code = ExitFailure
	}
	if *report != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err == nil {
			err = writeFileAtomic(*report, append(data, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "writing report %s: %v\n", *report, err)
			return ExitFailure
		}
	}

	if *output == "json" {
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	fmt.Fprintf(stdout, "declared %d · observed %d · matched %d · scanned %d scope(s)\n",
		rep.Declared, rep.Observed, rep.Matched, len(rep.Scanned))
	if len(rep.Findings) > 0 {
		fmt.Fprintln(stdout)
		tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "KIND\tCLUSTER\tSCOPE\tDETAIL")
		for _, f := range rep.Findings {
			detail := f.Detail
			if f.Kind == reconcile.Drift {
				detail = fmt.Sprintf("%s: inventory %q, cloud %q", f.Field, f.Declared, f.Observed)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Kind, f.Cluster, f.Scope, detail)
		}
		tw.Flush()
	}
	printScanErrors(stderr, rep.ScanErrors)

	if rep.InSync {
		fmt.Fprintln(stdout, "\nIN SYNC — every declared cluster verified in a scanned scope; no shadow clusters")
		return code
	}
	var parts []string
	for _, k := range []reconcile.Kind{reconcile.Shadow, reconcile.Missing, reconcile.Drift, reconcile.Unscanned} {
		if n := rep.Count(k); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, k))
		}
	}
	if !rep.Complete {
		parts = append(parts, "scan incomplete")
	}
	fmt.Fprintf(stdout, "\nNOT IN SYNC — %s\n", strings.Join(parts, ", "))
	return code
}

// inventoryValidate checks the config and an inventory against it — every
// rule commands apply at load time, reported in one pass. --file validates a
// candidate (a proposed inventory in a pull request) instead of the
// configured one.
func inventoryValidate(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "inventory file to validate (default: the configured inventory)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: nedctl inventory validate [--file PATH]")
		return ExitUsage
	}
	var (
		cfg   config.Config
		fleet inventory.Fleet
		ok    bool
	)
	if *file == "" {
		if cfg, fleet, ok = loadFleet(cfgPath, stderr); !ok {
			return ExitFailure
		}
	} else {
		var err error
		if cfg, _, err = config.Load(cfgPath); err != nil {
			fmt.Fprintf(stderr, "config error: %v\n", err)
			return ExitFailure
		}
		if fleet, err = inventory.LoadFile(*file); err == nil {
			err = fleet.Validate(cfg.Environments)
		}
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return ExitFailure
		}
	}
	byEnv := map[string]int{}
	for _, c := range fleet.Clusters {
		byEnv[strings.ToLower(c.Environment)]++
	}
	envs := make([]string, 0, len(byEnv))
	for e := range byEnv {
		envs = append(envs, e)
	}
	sort.Strings(envs)
	parts := make([]string, len(envs))
	for i, e := range envs {
		label := e
		if label == "" {
			label = "(none)"
		}
		parts[i] = fmt.Sprintf("%s %d", label, byEnv[e])
	}
	fmt.Fprintf(stdout, "inventory valid: %d cluster(s)", len(fleet.Clusters))
	if len(parts) > 0 {
		fmt.Fprintf(stdout, " — %s", strings.Join(parts, ", "))
	}
	fmt.Fprintln(stdout)
	return ExitOK
}

func inventorySync(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write the proposed inventory to this file instead of stdout")
	force := fs.Bool("force", false, "overwrite --out if it exists")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: nedctl inventory sync [--out FILE] [--force]")
		return ExitUsage
	}
	if *out != "" && !*force {
		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(stderr, "%s already exists — use --force to overwrite\n", *out)
			return ExitFailure
		}
	}

	cfg, declared, res, ok := scan(ctx, cfgPath, stderr, false)
	if !ok {
		return ExitFailure
	}
	if !res.Complete() {
		printScanErrors(stderr, res.Errors)
		fmt.Fprintln(stderr, "refusing to write an inventory from a partial scan: clusters in the failed scopes would be silently dropped")
		return ExitFailure
	}

	proposed := reconcile.Proposed(declared, res)
	if err := proposed.Validate(cfg.Environments); err != nil {
		fmt.Fprintf(stderr, "the discovered estate does not form a valid inventory, so nothing was written.\n%v\n", err)
		fmt.Fprintln(stderr, "fix at the source: tag clusters (environment/owner/cost centre), or rename clusters that share a name")
		return ExitFailure
	}

	data, err := json.MarshalIndent(proposed, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encoding inventory: %v\n", err)
		return ExitFailure
	}
	data = append(data, '\n')

	rep := reconcile.Diff(declared, res)
	updated := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Kind == reconcile.Drift {
			updated[f.Cluster] = true
		}
	}
	summary := fmt.Sprintf("%d cluster(s): %d added, %d removed, %d updated",
		len(proposed.Clusters), rep.Count(reconcile.Shadow), rep.Count(reconcile.Missing), len(updated))

	if *out == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "writing inventory: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintln(stderr, "proposed inventory — "+summary)
		return ExitOK
	}
	if err := writeFileAtomic(*out, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "writing %s: %v\n", *out, err)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "wrote %s — %s\n", *out, summary)
	return ExitOK
}

// writeFileAtomic writes data so readers see either the old file or the new
// one, never a truncated mix: temp file in the same directory, fsync, rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Persist the rename itself. Best-effort: some platforms cannot fsync a
	// directory, and the rename is atomic either way.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
