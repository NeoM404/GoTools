package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/kube"
)

type sweepReport struct {
	Kubeconfig string             `json:"kubeconfig"`
	Applied    bool               `json:"applied"`
	Backup     string             `json:"backup,omitempty"`
	Plans      []kube.ContextPlan `json:"plans"`
	Removed    struct {
		Contexts int `json:"contexts"`
		Clusters int `json:"clusters"`
		Users    int `json:"users"`
	} `json:"removed"`
	Errors []string `json:"errors"`
}

func cmdSweep(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "remove the stale contexts (default: report only)")
	includeCurrent := fs.Bool("include-current", false, "also remove the current context if it is stale")
	kcFlag := fs.String("kubeconfig", "", "kubeconfig file to sweep (default: $KUBECONFIG or ~/.kube/config)")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: bankctl sweep [--apply] [--include-current] [--kubeconfig PATH] [-o table|json]")
		return ExitUsage
	}

	path, err := kubeconfigPath(*kcFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	// The inventory decides what is stale, so it must load and validate; the
	// sweeper never runs on a guess.
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		fmt.Fprintln(stderr, "refusing to sweep without a valid inventory")
		return ExitFailure
	}
	before, err := kube.ViewKubeconfig(ctx, path)
	if err != nil {
		fmt.Fprintf(stderr, "reading %s: %v\n", path, err)
		return ExitFailure
	}

	rep := sweepReport{Kubeconfig: path, Plans: kube.PlanSweep(before, fleet, *includeCurrent), Errors: []string{}}
	kube.SortPlans(rep.Plans)
	var removals []kube.ContextPlan
	for _, p := range rep.Plans {
		if p.Verdict.Removes() {
			removals = append(removals, p)
		}
	}

	code := ExitOK
	if *apply && len(removals) > 0 {
		cfg, _, _ := config.Load(cfgPath) // already validated by loadFleet
		tr, err := beginAudit(ctx, cfg, "kubeconfig-sweep", nil, false, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%v — refusing to modify %s: every change must be recorded\n", err, path)
			return ExitFailure
		}
		code = applySweep(ctx, path, before, removals, &rep)
		names := make([]string, 0, len(removals))
		for _, p := range removals {
			names = append(names, p.Context)
		}
		outcome := audit.OutcomeSuccess
		if code != ExitOK {
			outcome = audit.OutcomeFailure
		}
		tr.end(ctx, outcome, "", fmt.Sprintf("%s: removed %d context(s): %s", path, rep.Removed.Contexts, strings.Join(names, ", ")), stderr)
	}

	if *output == "json" {
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTEXT\tVERDICT\tDETAIL")
	for _, p := range rep.Plans {
		detail := p.Reason
		if p.ResolvedTo != "" && p.ResolvedTo != p.Context {
			detail += " as " + p.ResolvedTo
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", p.Context, p.Verdict, detail)
	}
	tw.Flush()
	fmt.Fprintln(stdout)
	switch {
	case len(removals) == 0:
		fmt.Fprintf(stdout, "nothing to remove from %s\n", path)
	case !*apply:
		clusters, users := 0, 0
		for _, p := range removals {
			if p.DeleteCluster != "" {
				clusters++
			}
			if p.DeleteUser != "" {
				users++
			}
		}
		fmt.Fprintf(stdout, "dry run: %d stale context(s) would be removed from %s, with %d cluster and %d user entries no other context uses.\n",
			len(removals), path, clusters, users)
		fmt.Fprintln(stdout, "re-run with --apply to remove them — a backup is written first.")
	default:
		fmt.Fprintf(stdout, "removed %d context(s), %d cluster(s), %d user(s) from %s\nbackup: %s\n",
			rep.Removed.Contexts, rep.Removed.Clusters, rep.Removed.Users, path, rep.Backup)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(stderr, "error: %s\n", e)
	}
	return code
}

// applySweep backs up the file, removes the planned entries through kubectl,
// then re-reads the file to verify the result rather than trusting each call.
func applySweep(ctx context.Context, path string, before kube.Kubeconfig, removals []kube.ContextPlan, rep *sweepReport) int {
	backup, err := backupFile(path)
	if err != nil {
		rep.Errors = append(rep.Errors, "backup failed, nothing was changed: "+err.Error())
		return ExitFailure
	}
	rep.Backup, rep.Applied = backup, true

	failed := false
	note := func(err error) {
		if err != nil {
			failed = true
			rep.Errors = append(rep.Errors, err.Error())
		}
	}
	removedCurrent := false
	for _, p := range removals {
		if err := kube.DeleteEntry(ctx, path, "context", p.Context); err != nil {
			note(err)
			continue // keep its cluster/user: they may still be needed
		}
		rep.Removed.Contexts++
		removedCurrent = removedCurrent || p.Context == before.CurrentContext
		if p.DeleteCluster != "" {
			if err := kube.DeleteEntry(ctx, path, "cluster", p.DeleteCluster); err != nil {
				note(err)
			} else {
				rep.Removed.Clusters++
			}
		}
		if p.DeleteUser != "" {
			if err := kube.DeleteEntry(ctx, path, "user", p.DeleteUser); err != nil {
				note(err)
			} else {
				rep.Removed.Users++
			}
		}
	}
	if removedCurrent {
		note(kube.UnsetCurrentContext(ctx, path))
	}

	after, err := kube.ViewKubeconfig(ctx, path)
	if err != nil {
		note(fmt.Errorf("verifying %s after the sweep: %w", path, err))
	} else {
		note(verifySweep(after, before, removals))
	}
	if failed {
		rep.Errors = append(rep.Errors, "restore the original with: cp "+shellQuote(backup)+" "+shellQuote(path))
		return ExitFailure
	}
	return ExitOK
}

// verifySweep checks the planned contexts are gone and every other context
// survived.
func verifySweep(after, before kube.Kubeconfig, removals []kube.ContextPlan) error {
	gone := map[string]bool{}
	for _, p := range removals {
		gone[p.Context] = true
	}
	present := map[string]bool{}
	for _, c := range after.Contexts {
		present[c.Name] = true
	}
	var errs []error
	for _, c := range before.Contexts {
		switch {
		case gone[c.Name] && present[c.Name]:
			errs = append(errs, fmt.Errorf("context %q is still present after removal", c.Name))
		case !gone[c.Name] && !present[c.Name]:
			errs = append(errs, fmt.Errorf("context %q disappeared although it was not planned for removal", c.Name))
		}
	}
	return errors.Join(errs...)
}

// kubeconfigPath picks the single file to sweep. A KUBECONFIG listing
// several files is refused: kubectl would write into whichever file defines
// each entry, and we back up exactly one file.
func kubeconfigPath(flagValue string) (string, error) {
	path := flagValue
	if path == "" {
		var parts []string
		for _, p := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
			if p != "" {
				parts = append(parts, p)
			}
		}
		switch len(parts) {
		case 0:
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("cannot locate home directory: %w", err)
			}
			path = filepath.Join(home, ".kube", "config")
		case 1:
			path = parts[0]
		default:
			return "", fmt.Errorf("KUBECONFIG lists %d files; pass --kubeconfig to choose the one to sweep", len(parts))
		}
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("kubeconfig %s: %w", path, err)
	}
	return path, nil
}

// backupFile copies path to a timestamped sibling (0600, fsynced) and
// refuses to overwrite an existing backup.
func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := path + ".bankctl-" + now().UTC().Format("20060102T150405Z") + ".bak"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	return backup, f.Close()
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
