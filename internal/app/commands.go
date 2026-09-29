package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/cloud"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/execx"
	"github.com/NeoM404/GoTools/internal/inventory"
	"github.com/NeoM404/GoTools/internal/kube"
)

// addOutputFlag registers -o/--output (table|json) on a flag set, both names
// bound to the same variable so either spelling works (kubectl-style -o).
func addOutputFlag(fs *flag.FlagSet) *string {
	out := new(string)
	fs.StringVar(out, "o", "table", "output format: table|json")
	fs.StringVar(out, "output", "table", "output format: table|json")
	return out
}

// writeJSON marshals v as indented JSON to w. Returns exit code.
func writeJSON(w io.Writer, stderr io.Writer, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encoding json: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(w, string(b))
	return ExitOK
}

// badOutput reports an invalid -o value.
func badOutput(stderr io.Writer, v string) int {
	fmt.Fprintf(stderr, "invalid output format %q (want: table|json)\n", v)
	return ExitUsage
}

// loadFleet resolves config then loads the inventory from URL (preferred) or
// file. Returns the config too, since callers need prod patterns / target.
func loadFleet(cfgPath string, stderr io.Writer) (config.Config, inventory.Fleet, bool) {
	cfg, used, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	var fleet inventory.Fleet
	switch {
	case cfg.InventoryURL != "":
		fleet, err = inventory.LoadURL(cfg.InventoryURL)
	case cfg.InventoryPath != "":
		fleet, err = inventory.LoadFile(cfg.InventoryPath)
	default:
		hint := "set inventoryPath or inventoryUrl in your config"
		if used != "" {
			hint = fmt.Sprintf("%s (loaded %s)", hint, used)
		}
		fmt.Fprintf(stderr, "no inventory source configured — %s\n", hint)
		return cfg, inventory.Fleet{}, false
	}
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	if err := fleet.Validate(cfg.Environments); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return cfg, inventory.Fleet{}, false
	}
	return cfg, fleet, true
}

func cmdClusters(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: bankctl clusters <list|get> ...")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return clustersList(cfgPath, args[1:], stdout, stderr)
	case "get":
		return clustersGet(cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown clusters subcommand %q\n", args[0])
		return ExitUsage
	}
}

func clustersList(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clusters list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cloudFlag := fs.String("cloud", "", "filter by cloud (aws|azure)")
	envFlag := fs.String("env", "", "filter by environment")
	ownerFlag := fs.String("owner", "", "filter by owner substring")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	matches := fleet.Filter(*cloudFlag, *envFlag, *ownerFlag)
	if *output == "json" {
		// Always emit an array (never null) so `jq` / scripts are happy.
		if matches == nil {
			matches = []inventory.Cluster{}
		}
		return writeJSON(stdout, stderr, matches)
	}
	if len(matches) == 0 {
		fmt.Fprintln(stdout, "no clusters match")
		return ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLOUD\tENV\tREGION\tVERSION\tOWNER\tCOST-CENTRE")
	for _, c := range matches {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Cloud, c.Environment, c.Region, c.Version, c.Owner, c.CostCentre)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d cluster(s)\n", len(matches))
	return ExitOK
}

func clustersGet(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clusters get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: bankctl clusters get <name> [-o table|json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	c, err := fleet.Find(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return ExitFailure
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, c)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "Name:\t%s\n", c.Name)
	fmt.Fprintf(tw, "Cloud:\t%s\n", c.Cloud)
	fmt.Fprintf(tw, "Environment:\t%s\n", c.Environment)
	fmt.Fprintf(tw, "Region:\t%s\n", c.Region)
	fmt.Fprintf(tw, "Version:\t%s\n", c.Version)
	fmt.Fprintf(tw, "Owner:\t%s\n", c.Owner)
	fmt.Fprintf(tw, "Cost centre:\t%s\n", c.CostCentre)
	if c.Cloud == inventory.AWS {
		fmt.Fprintf(tw, "Account:\t%s\n", c.Account)
	}
	if c.Cloud == inventory.Azure {
		fmt.Fprintf(tw, "Subscription:\t%s\n", c.Subscription)
		fmt.Fprintf(tw, "Resource group:\t%s\n", c.ResourceGroup)
	}
	tw.Flush()
	return ExitOK
}

// parseInterspersed parses flags that may appear before OR after positional
// args (the Go flag package stops at the first positional by default). It
// returns the collected positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals, nil
}

func cmdKubeconfig(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kubeconfig", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fileFlag := fs.String("file", "", "write to an isolated kubeconfig file instead of the default")
	dryRun := fs.Bool("dry-run", false, "print the CLI command without running it")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: bankctl kubeconfig <cluster> [--file PATH] [--dry-run]")
		return ExitUsage
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	c, err := fleet.Find(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return ExitFailure
	}
	file := *fileFlag
	if file == "" && cfg.KubeconfigDir != "" {
		file = cfg.KubeconfigDir + "/" + c.Name + ".kubeconfig"
	}
	opts := cloud.KubeconfigOptions{File: file, DryRun: *dryRun, Stdout: stdout, Stderr: stderr, Timeout: cfg.Timeout()}
	if *dryRun {
		cmdArgs, err := cloud.UpdateKubeconfig(ctx, c, opts)
		if err != nil {
			fmt.Fprintf(stderr, "kubeconfig: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintln(stdout, strings.Join(cmdArgs, " "))
		return ExitOK
	}

	// Every credential fetch is recorded before it happens; if the record
	// cannot be written, the fetch does not happen.
	production := cfg.IsProdEnvironment(c.Environment) || kube.IsProd(c.Name, cfg.ProdPatterns)
	tr, err := beginAudit(ctx, cfg, "credentials", &c, production, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to fetch credentials: every credential fetch must be recorded\n", err)
		return ExitFailure
	}

	// Confirm the CLI will act in the cluster's own account/subscription:
	// otherwise a same-named cluster elsewhere could be fetched and labelled
	// as this one.
	id, err := cloud.VerifyIdentity(ctx, c, cfg.Timeout())
	if err != nil {
		var wrong *cloud.ErrWrongAccount
		if errors.As(err, &wrong) {
			tr.end(ctx, audit.OutcomeRefused, wrong.Principal, err.Error(), stderr)
			fmt.Fprintf(stderr, "kubeconfig refused: %v\n", err)
			return ExitFailure
		}
		tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
		reportCLIFailure(stderr, c, err)
		return ExitFailure
	}

	if _, err := cloud.UpdateKubeconfig(ctx, c, opts); err != nil {
		tr.end(ctx, audit.OutcomeFailure, id.Principal, err.Error(), stderr)
		reportCLIFailure(stderr, c, err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, id.Principal, "", stderr)
	fmt.Fprintf(stdout, "credentials for %q ready", c.Name)
	if file != "" {
		fmt.Fprintf(stdout, " in %s (use: KUBECONFIG=%s kubectl ...)", file, file)
	} else {
		fmt.Fprint(stdout, " — run `bankctl current` to confirm the active context")
	}
	fmt.Fprintln(stdout)

	// Drift hint: if the cloud CLI stamped a removed exec-auth apiVersion, the
	// kubeconfig will fail against a modern cluster. Warn (stderr) so scripting
	// stays clean. Best-effort — skip silently if kubectl can't be inspected.
	if ver, verr := kube.ExecAuthAPIVersion(ctx, file); verr == nil && kube.IsDeprecatedExecAPIVersion(ver) {
		fmt.Fprintf(stderr, "⚠  kubeconfig uses a deprecated auth plugin apiVersion (%s) — "+
			"update your %s CLI and run `bankctl doctor`.\n", ver, cliForCloud(c.Cloud))
	}
	return ExitOK
}

// reportCLIFailure prints a cloud CLI failure, with a doctor hint when the
// cause could be a missing or outdated CLI.
func reportCLIFailure(stderr io.Writer, c inventory.Cluster, err error) {
	fmt.Fprintf(stderr, "kubeconfig failed: %v\n", err)
	var notFound *execx.NotFoundError
	if !errors.As(err, &notFound) && !errors.Is(err, execx.ErrInterrupted) {
		fmt.Fprintf(stderr, "→ if this looks like a CLI/version problem, run `bankctl doctor` (check your %s CLI)\n", cliForCloud(c.Cloud))
	}
}

func cliForCloud(c inventory.Cloud) string {
	if c == inventory.Azure {
		return "az"
	}
	return "aws"
}

func cmdLogin(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	rc := cmdKubeconfig(ctx, cfgPath, args, stdout, stderr)
	if rc != 0 {
		return rc
	}
	// After fetching creds, warn loudly if the target is production. Re-parse
	// to find the positional cluster name regardless of flag ordering.
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return rc
	}
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("file", "", "")
	fs.Bool("dry-run", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 {
		return ExitOK
	}
	if c, err := fleet.Find(pos[0]); err == nil {
		if cfg.IsProdEnvironment(c.Environment) || kube.IsProd(c.Name, cfg.ProdPatterns) {
			fmt.Fprintf(stdout, "\n⚠  %q is a PRODUCTION cluster. Changes require a change record.\n", c.Name)
		}
	}
	return ExitOK
}

// contextStatus is the machine-readable shape shared by guard and current,
// so scripts parse one schema regardless of which command they call.
type contextStatus struct {
	Context     string   `json:"context"`
	Production  bool     `json:"production"`
	Cluster     string   `json:"cluster,omitempty"`     // inventory cluster the context resolves to
	Environment string   `json:"environment,omitempty"` // that cluster's environment
	Reasons     []string `json:"reasons"`               // why it is (or is not) production
}

// resolveContext loads config, reads the current kube-context and classifies
// it using both the inventory and the name patterns.
func resolveContext(ctx context.Context, cfgPath string, stderr io.Writer) (contextStatus, bool) {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return contextStatus{}, false
	}
	name, err := kube.CurrentContext(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "could not read current kube-context: %v\n", err)
		return contextStatus{}, false
	}
	cl := kube.Classify(name, guardFleet(cfg, stderr), cfg.ProdEnvs(), cfg.ProdPatterns)
	return contextStatus{Context: name, Production: cl.Production, Cluster: cl.Cluster,
		Environment: cl.Environment, Reasons: cl.Reasons}, true
}

// guardFleet loads the inventory for context classification without ever
// failing the command: guard must keep working (on name patterns) when the
// inventory is unreachable or broken, and it says so on stderr. A URL
// inventory is served from the local cache so a shell prompt stays fast.
func guardFleet(cfg config.Config, stderr io.Writer) *inventory.Fleet {
	var (
		fleet inventory.Fleet
		err   error
	)
	switch {
	case cfg.InventoryURL != "":
		var dir string
		if dir, err = inventory.DefaultCacheDir(); err == nil {
			var src inventory.Source
			fleet, src, err = inventory.LoadURLCached(cfg.InventoryURL, dir, cfg.CacheTTL())
			if err == nil && src.Kind == "stale-cache" {
				fmt.Fprintf(stderr, "warning: using cached inventory from %s ago — refresh failed: %s\n",
					src.Age.Round(time.Second), src.FetchErr)
			}
		}
	case cfg.InventoryPath != "":
		fleet, err = inventory.LoadFile(cfg.InventoryPath)
	default:
		return nil // no inventory configured: name patterns only, by design
	}
	if err == nil {
		err = fleet.Validate(cfg.Environments)
	}
	if err != nil {
		fmt.Fprintf(stderr, "warning: inventory unavailable, classifying by name patterns only: %v\n", err)
		return nil
	}
	return &fleet
}

func reasonSuffix(st contextStatus) string {
	if len(st.Reasons) == 0 {
		return ""
	}
	return "  (" + strings.Join(st.Reasons, "; ") + ")"
}

func cmdGuard(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	block := fs.Bool("block", false, "exit 3 (not 0) when the current context is production")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	st, ok := resolveContext(ctx, cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if *output == "json" {
		if rc := writeJSON(stdout, stderr, st); rc != ExitOK {
			return rc
		}
	} else if st.Production {
		fmt.Fprintf(stdout, "PROD  %s%s\n", st.Context, reasonSuffix(st))
	} else {
		fmt.Fprintf(stdout, "ok    %s\n", st.Context)
	}
	if st.Production && *block {
		return ExitProdContext
	}
	return ExitOK
}

func cmdCurrent(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("current", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	st, ok := resolveContext(ctx, cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, st)
	}
	status := "non-prod"
	if st.Production {
		status = "PRODUCTION"
	}
	fmt.Fprintf(stdout, "context: %s\nstatus:  %s\n", st.Context, status)
	if st.Cluster != "" {
		fmt.Fprintf(stdout, "cluster: %s (%s)\n", st.Cluster, st.Environment)
	}
	for _, r := range st.Reasons {
		fmt.Fprintf(stdout, "reason:  %s\n", r)
	}
	return ExitOK
}
