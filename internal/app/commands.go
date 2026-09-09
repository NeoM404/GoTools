package app

import (
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/NeoM404/GoTools/internal/cloud"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/inventory"
	"github.com/NeoM404/GoTools/internal/kube"
)

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
	return cfg, fleet, true
}

func cmdClusters(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: bankctl clusters <list|get> ...")
		return 2
	}
	switch args[0] {
	case "list":
		return clustersList(cfgPath, args[1:], stdout, stderr)
	case "get":
		return clustersGet(cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown clusters subcommand %q\n", args[0])
		return 2
	}
}

func clustersList(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("clusters list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cloudFlag := fs.String("cloud", "", "filter by cloud (aws|azure)")
	envFlag := fs.String("env", "", "filter by environment")
	ownerFlag := fs.String("owner", "", "filter by owner substring")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return 1
	}
	matches := fleet.Filter(*cloudFlag, *envFlag, *ownerFlag)
	if len(matches) == 0 {
		fmt.Fprintln(stdout, "no clusters match")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLOUD\tENV\tREGION\tVERSION\tOWNER\tCOST-CENTRE")
	for _, c := range matches {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Cloud, c.Environment, c.Region, c.Version, c.Owner, c.CostCentre)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d cluster(s)\n", len(matches))
	return 0
}

func clustersGet(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: bankctl clusters get <name>")
		return 2
	}
	_, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return 1
	}
	c, err := fleet.Find(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
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
	return 0
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

func cmdKubeconfig(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kubeconfig", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fileFlag := fs.String("file", "", "write to an isolated kubeconfig file instead of the default")
	dryRun := fs.Bool("dry-run", false, "print the CLI command without running it")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: bankctl kubeconfig <cluster> [--file PATH] [--dry-run]")
		return 2
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return 1
	}
	c, err := fleet.Find(pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	file := *fileFlag
	if file == "" && cfg.KubeconfigDir != "" {
		file = cfg.KubeconfigDir + "/" + c.Name + ".kubeconfig"
	}
	cmdArgs, err := cloud.UpdateKubeconfig(c, cloud.KubeconfigOptions{
		File: file, DryRun: *dryRun, Stdout: stdout, Stderr: stderr,
	})
	if *dryRun {
		fmt.Fprintln(stdout, join(cmdArgs))
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "kubeconfig failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "credentials for %q ready", c.Name)
	if file != "" {
		fmt.Fprintf(stdout, " in %s", file)
	}
	fmt.Fprintln(stdout)
	return 0
}

func cmdLogin(cfgPath string, args []string, stdout, stderr io.Writer) int {
	rc := cmdKubeconfig(cfgPath, args, stdout, stderr)
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
		return 0
	}
	if c, err := fleet.Find(pos[0]); err == nil {
		if c.Environment == "prod" || kube.IsProd(c.Name, cfg.ProdPatterns) {
			fmt.Fprintf(stdout, "\n⚠  %q is a PRODUCTION cluster. Changes require a change record.\n", c.Name)
		}
	}
	return 0
}

func cmdFleet(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "versions" {
		fmt.Fprintln(stderr, "usage: bankctl fleet versions [--fail-on-stale]")
		return 2
	}
	fs := flag.NewFlagSet("fleet versions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	failOnStale := fs.Bool("fail-on-stale", false, "exit 1 if any cluster is STALE")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return 1
	}
	if cfg.TargetKubeVersion == "" {
		fmt.Fprintln(stderr, "set targetKubeVersion in config to run the drift report")
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLOUD\tENV\tVERSION\tTARGET\tSTATUS")
	stale := 0
	for _, c := range fleet.Filter("", "", "") {
		status := inventory.Classify(c.Version, cfg.TargetKubeVersion)
		if status == inventory.StatusStale {
			stale++
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Cloud, c.Environment, c.Version, cfg.TargetKubeVersion, status)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\ntarget %s | %d stale cluster(s)\n", cfg.TargetKubeVersion, stale)
	if *failOnStale && stale > 0 {
		return 1
	}
	return 0
}

func cmdGuard(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	block := fs.Bool("block", false, "exit 3 (not 0) when the current context is production")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	ctx, err := kube.CurrentContext()
	if err != nil {
		fmt.Fprintf(stderr, "could not read current kube-context (is kubectl configured?): %v\n", err)
		return 1
	}
	if kube.IsProd(ctx, cfg.ProdPatterns) {
		fmt.Fprintf(stdout, "PROD  %s\n", ctx)
		if *block {
			return 3
		}
		return 0
	}
	fmt.Fprintf(stdout, "ok    %s\n", ctx)
	return 0
}

func cmdCurrent(cfgPath string, stdout, stderr io.Writer) int {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	ctx, err := kube.CurrentContext()
	if err != nil {
		fmt.Fprintf(stderr, "could not read current kube-context: %v\n", err)
		return 1
	}
	status := "non-prod"
	if kube.IsProd(ctx, cfg.ProdPatterns) {
		status = "PRODUCTION"
	}
	fmt.Fprintf(stdout, "context: %s\nstatus:  %s\n", ctx, status)
	return 0
}

func join(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
