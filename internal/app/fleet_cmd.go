package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
	"nedctl/internal/support"
)

// now is the clock; tests pin it so date arithmetic is deterministic.
var now = time.Now

func cmdFleet(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl fleet <versions|eol|calendar> ...")
		return ExitUsage
	}
	switch args[0] {
	case "versions":
		return fleetVersions(cfgPath, args[1:], stdout, stderr)
	case "eol":
		return fleetEOL(cfgPath, args[1:], stdout, stderr)
	case "calendar":
		return fleetCalendar(ctx, cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown fleet subcommand %q\n", args[0])
		return ExitUsage
	}
}

// ---- fleet versions ----

func fleetVersions(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleet versions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	failOnStale := fs.Bool("fail-on-stale", false, "exit 1 if any cluster is STALE")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if !cfg.HasTargets() {
		fmt.Fprintln(stderr, "set targetKubeVersion (and optionally per-environment targetKubeVersions) in config to run the drift report")
		return ExitFailure
	}

	type row struct {
		Name        string                `json:"name"`
		Cloud       inventory.Cloud       `json:"cloud"`
		Environment string                `json:"environment"`
		Version     string                `json:"version"`
		Target      string                `json:"target"`
		Status      inventory.DriftStatus `json:"status"`
	}
	rows := []row{}
	stale := 0
	for _, c := range fleet.Filter("", "", "") {
		target := cfg.TargetFor(c.Environment)
		status := inventory.Classify(c.Version, target)
		if status == inventory.StatusStale {
			stale++
		}
		rows = append(rows, row{c.Name, c.Cloud, c.Environment, c.Version, target, status})
	}
	code := ExitOK
	if *failOnStale && stale > 0 {
		code = ExitFailure
	}

	if *output == "json" {
		if rc := writeJSON(stdout, stderr, rows); rc != ExitOK {
			return rc
		}
		return code
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCLOUD\tENV\tVERSION\tTARGET\tSTATUS")
	for _, r := range rows {
		target := r.Target
		if target == "" {
			target = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Cloud, r.Environment, r.Version, target, r.Status)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%s | %d stale cluster(s)\n", describeTargets(cfg), stale)
	return code
}

func describeTargets(cfg config.Config) string {
	if len(cfg.TargetKubeVersions) == 0 {
		return "target " + cfg.TargetKubeVersion
	}
	envs := make([]string, 0, len(cfg.TargetKubeVersions))
	for e := range cfg.TargetKubeVersions {
		envs = append(envs, e)
	}
	sort.Strings(envs)
	parts := make([]string, 0, len(envs)+1)
	if cfg.TargetKubeVersion != "" {
		parts = append(parts, "default "+cfg.TargetKubeVersion)
	}
	for _, e := range envs {
		parts = append(parts, e+" "+cfg.TargetKubeVersions[e])
	}
	return "targets: " + strings.Join(parts, ", ")
}

// ---- fleet eol ----

type eolRow struct {
	Name        string          `json:"name"`
	Cloud       inventory.Cloud `json:"cloud"`
	Environment string          `json:"environment"`
	Version     string          `json:"version"`
	Owner       string          `json:"owner,omitempty"`
	CostCentre  string          `json:"costCentre,omitempty"`
	support.Assessment
	// Money is a decimal string ("365.00") so no consumer reintroduces
	// floating-point error.
	PremiumMonthly   string `json:"premiumMonthly,omitempty"`
	ProjectedMonthly string `json:"projectedPremiumMonthly,omitempty"`
}

type eolSummary struct {
	Unsupported      int    `json:"unsupported"`
	Extended         int    `json:"extended"`
	Ending           int    `json:"ending"`
	Unknown          int    `json:"unknown"`
	OK               int    `json:"ok"`
	PremiumMonthly   string `json:"premiumMonthly,omitempty"`
	ProjectedMonthly string `json:"projectedPremiumMonthly,omitempty"`
}

type costCentreRow struct {
	CostCentre       string `json:"costCentre"`
	Clusters         int    `json:"clusters"`
	AtRisk           int    `json:"atRisk"`
	PremiumMonthly   string `json:"premiumMonthly,omitempty"`
	ProjectedMonthly string `json:"projectedPremiumMonthly,omitempty"`
}

type eolReport struct {
	Today        string          `json:"today"`
	WarnDays     int             `json:"warnDays"`
	Currency     string          `json:"currency,omitempty"`
	AtRisk       bool            `json:"atRisk"`
	Clusters     []eolRow        `json:"clusters"`
	Summary      eolSummary      `json:"summary"`
	ByCostCentre []costCentreRow `json:"byCostCentre"`
}

func fleetEOL(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleet eol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	warnDays := fs.Int("warn-days", 90, "flag clusters whose standard support ends within this many days")
	failOnRisk := fs.Bool("fail-on-risk", false, "exit 1 if any cluster is unsupported, in extended support, ending soon, or unknown")
	byCC := fs.Bool("by-cost-centre", false, "add a roll-up per cost centre")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if *warnDays < 0 {
		fmt.Fprintln(stderr, "--warn-days must be zero or more")
		return ExitUsage
	}
	cfg, fleet, ok := loadFleet(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	if cfg.SupportCalendar.Empty() {
		fmt.Fprintln(stderr, "no supportCalendar configured — generate the AWS part with `nedctl fleet calendar aws`; "+
			"add Azure dates from the AKS release calendar (Azure publishes no API for them). See docs/nedctl.md.")
		return ExitFailure
	}

	today := now()
	rep := eolReport{Today: today.UTC().Format("2006-01-02"), WarnDays: *warnDays, Clusters: []eolRow{}, ByCostCentre: []costCentreRow{}}
	priced := cfg.CostRates.Configured()
	if priced {
		rep.Currency = cfg.CostRates.Currency
	}

	type ccAgg struct {
		clusters, atRisk   int
		premium, projected int64
	}
	byCostCentre := map[string]*ccAgg{}
	var premium, projected int64
	for _, c := range fleet.Filter("", "", "") {
		a := support.Assess(cfg.SupportCalendar, cfg.CostRates, c.Cloud, c.Version, today, *warnDays)
		row := eolRow{Name: c.Name, Cloud: c.Cloud, Environment: c.Environment, Version: c.Version,
			Owner: c.Owner, CostCentre: c.CostCentre, Assessment: a}
		// Projected premium is counted only for clusters about to lose
		// standard support — the money at stake inside the warning window.
		proj := int64(0)
		if a.Status == support.Ending {
			proj = a.ProjectedMicros
		}
		if priced {
			if a.PremiumMicros > 0 {
				row.PremiumMonthly = support.Money(a.PremiumMicros)
			}
			if proj > 0 {
				row.ProjectedMonthly = support.Money(proj)
			}
		}
		premium += a.PremiumMicros
		projected += proj
		switch a.Status {
		case support.Unsupported:
			rep.Summary.Unsupported++
		case support.Extended:
			rep.Summary.Extended++
		case support.Ending:
			rep.Summary.Ending++
		case support.Unknown:
			rep.Summary.Unknown++
		default:
			rep.Summary.OK++
		}
		cc := c.CostCentre
		if cc == "" {
			cc = "(none)"
		}
		agg := byCostCentre[cc]
		if agg == nil {
			agg = &ccAgg{}
			byCostCentre[cc] = agg
		}
		agg.clusters++
		if a.Status.AtRisk() {
			agg.atRisk++
			rep.AtRisk = true
		}
		agg.premium += a.PremiumMicros
		agg.projected += proj
		rep.Clusters = append(rep.Clusters, row)
	}
	sort.SliceStable(rep.Clusters, func(i, j int) bool {
		a, b := rep.Clusters[i], rep.Clusters[j]
		if a.Status.Rank() != b.Status.Rank() {
			return a.Status.Rank() < b.Status.Rank()
		}
		if (a.DaysLeft == nil) != (b.DaysLeft == nil) {
			return b.DaysLeft == nil
		}
		if a.DaysLeft != nil && *a.DaysLeft != *b.DaysLeft {
			return *a.DaysLeft < *b.DaysLeft
		}
		return a.Name < b.Name
	})
	if priced {
		rep.Summary.PremiumMonthly = support.Money(premium)
		rep.Summary.ProjectedMonthly = support.Money(projected)
	}
	ccs := make([]string, 0, len(byCostCentre))
	for cc := range byCostCentre {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)
	for _, cc := range ccs {
		a := byCostCentre[cc]
		r := costCentreRow{CostCentre: cc, Clusters: a.clusters, AtRisk: a.atRisk}
		if priced {
			r.PremiumMonthly, r.ProjectedMonthly = support.Money(a.premium), support.Money(a.projected)
		}
		rep.ByCostCentre = append(rep.ByCostCentre, r)
	}

	code := ExitOK
	if *failOnRisk && rep.AtRisk {
		code = ExitFailure
	}
	if *output == "json" {
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}

	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	header := "NAME\tCLOUD\tENV\tVERSION\tSTATUS\tPHASE ENDS\tDAYS"
	if priced {
		header += "\tPREMIUM/MO (" + rep.Currency + ")"
	}
	fmt.Fprintln(tw, header)
	for _, r := range rep.Clusters {
		ends, days := dash(r.PhaseEnds), "-"
		if r.DaysLeft != nil {
			days = fmt.Sprint(*r.DaysLeft)
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", r.Name, r.Cloud, r.Environment, r.Version, r.Status, ends, days)
		if priced {
			switch {
			case r.PremiumMonthly != "":
				line += "\t" + r.PremiumMonthly
			case r.ProjectedMonthly != "":
				line += "\t" + r.ProjectedMonthly + " from " + r.PhaseEnds
			default:
				line += "\t-"
			}
		}
		fmt.Fprintln(tw, line)
	}
	tw.Flush()

	s := rep.Summary
	fmt.Fprintf(stdout, "\ntoday %s · warning window %d days\n", rep.Today, rep.WarnDays)
	fmt.Fprintf(stdout, "%d unsupported · %d in extended support · %d ending within %d days · %d unknown · %d ok\n",
		s.Unsupported, s.Extended, s.Ending, rep.WarnDays, s.Unknown, s.OK)
	if priced {
		fmt.Fprintf(stdout, "extended-support premium: %s %s/month now", rep.Currency, s.PremiumMonthly)
		if s.Ending > 0 {
			fmt.Fprintf(stdout, "; +%s %s/month if the %d ending cluster(s) are not upgraded in time", rep.Currency, s.ProjectedMonthly, s.Ending)
		}
		fmt.Fprintln(stdout)
	}
	if s.Unknown > 0 {
		fmt.Fprintln(stderr, "note: 'unknown' clusters have no supportCalendar entry for their version — add one so their lifecycle can be assured")
	}

	if *byCC {
		fmt.Fprintln(stdout)
		tw = tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		h := "COST CENTRE\tCLUSTERS\tAT RISK"
		if priced {
			h += "\tPREMIUM/MO\tPROJECTED/MO"
		}
		fmt.Fprintln(tw, h)
		for _, r := range rep.ByCostCentre {
			line := fmt.Sprintf("%s\t%d\t%d", r.CostCentre, r.Clusters, r.AtRisk)
			if priced {
				line += "\t" + r.PremiumMonthly + "\t" + r.ProjectedMonthly
			}
			fmt.Fprintln(tw, line)
		}
		tw.Flush()
	}
	return code
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- fleet calendar ----

const aksCalendarURL = "https://learn.microsoft.com/azure/aks/supported-kubernetes-versions"

func fleetCalendar(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleet calendar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "AWS CLI profile (default: the first discovery.aws profile)")
	region := fs.String("region", "", "AWS region to query (default: the first discovery.aws region)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: nedctl fleet calendar aws [--profile P] [--region R]")
		return ExitUsage
	}
	switch pos[0] {
	case "aws":
	case "azure":
		fmt.Fprintf(stderr, "Azure publishes no API for AKS support dates; maintain supportCalendar.azure from %s\n", aksCalendarURL)
		return ExitUsage
	default:
		fmt.Fprintf(stderr, "unknown cloud %q (want aws)\n", pos[0])
		return ExitUsage
	}

	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if len(cfg.Discovery.AWS) > 0 {
		if *profile == "" {
			*profile = cfg.Discovery.AWS[0].Profile
		}
		if *region == "" {
			*region = cfg.Discovery.AWS[0].Regions[0]
		}
	}
	if *region == "" {
		fmt.Fprintln(stderr, "--region is required (no discovery.aws target to default from)")
		return ExitUsage
	}

	awsArgs := []string{"eks", "describe-cluster-versions", "--region", *region, "--output", "json"}
	if *profile != "" {
		awsArgs = append(awsArgs, "--profile", *profile)
	}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", awsArgs...)
	if err != nil {
		fmt.Fprintf(stderr, "fetching EKS version lifecycle: %v\n", err)
		return ExitFailure
	}
	cal, err := parseEKSVersions(out)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return ExitFailure
	}
	if rc := writeJSON(stdout, stderr, cal); rc != ExitOK {
		return rc
	}
	fmt.Fprintf(stderr, "%d AWS version(s) — paste under \"supportCalendar\" in your config. Add Azure dates from %s\n", len(cal.AWS), aksCalendarURL)
	return ExitOK
}

// parseEKSVersions turns `aws eks describe-cluster-versions` output into a
// calendar. Timestamps may arrive as ISO 8601 strings (the CLI default) or
// epoch seconds (cli_timestamp_format = none), so both are accepted.
func parseEKSVersions(data []byte) (support.Calendar, error) {
	var resp struct {
		ClusterVersions []struct {
			ClusterVersion string          `json:"clusterVersion"`
			StandardEnd    json.RawMessage `json:"endOfStandardSupportDate"`
			ExtendedEnd    json.RawMessage `json:"endOfExtendedSupportDate"`
		} `json:"clusterVersions"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return support.Calendar{}, fmt.Errorf("parsing eks describe-cluster-versions: %w", err)
	}
	cal := support.Calendar{AWS: map[string]support.Window{}}
	for _, v := range resp.ClusterVersions {
		std, err := awsDate(v.StandardEnd)
		if err != nil {
			return support.Calendar{}, fmt.Errorf("version %s: %w", v.ClusterVersion, err)
		}
		ext, err := awsDate(v.ExtendedEnd)
		if err != nil {
			return support.Calendar{}, fmt.Errorf("version %s: %w", v.ClusterVersion, err)
		}
		if v.ClusterVersion == "" || std == "" {
			continue // no lifecycle published for this entry
		}
		cal.AWS[v.ClusterVersion] = support.Window{StandardEnd: std, ExtendedEnd: ext}
	}
	if err := cal.Validate(); err != nil {
		return support.Calendar{}, fmt.Errorf("EKS returned an inconsistent lifecycle: %w", err)
	}
	return cal, nil
}

func awsDate(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700", "2006-01-02"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC().Format("2006-01-02"), nil
			}
		}
		return "", fmt.Errorf("unrecognised timestamp %q", s)
	}
	var epoch float64
	if err := json.Unmarshal(raw, &epoch); err == nil {
		return time.Unix(int64(epoch), 0).UTC().Format("2006-01-02"), nil
	}
	return "", fmt.Errorf("unrecognised timestamp %s", raw)
}
