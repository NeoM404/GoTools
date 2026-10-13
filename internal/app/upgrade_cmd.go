package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl upgrade-check` assesses whether EKS clusters are ready for their
// next Kubernetes version (upgrade_check.go): a readiness score, blockers,
// findings with fixes, add-ons to verify upstream, and the upgrade plan with
// its commands filled in. Read-only: the EKS and EC2 APIs, then a few paged
// kubectl lists through the usual tunnel. -o json is the evidence an agent
// or a pipeline works from; --report writes the same as Markdown for the
// change request.

// eksRef is one EKS cluster to assess.
type eksRef struct {
	name, region, profile, env string
}

// upgradeKube reads a cluster with kubectl (a seam for tests).
var upgradeKube = func(ctx context.Context, cfg config.Config, ref eksRef, probes []probe, stderr io.Writer) clusterOut {
	s, code := openEKSSession(ctx, cfg, sessionFlags{cluster: ref.name, awsProfile: ref.profile, region: ref.region}, stderr)
	if code != ExitOK {
		return clusterOut{Cloud: "aws", Env: ref.env, Cluster: ref.name, Err: errors.New("could not open a tunnel to the cluster")}
	}
	defer s.close()
	sp := spinning(stderr, "Reading "+s.label()+" (paged, read-only)…")
	defer sp.Stop()
	return sessionProbes(ctx, s, probes)
}

func cmdUpgradeCheck(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("upgrade-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	target := fs.String("target", "", "the version to assess, e.g. 1.32 (default: the next minor)")
	report := fs.String("report", "", "also write the assessment as Markdown to this new file (for the change request)")
	minSev := fs.String("min", "low", "show findings at least this severe: info, low, medium, high, critical")
	failOn := failOnFlag(fs, "none")
	failBelow := fs.Int("fail-below", 0, "exit 1 when a cluster's readiness score is below this (e.g. 80), or it has a blocker")
	output := fs.String("o", "table", "output format: table|json|md")
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl upgrade-check [--cluster C | --aws | --aws-env ete,qa] [--match WORD] [--target 1.32] [--report FILE.md] [--fail-below 80] [-o table|json|md]"
	if err == nil && len(pos) == 1 && sel.cluster == "" {
		sel.cluster, pos = pos[0], nil
	}
	if err != nil || len(pos) > 0 || severityRank(*minSev) < 0 || !validFailOn(*failOn) || *failBelow < 0 || *failBelow > 100 ||
		(*target != "" && minorOf(*target) == 0) || (*output != "table" && *output != "json" && *output != "md") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if sel.env != "" {
		fmt.Fprintln(stderr, "upgrade-check covers EKS for now (--cluster, --aws or --aws-env); AKS comes next — nedctl expiry --env shows AKS versions' support")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if !cfg.AWS.Configured() {
		fmt.Fprintln(stderr, "upgrade-check needs AWS access — run `nedctl setup`")
		return ExitFailure
	}
	refs, code := eksRefs(ctx, cfg, sel, stderr)
	if code != ExitOK {
		return code
	}
	var reports []upgradeReport
	for _, ref := range refs {
		reports = append(reports, checkOneUpgrade(ctx, cfg, ref, *target, stderr))
	}
	switch *output {
	case "json":
		cl := make([]any, len(reports))
		for i, r := range reports {
			cl[i] = r
		}
		if code := writeJSON(stdout, stderr, map[string]any{"schema": findingsSchema, "command": "upgrade-check", "generated": now().UTC().Format("2006-01-02T15:04:05Z"), "clusters": cl}); code != ExitOK {
			return code
		}
	case "md":
		fmt.Fprint(stdout, upgradeMarkdown(reports))
	default:
		printUpgrade(stdout, cfg, reports, *minSev)
	}
	if *report != "" {
		if err := writeNewFile(*report, []byte(upgradeMarkdown(reports))); err != nil {
			fmt.Fprintf(stderr, "writing the report: %v\n", err)
			return ExitFailure
		}
		fmt.Fprintf(stderr, "report written to %s\n", *report)
	}
	exit := ExitOK
	var fs2 []clusterFindings
	for _, r := range reports {
		fs2 = append(fs2, r.clusterFindings)
		if *failBelow > 0 && (r.Score == nil || *r.Score < *failBelow || len(r.Blockers) > 0) {
			exit = ExitFailure
		}
	}
	if failed(fs2, *failOn) {
		exit = ExitFailure
	}
	return exit
}

// eksRefs are the clusters chosen: one (--cluster, or picked), the
// signed-in account's (--aws), or the squad's accounts per environment
// (--aws-env).
func eksRefs(ctx context.Context, cfg config.Config, sel clusterSel, stderr io.Writer) ([]eksRef, int) {
	inAccount := func(pc profileContext) ([]eksRef, error) {
		hits, _, err := searchRegions(ctx, cfg, pc, regionSearch{}, "eks", stderr, func(region string) ([]clusterHit, error) {
			return clustersIn(ctx, cfg, pc.Name, region)
		})
		if err != nil {
			return nil, err
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
		var out []eksRef
		for _, h := range hits {
			if sel.match == "" || strings.Contains(h.Name, sel.match) {
				out = append(out, eksRef{name: h.Name, region: h.Region, profile: pc.Name, env: pc.Environment})
			}
		}
		return out, nil
	}
	pc, ok := loadProfileContext(ctx, cfg, sel.awsProfile, stderr)
	if !ok {
		return nil, ExitFailure
	}
	var refs []eksRef
	switch {
	case sel.awsEnv != "":
		for _, env := range strings.Split(strings.ToLower(sel.awsEnv), ",") {
			if env = strings.TrimSpace(env); env == "" {
				continue
			}
			name, err := profileForEnv(ctx, cfg, pc, env, stderr)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", strings.ToUpper(env), err)
				continue
			}
			epc, ok := loadProfileContext(ctx, cfg, name, stderr)
			if !ok {
				continue
			}
			r, err := inAccount(epc)
			if err != nil {
				fmt.Fprintf(stderr, "%s: listing clusters: %v\n", strings.ToUpper(env), err)
				continue
			}
			refs = append(refs, r...)
		}
	case sel.aws:
		r, err := inAccount(pc)
		if err != nil {
			fmt.Fprintf(stderr, "listing clusters: %v\n", err)
			return nil, ExitFailure
		}
		refs = r
	default:
		var p []string
		if sel.cluster != "" {
			if !eksNameRe.MatchString(sel.cluster) {
				fmt.Fprintf(stderr, "%q is not a cluster name\n", sel.cluster)
				return nil, ExitUsage
			}
			p = []string{sel.cluster}
		}
		name, rs, code := resolveClusterArg(ctx, cfg, pc, regionSearch{}, p, stderr)
		if code != ExitOK {
			return nil, code
		}
		region := rs.Flag
		if region == "" {
			r, err := findCluster(ctx, cfg, pc, rs, name, stderr)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return nil, ExitFailure
			}
			region = r
		}
		refs = []eksRef{{name: name, region: region, profile: pc.Name, env: pc.Environment}}
	}
	if len(refs) == 0 {
		fmt.Fprintln(stderr, "no EKS clusters to assess")
		return nil, ExitFailure
	}
	return refs, ExitOK
}

func checkOneUpgrade(ctx context.Context, cfg config.Config, ref eksRef, target string, stderr io.Writer) upgradeReport {
	sp := spinning(stderr, "Reading "+ref.name+" from the EKS API ("+ref.region+")…")
	facts := gatherEKSFacts(ctx, cfg, ref.profile, ref.region, ref.name, target)
	sp.Stop()
	if msg, bad := facts.Errors["cluster"]; bad {
		r := upgradeReport{clusterFindings: clusterFindings{Cloud: "aws", Environment: ref.env, Cluster: ref.name, Status: "unreachable", Error: msg, Findings: []checkFinding{}}, Region: ref.region, Tier: "NOT ASSESSED", Blockers: []string{}}
		return r
	}
	t := target
	if t == "" {
		t = nextMinor(facts.Version)
	}
	if minorOf(t) <= minorOf(facts.Version) {
		r := upgradeReport{clusterFindings: clusterFindings{Cloud: "aws", Environment: ref.env, Cluster: ref.name, Status: "ok", Findings: []checkFinding{}}, Region: ref.region,
			Current: facts.Version, Target: t, Tier: "NOT ASSESSED", Blockers: []string{}}
		r.unassessed("the cluster already runs %s: nothing to upgrade to %s", facts.Version, t)
		return r
	}
	co := upgradeKube(ctx, cfg, ref, upgradeProbes(minorOf(t)), stderr)
	co.Env = ref.env
	r := assessUpgrade(cfg, facts, co, t, now())
	r.Environment = ref.env
	return r
}

func tierStyle(st ui.Style, tier string) string {
	switch tier {
	case "READY", "GOOD":
		return st.OK(tier)
	case "FAIR":
		return st.Fg(ui.Amber, tier)
	case "NOT ASSESSED":
		return st.Dim(tier)
	}
	return st.Fail(tier)
}

func printUpgrade(w io.Writer, cfg config.Config, reports []upgradeReport, minSev string) {
	st := ui.Style{Color: colorOn(w)}
	for i, r := range reports {
		if i > 0 {
			fmt.Fprintln(w, "\n"+strings.Repeat("─", 60))
		}
		head := strings.TrimSpace(strings.ToUpper(r.Environment) + " " + r.Cluster)
		fmt.Fprintf(w, "%s  %s  %s\n", st.BoldFg(cfg.ColorFor(r.Environment), head), st.Dim(r.Region), st.Bold(firstNonBlank(r.Current, "?")+" → "+firstNonBlank(r.Target, "?")))
		if r.Status == "unreachable" {
			fmt.Fprintln(w, st.Fail("not assessed: "+r.Error))
			continue
		}
		score := ""
		if r.Score != nil {
			score = fmt.Sprintf("%d%% ", *r.Score)
		}
		line := "Readiness " + st.Bold(score) + tierStyle(st, r.Tier)
		if r.Provisional {
			line += st.Dim(fmt.Sprintf("  (provisional: %d check(s) not assessed, %d add-on(s) to verify)", len(r.Unassessed), len(r.Verify)))
		}
		fmt.Fprintln(w, line)
		if len(r.Blockers) > 0 {
			fmt.Fprintln(w, st.Fail("Blockers:"))
			for _, b := range r.Blockers {
				fmt.Fprintln(w, "  ✖ "+b)
			}
		}
		if len(r.Breakdown) > 0 {
			tw := newTable(w)
			fmt.Fprintln(tw, "AREA\tPOINTS LOST\tOF")
			for _, b := range r.Breakdown {
				if b.Deducted > 0 {
					fmt.Fprintf(tw, "%s\t%d\t%d\n", b.Area, b.Deducted, b.Max)
				}
			}
			tw.Flush()
		}
		fmt.Fprintln(w)
		printReport(w, cfg, []clusterFindings{r.clusterFindings}, minSev)
		if len(r.Verify) > 0 {
			fmt.Fprintf(w, "\n%s\n", st.Heading("Verify against the project (nedctl does not guess)"))
			tw := newTable(w)
			fmt.Fprintln(tw, "ADD-ON\tVERSION\tWHERE\tSUPPORTED VERSIONS")
			for _, v := range r.Verify {
				name := v.Name
				if v.Critical {
					name += " (cluster CNI)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, v.Version, v.Where, v.URL)
			}
			tw.Flush()
		}
		if len(r.Plan) > 0 {
			fmt.Fprintf(w, "\n%s %s\n", st.Heading("Upgrade plan"), st.Dim("(nedctl never runs these)"))
			for n, p := range r.Plan {
				fmt.Fprintf(w, "%d. %s\n", n+1, st.Bold(p.Title))
				for _, c := range p.Commands {
					fmt.Fprintln(w, "     "+c)
				}
				for _, x := range p.Notes {
					fmt.Fprintln(w, "     · "+x)
				}
			}
		}
	}
	fmt.Fprintf(w, "\n%s\n", st.Dim("-o json is the evidence (for a pipeline or an agent) · --report FILE.md for the change request · read-only"))
}

// upgradeMarkdown is the assessment for a change request.
func upgradeMarkdown(reports []upgradeReport) string {
	var b strings.Builder
	for i, r := range reports {
		if i > 0 {
			b.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&b, "# EKS upgrade readiness: %s (%s)\n\n", r.Cluster, firstNonBlank(r.Region, "?"))
		fmt.Fprintf(&b, "- **Environment:** %s\n- **Upgrade:** %s → %s\n- **Assessed:** %s by nedctl %s (read-only)\n", strings.ToUpper(r.Environment), r.Current, r.Target, now().UTC().Format("2006-01-02 15:04 UTC"), Version)
		if r.Status == "unreachable" {
			fmt.Fprintf(&b, "\n**Not assessed:** %s\n", r.Error)
			continue
		}
		score := "not scored"
		if r.Score != nil {
			score = fmt.Sprintf("%d%%", *r.Score)
		}
		fmt.Fprintf(&b, "- **Readiness:** %s — **%s**", score, r.Tier)
		if r.Provisional {
			b.WriteString(" (provisional: see Not assessed and Verify)")
		}
		b.WriteString("\n\n## Blockers\n\n")
		if len(r.Blockers) == 0 {
			b.WriteString("None.\n")
		}
		for _, x := range r.Blockers {
			fmt.Fprintf(&b, "- %s\n", x)
		}
		if len(r.Breakdown) > 0 {
			b.WriteString("\n## Score\n\n| Area | Points lost | Of |\n|---|---|---|\n")
			for _, x := range r.Breakdown {
				fmt.Fprintf(&b, "| %s | %d | %d |\n", x.Area, x.Deducted, x.Max)
			}
		}
		b.WriteString("\n## Findings\n\n| Severity | Area | Check | Object | Finding | Fix |\n|---|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			what := f.Title + ifNonBlank(" — ", f.Detail)
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", strings.ToUpper(f.Severity), f.Area, f.Check, mdCell(f.Object), mdCell(what), mdCell(f.Fix))
		}
		if len(r.Unassessed) > 0 {
			b.WriteString("\n## Not assessed (not a pass)\n\n")
			for _, u := range r.Unassessed {
				fmt.Fprintf(&b, "- %s\n", u)
			}
		}
		if len(r.Verify) > 0 {
			b.WriteString("\n## Verify against the project\n\n| Add-on | Version | Where | Supported versions |\n|---|---|---|---|\n")
			for _, v := range r.Verify {
				fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", v.Name, v.Version, v.Where, v.URL)
			}
		}
		b.WriteString("\n## Upgrade plan\n\n")
		for n, p := range r.Plan {
			fmt.Fprintf(&b, "%d. **%s**\n", n+1, p.Title)
			if len(p.Commands) > 0 {
				b.WriteString("   ```bash\n")
				for _, c := range p.Commands {
					fmt.Fprintf(&b, "   %s\n", c)
				}
				b.WriteString("   ```\n")
			}
			for _, x := range p.Notes {
				fmt.Fprintf(&b, "   - %s\n", x)
			}
		}
	}
	return b.String()
}

func mdCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
