package app

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// Findings are what the checking commands (expiry, upgrade-check, mesh,
// why, capacity, images scan) report, in one shape: a severity, the check
// that found it, the object, what was seen, and what to do. One shape means
// one JSON schema for pipelines and agents (findingsSchema), one --fail-on
// gate, and one way to print them.

// findingsSchema names the JSON layout; it changes only when a field is
// removed or changes meaning (added fields keep it).
const findingsSchema = "nedctl.findings/v1"

// Severities, lowest first.
var severities = []string{"info", "low", "medium", "high", "critical"}

func severityRank(s string) int {
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return -1
}

// checkFinding is one thing a check found on one cluster.
type checkFinding struct {
	Check    string `json:"check"`
	Area     string `json:"area,omitempty"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Object   string `json:"object,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	Source   string `json:"source,omitempty"` // where the evidence came from (kubernetes, eks-api, ecr, trivy…)
	Blocker  bool   `json:"blocker,omitempty"`
}

// clusterFindings is one cluster's report.
type clusterFindings struct {
	Cloud       string         `json:"cloud,omitempty"`
	Environment string         `json:"environment"`
	Cluster     string         `json:"cluster"`
	Status      string         `json:"status"` // the highest severity found, "ok", or "unreachable"
	Error       string         `json:"error,omitempty"`
	Summary     map[string]any `json:"summary,omitempty"`
	Findings    []checkFinding `json:"findings"`
	// Unassessed are checks that could not run (denied, missing, timed
	// out): never counted as a pass.
	Unassessed []string `json:"unassessed,omitempty"`
}

func newClusterFindings(r clusterOut) clusterFindings {
	cf := clusterFindings{Cloud: r.Cloud, Environment: r.Env, Cluster: firstNonBlank(r.Cluster, r.Where), Status: "ok", Findings: []checkFinding{}}
	if err := r.Err; err != nil {
		cf.Status, cf.Error = "unreachable", err.Error()
	}
	return cf
}

func (cf *clusterFindings) add(f checkFinding) { cf.Findings = append(cf.Findings, f) }

func (cf *clusterFindings) unassessed(format string, a ...any) {
	cf.Unassessed = append(cf.Unassessed, fmt.Sprintf(format, a...))
}

// finish orders the findings (worst first) and sets the status.
func (cf *clusterFindings) finish() {
	sort.SliceStable(cf.Findings, func(i, j int) bool {
		a, b := cf.Findings[i], cf.Findings[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Object < b.Object
	})
	if cf.Status == "unreachable" {
		return
	}
	cf.Status = "ok"
	if len(cf.Findings) > 0 && severityRank(cf.Findings[0].Severity) > 0 {
		cf.Status = cf.Findings[0].Severity
	}
}

// failOnFlag is --fail-on: the severity from which a run exits 1.
func failOnFlag(fs *flag.FlagSet, def string) *string {
	return fs.String("fail-on", def, "exit 1 when a finding is at least this severe: "+strings.Join(severities[1:], ", ")+" or none")
}

func validFailOn(v string) bool { return v == "none" || severityRank(v) > 0 }

// failed reports whether a report should make the command exit 1: an
// unreachable cluster, or a finding at or above failOn.
func failed(report []clusterFindings, failOn string) bool {
	for _, c := range report {
		if c.Status == "unreachable" {
			return true
		}
		if failOn == "none" {
			continue
		}
		for _, f := range c.Findings {
			if severityRank(f.Severity) >= severityRank(failOn) {
				return true
			}
		}
	}
	return false
}

// findingsDoc is the JSON document every checking command writes.
func findingsDoc(command string, report []clusterFindings, extra map[string]any) map[string]any {
	doc := map[string]any{"schema": findingsSchema, "command": command, "generated": now().UTC().Format("2006-01-02T15:04:05Z"), "clusters": report}
	for k, v := range extra {
		doc[k] = v
	}
	return doc
}

// severityStyle colours a severity word.
func severityStyle(st ui.Style, s string) string {
	switch s {
	case "critical", "high":
		return st.Fail(strings.ToUpper(s))
	case "medium":
		return st.Fg(ui.Amber, strings.ToUpper(s))
	case "low":
		return st.Dim(strings.ToUpper(s))
	case "ok":
		return st.OK("OK")
	}
	return st.Dim(strings.ToUpper(s))
}

// printReport prints each cluster's findings: a heading, then a table
// (worst first), then what could not be checked. minSev hides findings
// below it (the count still shows).
func printReport(w io.Writer, cfg config.Config, report []clusterFindings, minSev string) {
	st := ui.Style{Color: colorOn(w)}
	for i, c := range report {
		if i > 0 {
			fmt.Fprintln(w)
		}
		head := strings.TrimSpace(strings.ToUpper(c.Environment) + " " + c.Cluster)
		if c.Status == "unreachable" {
			fmt.Fprintf(w, "%s  %s\n", st.Bold(head), st.Fail("unreachable: "+c.Error))
			continue
		}
		counts := map[string]int{}
		for _, f := range c.Findings {
			counts[f.Severity]++
		}
		var parts []string
		for j := len(severities) - 1; j >= 0; j-- {
			if n := counts[severities[j]]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, severities[j]))
			}
		}
		summary := "nothing found"
		if len(parts) > 0 {
			summary = strings.Join(parts, " · ")
		}
		fmt.Fprintf(w, "%s  %s  %s\n", st.BoldFg(cfg.ColorFor(c.Environment), head), severityStyle(st, c.Status), st.Dim(summary))
		hidden := 0
		tw := newTable(w)
		header := false
		for _, f := range c.Findings {
			if severityRank(f.Severity) < severityRank(minSev) {
				hidden++
				continue
			}
			if !header {
				fmt.Fprintln(tw, "SEVERITY\tCHECK\tOBJECT\tFINDING")
				header = true
			}
			what := f.Title
			if f.Detail != "" {
				what += " — " + f.Detail
			}
			if f.Blocker {
				what = "BLOCKER: " + what
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity), f.Check, firstNonBlank(f.Object, "-"), what)
		}
		tw.Flush()
		if hidden > 0 {
			fmt.Fprintln(w, st.Dim(fmt.Sprintf("  %d finding(s) below %s not shown (--min info shows them)", hidden, minSev)))
		}
		if len(c.Unassessed) > 0 {
			fmt.Fprintln(w, st.Fg(ui.Amber, "  not assessed (not a pass):"))
			for _, u := range c.Unassessed {
				fmt.Fprintln(w, "   · "+u)
			}
		}
	}
}

// printFixes lists each distinct fix once, for the checks shown.
func printFixes(w io.Writer, report []clusterFindings, minSev string) {
	st := ui.Style{Color: colorOn(w)}
	seen := map[string]bool{}
	var lines []string
	for _, c := range report {
		for _, f := range c.Findings {
			if f.Fix == "" || severityRank(f.Severity) < severityRank(minSev) || seen[f.Check+f.Fix] {
				continue
			}
			seen[f.Check+f.Fix] = true
			lines = append(lines, f.Check+"\t"+f.Fix)
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s\n", st.Heading("What to do"))
	tw := newTable(w)
	fmt.Fprintln(tw, "CHECK\tFIX")
	for _, l := range lines {
		fmt.Fprintln(tw, l)
	}
	tw.Flush()
}
