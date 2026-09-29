// Package evidence turns audit logs into an auditor-facing evidence pack for
// a period: every access (a start/end event pair) with its change record and
// outcome, totals, and the exceptions a reviewer must look at. It is pure;
// the caller reads and verifies the logs.
package evidence

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/NeoM404/GoTools/internal/audit"
)

// Source is one audit log with its chain verification.
type Source struct {
	Path   string             `json:"path"`
	Events []audit.Event      `json:"-"`
	Chain  audit.VerifyResult `json:"chain"`
}

// Access is one audited action, joined from its start and end events.
type Access struct {
	ID               string `json:"id"`
	Started          string `json:"started"`
	Ended            string `json:"ended,omitempty"`
	Action           string `json:"action"`
	Outcome          string `json:"outcome"` // success | failure | refused | incomplete
	User             string `json:"user"`
	Host             string `json:"host"`
	Principal        string `json:"principal,omitempty"`
	Cluster          string `json:"cluster,omitempty"`
	Cloud            string `json:"cloud,omitempty"`
	Account          string `json:"account,omitempty"`
	Subscription     string `json:"subscription,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Production       bool   `json:"production"`
	ChangeRecord     string `json:"changeRecord,omitempty"`
	ChangeVerified   bool   `json:"changeVerified"`
	BreakGlass       bool   `json:"breakGlass"`
	BreakGlassReason string `json:"breakGlassReason,omitempty"`
	Detail           string `json:"detail,omitempty"`
	Source           string `json:"source"`
}

// Exception is an access a reviewer must examine.
type Exception struct {
	Access
	Reason string `json:"reason"`
}

// Summary counts accesses in the period.
type Summary struct {
	Accesses             int `json:"accesses"`
	Production           int `json:"production"`
	ProdVerifiedChange   int `json:"productionWithVerifiedChange"`
	ProdUnverifiedChange int `json:"productionWithUnverifiedChange"`
	ProdWithoutChange    int `json:"productionWithoutChange"`
	BreakGlass           int `json:"breakGlass"`
	Refused              int `json:"refused"`
	Failed               int `json:"failed"`
	Incomplete           int `json:"incomplete"`
}

// Report is the evidence pack.
type Report struct {
	GeneratedAt string      `json:"generatedAt"`
	Tool        string      `json:"tool"`
	Version     string      `json:"version"`
	From        string      `json:"from"` // inclusive, UTC
	To          string      `json:"to"`   // inclusive, UTC
	Production  bool        `json:"productionOnly"`
	Complete    bool        `json:"complete"` // every source chain intact
	Sources     []Source    `json:"sources"`
	Summary     Summary     `json:"summary"`
	Exceptions  []Exception `json:"exceptions"`
	Accesses    []Access    `json:"accesses"`
}

// Build assembles the report for accesses that started within [from, to]
// (whole UTC days).
func Build(sources []Source, from, to time.Time, productionOnly bool, generated time.Time, version string) Report {
	rep := Report{
		GeneratedAt: generated.UTC().Format(time.RFC3339), Tool: "bankctl", Version: version,
		From: from.Format(dateLayout), To: to.Format(dateLayout), Production: productionOnly,
		Complete: true, Sources: sources, Exceptions: []Exception{}, Accesses: []Access{},
	}
	end := to.AddDate(0, 0, 1) // exclusive upper bound
	seen := map[string]bool{}
	byID := map[string]*Access{}
	var order []string
	for _, src := range sources {
		if !src.Chain.OK {
			rep.Complete = false
		}
		for _, e := range src.Events {
			key := e.ID + "/" + e.Phase
			if seen[key] {
				continue // the same event collected from two copies of a log
			}
			seen[key] = true
			a := byID[e.ID]
			if a == nil {
				a = &Access{ID: e.ID, Outcome: "incomplete", Source: src.Path}
				byID[e.ID] = a
				order = append(order, e.ID)
			}
			merge(a, e)
		}
	}
	for _, id := range order {
		a := byID[id]
		t, err := time.Parse(time.RFC3339Nano, a.Started)
		if err != nil || t.Before(from) || !t.Before(end) {
			continue
		}
		if productionOnly && !a.Production {
			continue
		}
		rep.Accesses = append(rep.Accesses, *a)
	}
	sort.SliceStable(rep.Accesses, func(i, j int) bool { return rep.Accesses[i].Started < rep.Accesses[j].Started })

	for _, a := range rep.Accesses {
		s := &rep.Summary
		s.Accesses++
		switch a.Outcome {
		case audit.OutcomeRefused:
			s.Refused++
		case audit.OutcomeFailure:
			s.Failed++
		case "incomplete":
			s.Incomplete++
		}
		if a.BreakGlass {
			s.BreakGlass++
		}
		if a.Production {
			s.Production++
			switch {
			case a.ChangeRecord != "" && a.ChangeVerified:
				s.ProdVerifiedChange++
			case a.ChangeRecord != "":
				s.ProdUnverifiedChange++
			default:
				s.ProdWithoutChange++
			}
		}
		if reason := exception(a); reason != "" {
			rep.Exceptions = append(rep.Exceptions, Exception{Access: a, Reason: reason})
		}
	}
	return rep
}

// merge folds an event into its access: identity from the start event,
// outcome and principal from the end event.
func merge(a *Access, e audit.Event) {
	switch e.Phase {
	case audit.PhaseStart:
		a.Started, a.Action, a.User, a.Host = e.Time, e.Action, e.User, e.Host
		a.Cluster, a.Cloud, a.Account, a.Subscription = e.Cluster, e.Cloud, e.Account, e.Subscription
		a.Environment, a.Production = e.Environment, e.Production
		a.ChangeRecord, a.BreakGlass, a.BreakGlassReason = e.ChangeRecord, e.BreakGlass, e.BreakGlassReason
	case audit.PhaseEnd:
		a.Ended, a.Outcome, a.Principal, a.Detail = e.Time, e.Outcome, e.Principal, e.Detail
		a.ChangeVerified = e.ChangeVerified
		if a.Started == "" { // start event outside this log; keep what the end knows
			a.Action, a.User, a.Host, a.Cluster, a.Environment, a.Production = e.Action, e.User, e.Host, e.Cluster, e.Environment, e.Production
			a.Started = e.Time
		}
	}
}

// exception says why an access needs review, or "".
func exception(a Access) string {
	switch {
	case a.BreakGlass && a.Outcome == audit.OutcomeSuccess:
		return "break-glass access: " + a.BreakGlassReason
	case a.Outcome == "incomplete":
		return "started but never finished — the process was killed mid-access"
	case a.Production && a.Outcome == audit.OutcomeSuccess && a.ChangeRecord == "":
		return "production access without a change record"
	case a.Production && a.Outcome == audit.OutcomeSuccess && !a.ChangeVerified:
		return "production access with an unverified change record " + a.ChangeRecord
	}
	return ""
}

const dateLayout = "2006-01-02"

var (
	quarterRe = regexp.MustCompile(`^(\d{4})-Q([1-4])$`)
	monthRe   = regexp.MustCompile(`^(\d{4})-(0[1-9]|1[0-2])$`)
)

// ParsePeriod turns "2026-Q3" or "2026-09" into inclusive UTC dates.
func ParsePeriod(s string) (from, to time.Time, err error) {
	if m := quarterRe.FindStringSubmatch(s); m != nil {
		y, _ := strconv.Atoi(m[1])
		q, _ := strconv.Atoi(m[2])
		from = time.Date(y, time.Month(3*q-2), 1, 0, 0, 0, 0, time.UTC)
		return from, from.AddDate(0, 3, -1), nil
	}
	if m := monthRe.FindStringSubmatch(s); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		from = time.Date(y, time.Month(mo), 1, 0, 0, 0, 0, time.UTC)
		return from, from.AddDate(0, 1, -1), nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("period %q: want a quarter like 2026-Q3 or a month like 2026-09", s)
}

// ParseDate parses an inclusive YYYY-MM-DD bound.
func ParseDate(s string) (time.Time, error) {
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("date %q: want YYYY-MM-DD", s)
	}
	return t, nil
}
