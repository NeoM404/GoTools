package evidence

import (
	"strings"
	"testing"
	"time"

	"nedctl/internal/audit"
)

type access struct {
	id, started, outcome, env, cr string
	verified, glass, noEnd        bool
}

func events(as ...access) []audit.Event {
	var out []audit.Event
	for _, a := range as {
		base := audit.Event{ID: a.id, Action: "credentials", User: "neo", Host: "laptop", Cluster: "c-" + a.id,
			Environment: a.env, Production: a.env == "prod", ChangeRecord: a.cr, BreakGlass: a.glass}
		if a.glass {
			base.BreakGlassReason = "P1 incident, payments down"
		}
		start := base
		start.Phase, start.Time = audit.PhaseStart, a.started
		out = append(out, start)
		if !a.noEnd {
			end := base
			end.Phase, end.Time, end.Outcome, end.ChangeVerified = audit.PhaseEnd, a.started, a.outcome, a.verified
			out = append(out, end)
		}
	}
	return out
}

func build(t *testing.T, prodOnly bool, srcs ...Source) Report {
	t.Helper()
	from, to, err := ParsePeriod("2026-Q3")
	if err != nil {
		t.Fatal(err)
	}
	return Build(srcs, from, to, prodOnly, time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), "test")
}

func ok(path string, ev []audit.Event) Source {
	return Source{Path: path, Events: ev, Chain: audit.VerifyResult{OK: true, Events: len(ev)}}
}

func TestPeriodBoundariesAndPairing(t *testing.T) {
	rep := build(t, false, ok("a.jsonl", events(
		access{id: "before", started: "2026-06-30T23:59:59Z", outcome: "success", env: "dev"},
		access{id: "first", started: "2026-07-01T00:00:00Z", outcome: "success", env: "dev"},
		access{id: "last", started: "2026-09-30T23:59:59.9Z", outcome: "success", env: "dev"},
		access{id: "after", started: "2026-10-01T00:00:00Z", outcome: "success", env: "dev"},
	)))
	if len(rep.Accesses) != 2 || rep.Accesses[0].ID != "first" || rep.Accesses[1].ID != "last" {
		t.Fatalf("period must be inclusive of both whole days: %+v", rep.Accesses)
	}
	if rep.From != "2026-07-01" || rep.To != "2026-09-30" || !rep.Complete {
		t.Fatalf("header: %+v", rep)
	}
}

func TestSummaryAndExceptions(t *testing.T) {
	rep := build(t, false, ok("a.jsonl", events(
		access{id: "p-verified", started: "2026-08-01T10:00:00Z", outcome: "success", env: "prod", cr: "CHG0000001", verified: true},
		access{id: "p-unverified", started: "2026-08-02T10:00:00Z", outcome: "success", env: "prod", cr: "CHG0000002"},
		access{id: "p-none", started: "2026-08-03T10:00:00Z", outcome: "success", env: "prod"},
		access{id: "p-glass", started: "2026-08-04T10:00:00Z", outcome: "success", env: "prod", glass: true},
		access{id: "p-refused", started: "2026-08-05T10:00:00Z", outcome: "refused", env: "prod"},
		access{id: "killed", started: "2026-08-06T10:00:00Z", env: "uat", noEnd: true},
		access{id: "dev-ok", started: "2026-08-07T10:00:00Z", outcome: "success", env: "dev"},
	)))
	s := rep.Summary
	if s.Accesses != 7 || s.Production != 5 || s.ProdVerifiedChange != 1 || s.ProdUnverifiedChange != 1 ||
		s.ProdWithoutChange != 3 || s.BreakGlass != 1 || s.Refused != 1 || s.Incomplete != 1 {
		t.Fatalf("summary: %+v", s)
	}
	reasons := map[string]string{}
	for _, e := range rep.Exceptions {
		reasons[e.ID] = e.Reason
	}
	want := map[string]string{
		"p-unverified": "unverified change record CHG0000002",
		"p-none":       "without a change record",
		"p-glass":      "break-glass access: P1 incident",
		"killed":       "never finished",
	}
	if len(reasons) != len(want) {
		t.Fatalf("exceptions: %v", reasons)
	}
	for id, w := range want {
		if !strings.Contains(reasons[id], w) {
			t.Errorf("%s: reason %q want %q", id, reasons[id], w)
		}
	}
	// A verified change, a refused attempt and routine dev access are not exceptions.
	for _, id := range []string{"p-verified", "p-refused", "dev-ok"} {
		if _, bad := reasons[id]; bad {
			t.Errorf("%s must not be an exception", id)
		}
	}
}

func TestProductionOnly(t *testing.T) {
	rep := build(t, true, ok("a.jsonl", events(
		access{id: "p", started: "2026-08-01T10:00:00Z", outcome: "success", env: "prod", cr: "CHG0000001", verified: true},
		access{id: "d", started: "2026-08-01T11:00:00Z", outcome: "success", env: "dev"},
	)))
	if len(rep.Accesses) != 1 || rep.Accesses[0].ID != "p" || !rep.Production {
		t.Fatalf("got %+v", rep.Accesses)
	}
}

func TestBrokenChainMakesPackIncomplete(t *testing.T) {
	good := ok("a.jsonl", events(access{id: "x", started: "2026-08-01T10:00:00Z", outcome: "success", env: "dev"}))
	bad := Source{Path: "b.jsonl", Chain: audit.VerifyResult{OK: false, Line: 7, Problem: "hash mismatch"}}
	if rep := build(t, false, good, bad); rep.Complete {
		t.Fatal("a pack built on a broken chain must not claim completeness")
	}
}

func TestDuplicateCopiesCountedOnce(t *testing.T) {
	ev := events(access{id: "x", started: "2026-08-01T10:00:00Z", outcome: "success", env: "dev"})
	if rep := build(t, false, ok("laptop.jsonl", ev), ok("siem-export.jsonl", ev)); rep.Summary.Accesses != 1 {
		t.Fatalf("got %d", rep.Summary.Accesses)
	}
}

func TestParsePeriod(t *testing.T) {
	cases := map[string][2]string{
		"2026-Q1": {"2026-01-01", "2026-03-31"},
		"2026-Q4": {"2026-10-01", "2026-12-31"},
		"2028-02": {"2028-02-01", "2028-02-29"}, // leap year
	}
	for in, want := range cases {
		from, to, err := ParsePeriod(in)
		if err != nil || from.Format(dateLayout) != want[0] || to.Format(dateLayout) != want[1] {
			t.Errorf("%s: %s..%s err=%v", in, from.Format(dateLayout), to.Format(dateLayout), err)
		}
	}
	for _, bad := range []string{"2026-Q5", "Q3", "2026-13", "last quarter"} {
		if _, _, err := ParsePeriod(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
