package app

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NeoM404/GoTools/internal/support"
)

// pinToday fixes the clock for date arithmetic.
func pinToday(t *testing.T, day string) {
	t.Helper()
	d, err := time.Parse("2006-01-02", day)
	if err != nil {
		t.Fatal(err)
	}
	prev := now
	now = func() time.Time { return d.Add(10 * time.Hour) }
	t.Cleanup(func() { now = prev })
}

// Synthetic lifecycle putting the example fleet in every state on 2026-09-29:
// aws 1.30 ends in 63 days (prod, uat → ending), aws 1.29 is in extended
// support (sit), aws 1.27 is past all support (dev), azure 1.30 is fine,
// azure 1.28 has no entry (unknown).
const lifecycle = `, "supportCalendar": {
  "aws": {
    "1.30": {"standardEnd": "2026-12-01", "extendedEnd": "2027-12-01"},
    "1.29": {"standardEnd": "2026-03-01", "extendedEnd": "2027-03-01"},
    "1.27": {"standardEnd": "2024-07-24", "extendedEnd": "2025-07-24"}
  },
  "azure": {"1.30": {"standardEnd": "2027-06-01"}}
}`

const pricing = `, "costRates": {"currency": "USD", "aws": {"standardHourly": 0.10, "extendedHourly": 0.60}}`

func TestFleetEOLStatesAndPremium(t *testing.T) {
	pinToday(t, "2026-09-29")
	cfg := writeConfig(t, lifecycle+pricing)
	code, out, errb := run("--config", cfg, "fleet", "eol", "-o", "json")
	if code != ExitOK {
		t.Fatalf("without --fail-on-risk the report itself succeeds: code=%d err=%q", code, errb)
	}
	var rep eolReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	s := rep.Summary
	if s.Unsupported != 1 || s.Extended != 1 || s.Ending != 2 || s.Unknown != 1 || s.OK != 1 {
		t.Fatalf("summary: %+v", s)
	}
	// sit in extended: (0.60-0.10)*730 = 365.00; two ending clusters project 730.00.
	if s.PremiumMonthly != "365.00" || s.ProjectedMonthly != "730.00" || rep.Currency != "USD" {
		t.Fatalf("money: %+v", s)
	}
	if first := rep.Clusters[0]; first.Name != "eks-payments-dev-euw1" || first.Status != support.Unsupported {
		t.Fatalf("most at-risk first: %+v", first)
	}
	if !rep.AtRisk || rep.Today != "2026-09-29" {
		t.Fatalf("report: atRisk=%v today=%s", rep.AtRisk, rep.Today)
	}
	for _, c := range rep.Clusters {
		if c.Status == support.Ending && (c.DaysLeft == nil || *c.DaysLeft != 63) {
			t.Fatalf("%s: daysLeft %v want 63", c.Name, c.DaysLeft)
		}
	}
	if code, _, _ := run("--config", cfg, "fleet", "eol", "--fail-on-risk"); code != ExitFailure {
		t.Fatalf("--fail-on-risk: code=%d", code)
	}
}

func TestFleetEOLTableAndCostCentres(t *testing.T) {
	pinToday(t, "2026-09-29")
	code, out, errb := run("--config", writeConfig(t, lifecycle+pricing), "fleet", "eol", "--by-cost-centre")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"PREMIUM/MO (USD)", "365.00", "365.00 from 2026-12-01",
		"1 unsupported · 1 in extended support · 2 ending within 90 days · 1 unknown · 1 ok",
		"USD 365.00/month now; +USD 730.00/month if the 2 ending cluster(s)",
		"CC-1001      4         4        365.00      730.00",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(errb, "'unknown' clusters have no supportCalendar entry") {
		t.Errorf("unknown clusters must be called out: %q", errb)
	}
}

func TestFleetEOLWithoutPricingOmitsMoney(t *testing.T) {
	pinToday(t, "2026-09-29")
	_, out, _ := run("--config", writeConfig(t, lifecycle), "fleet", "eol")
	if strings.Contains(out, "PREMIUM") || strings.Contains(out, "USD") {
		t.Fatalf("no rates configured, no money:\n%s", out)
	}
}

func TestFleetEOLWarnWindow(t *testing.T) {
	pinToday(t, "2026-09-29")
	_, out, _ := run("--config", writeConfig(t, lifecycle+pricing), "fleet", "eol", "--warn-days", "30", "-o", "json")
	var rep eolReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Ending != 0 || rep.Summary.OK != 3 {
		t.Fatalf("63 days out is outside a 30-day window: %+v", rep.Summary)
	}
	// The 1.30 clusters will enter paid extended support eventually, but not
	// inside the window, so nothing is projected for it.
	if rep.Summary.ProjectedMonthly != "0.00" || rep.Summary.PremiumMonthly != "365.00" {
		t.Fatalf("projected premium must only count clusters inside the window: %+v", rep.Summary)
	}
	if code, _, _ := run("--config", writeConfig(t, lifecycle), "fleet", "eol", "--warn-days", "-1"); code != ExitUsage {
		t.Fatalf("negative window: code=%d", code)
	}
}

func TestFleetEOLNeedsCalendar(t *testing.T) {
	code, _, errb := run("--config", writeConfig(t, ""), "fleet", "eol")
	if code != ExitFailure || !strings.Contains(errb, "fleet calendar aws") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestInvalidLifecycleConfigRejected(t *testing.T) {
	cfg := writeConfig(t, `, "supportCalendar": {"aws": {"1.30": {"standardEnd": "2027-01-01", "extendedEnd": "2026-01-01"}}},
	  "costRates": {"aws": {"standardHourly": -1}}`)
	code, _, errb := run("--config", cfg, "fleet", "eol")
	for _, want := range []string{"must be after standardEnd", "currency is required", "non-negative"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q in %q", want, errb)
		}
	}
	if code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
}

func TestFleetVersionsPerEnvironmentTargets(t *testing.T) {
	cfg := writeConfig(t, `, "environments": ["dev","sit","uat","prod"], "targetKubeVersions": {"prod": "1.32", "uat": "1.30"}`)
	code, out, _ := run("--config", cfg, "fleet", "versions", "-o", "json")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	var rows []struct{ Name, Environment, Target, Status string }
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Name] = r.Target + "/" + r.Status
	}
	for name, want := range map[string]string{
		"eks-payments-prod-euw1": "1.32/STALE",   // prod target applied
		"eks-payments-uat-euw1":  "1.30/current", // uat target applied
		"eks-payments-sit-euw1":  "1.30/n-1",     // falls back to the default
	} {
		if got[name] != want {
			t.Errorf("%s: %s want %s", name, got[name], want)
		}
	}
	_, table, _ := run("--config", cfg, "fleet", "versions")
	if !strings.Contains(table, "targets: default 1.30, prod 1.32, uat 1.30") {
		t.Fatalf("footer: %s", table)
	}
}

func TestTargetForUnknownEnvironmentRejected(t *testing.T) {
	cfg := writeConfig(t, `, "environments": ["dev","prod"], "targetKubeVersions": {"production": "1.30"}`)
	if code, _, errb := run("--config", cfg, "fleet", "versions"); code != ExitFailure || !strings.Contains(errb, `environment "production"`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestFleetCalendarAWS(t *testing.T) {
	seen := t.TempDir() + "/args"
	fakeCLI(t, "aws", `echo "$*" > `+seen+`
cat <<'JSON'
{"clusterVersions":[
 {"clusterVersion":"1.31","endOfStandardSupportDate":"2026-11-26T00:00:00+00:00","endOfExtendedSupportDate":"2027-11-26T00:00:00+00:00"},
 {"clusterVersion":"1.30","endOfStandardSupportDate":1784764800,"endOfExtendedSupportDate":1816300800},
 {"clusterVersion":"1.34"}
]}
JSON`)
	cfg := writeConfig(t, `, "discovery": {"aws": [{"profile": "pay-prod", "account": "111111111111", "regions": ["eu-central-1"]}]}`)
	code, out, errb := run("--config", cfg, "fleet", "calendar", "aws")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	var cal support.Calendar
	if err := json.Unmarshal([]byte(out), &cal); err != nil {
		t.Fatalf("output must paste straight into supportCalendar: %v\n%s", err, out)
	}
	if w := cal.AWS["1.31"]; w.StandardEnd != "2026-11-26" || w.ExtendedEnd != "2027-11-26" {
		t.Fatalf("ISO timestamps: %+v", w)
	}
	if w := cal.AWS["1.30"]; w.StandardEnd != "2026-07-23" || w.ExtendedEnd != "2027-07-23" {
		t.Fatalf("epoch timestamps: %+v", w)
	}
	if _, ok := cal.AWS["1.34"]; ok {
		t.Fatal("a version with no published lifecycle must be skipped")
	}
	args := readFile(t, seen)
	if !strings.Contains(args, "--region eu-central-1") || !strings.Contains(args, "--profile pay-prod") {
		t.Fatalf("profile/region must default from discovery: %q", args)
	}
	if code, _, errb := run("fleet", "calendar", "azure"); code != ExitUsage || !strings.Contains(errb, "learn.microsoft.com") {
		t.Fatalf("azure: code=%d err=%q", code, errb)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
