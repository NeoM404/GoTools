package support

import (
	"strings"
	"testing"
	"time"

	"nedctl/internal/inventory"
)

var cal = Calendar{
	AWS: map[string]Window{
		"1.30": {StandardEnd: "2026-07-23", ExtendedEnd: "2027-07-23"},
		"1.27": {StandardEnd: "2024-07-24", ExtendedEnd: "2025-07-24"},
	},
	Azure: map[string]Window{
		"1.29": {StandardEnd: "2026-03-01"}, // no extended support offered
	},
}

var rates = Rates{Currency: "USD", AWS: CloudRates{StandardHourly: 0.10, ExtendedHourly: 0.60}}

func day(s string) time.Time { t, _ := time.Parse(dateLayout, s); return t }

func TestPhaseBoundaries(t *testing.T) {
	cases := []struct {
		today  string
		status Status
		days   int
	}{
		{"2026-01-01", OK, 203},         // well inside standard
		{"2026-04-24", Ending, 90},      // exactly at the warning edge
		{"2026-07-22", Ending, 1},       // last day of standard support
		{"2026-07-23", Extended, 365},   // standardEnd is the first extended day
		{"2027-07-22", Extended, 1},     // last day of extended
		{"2027-07-23", Unsupported, -1}, // extendedEnd is the first unsupported day
	}
	for _, c := range cases {
		a := Assess(cal, rates, inventory.AWS, "1.30.4", day(c.today), 90)
		if a.Status != c.status {
			t.Errorf("%s: status %s want %s", c.today, a.Status, c.status)
			continue
		}
		if c.days >= 0 && (a.DaysLeft == nil || *a.DaysLeft != c.days) {
			t.Errorf("%s: daysLeft %v want %d", c.today, a.DaysLeft, c.days)
		}
		if c.days < 0 && a.DaysLeft != nil {
			t.Errorf("%s: unsupported must have no daysLeft", c.today)
		}
	}
}

func TestTimeOfDayAndZoneIgnored(t *testing.T) {
	// 23:30 on the last standard day in UTC+2 is still 2026-07-22 21:30 UTC.
	loc := time.FixedZone("CEST", 2*3600)
	a := Assess(cal, rates, inventory.AWS, "1.30", time.Date(2026, 7, 22, 23, 30, 0, 0, loc), 90)
	if a.Status != Ending || *a.DaysLeft != 1 {
		t.Fatalf("got %+v days=%v", a.Status, *a.DaysLeft)
	}
}

func TestNoExtendedSupportGoesStraightToUnsupported(t *testing.T) {
	if a := Assess(cal, rates, inventory.Azure, "1.29.7", day("2026-03-01"), 90); a.Status != Unsupported {
		t.Fatalf("got %s", a.Status)
	}
	if a := Assess(cal, rates, inventory.Azure, "1.29", day("2026-02-01"), 90); a.ProjectedMicros != 0 {
		t.Fatal("no extended support means no projected premium")
	}
}

func TestUnknown(t *testing.T) {
	for _, v := range []string{"1.31", "", "latest"} {
		if a := Assess(cal, rates, inventory.AWS, v, day("2026-01-01"), 90); a.Status != Unknown {
			t.Errorf("%q: got %s", v, a.Status)
		}
	}
}

func TestPremiumIsExact(t *testing.T) {
	a := Assess(cal, rates, inventory.AWS, "1.30", day("2026-08-01"), 90)
	// (0.60 − 0.10) × 730 = 365.00 exactly; float64 would give 364.99999999999994.
	if a.PremiumMicros != 365_000_000 || Money(a.PremiumMicros) != "365.00" {
		t.Fatalf("premium %d = %s", a.PremiumMicros, Money(a.PremiumMicros))
	}
	var sum int64
	for i := 0; i < 1000; i++ {
		sum += a.PremiumMicros
	}
	if Money(sum) != "365000.00" {
		t.Fatalf("sum drifted: %s", Money(sum))
	}
	pre := Assess(cal, rates, inventory.AWS, "1.30", day("2026-06-01"), 90)
	if pre.PremiumMicros != 0 || pre.ProjectedMicros != 365_000_000 {
		t.Fatalf("standard phase: premium=%d projected=%d", pre.PremiumMicros, pre.ProjectedMicros)
	}
	if a := Assess(cal, Rates{}, inventory.AWS, "1.30", day("2026-08-01"), 90); a.PremiumMicros != 0 {
		t.Fatal("no rates configured means no premium")
	}
}

func TestMoney(t *testing.T) {
	for in, want := range map[int64]string{0: "0.00", 4999: "0.00", 5000: "0.01", 1_234_567_890: "1234.57", -15000: "-0.02"} {
		if got := Money(in); got != want {
			t.Errorf("Money(%d)=%s want %s", in, got, want)
		}
	}
}

func TestCalendarValidate(t *testing.T) {
	if err := cal.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := Calendar{AWS: map[string]Window{
		"latest": {StandardEnd: "2026-01-01"},
		"1.30":   {StandardEnd: "23/07/2026"},
		"1.29":   {StandardEnd: "2026-01-01", ExtendedEnd: "2025-01-01"},
		"1.28":   {StandardEnd: "2026-01-01"},
		"v1.28":  {StandardEnd: "2026-01-01"},
	}}
	msg := bad.Validate().Error()
	for _, want := range []string{"not a Kubernetes minor", "must be YYYY-MM-DD", "must be after standardEnd", "same minor version"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in: %s", want, msg)
		}
	}
}

func TestRatesValidate(t *testing.T) {
	if err := (Rates{}).Validate(); err != nil {
		t.Fatal("unset rates are valid")
	}
	msg := Rates{AWS: CloudRates{StandardHourly: -1}}.Validate().Error()
	if !strings.Contains(msg, "currency is required") || !strings.Contains(msg, "non-negative") {
		t.Fatal(msg)
	}
}
