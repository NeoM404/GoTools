// Package support evaluates where each cluster's Kubernetes version sits in
// its cloud's support lifecycle, and what extended support costs. It is pure:
// the calendar, rates and "today" are inputs, so every boundary is testable.
//
// Dates are calendar days (YYYY-MM-DD, UTC). A phase's end date is the first
// day of the next phase: on standardEnd the version is in extended support.
package support

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"nedctl/internal/inventory"
)

// HoursPerMonth is the average month (8,760 h / 12) cloud pricing uses.
const HoursPerMonth = 730

const dateLayout = "2006-01-02"

// Window is one minor version's support lifecycle.
type Window struct {
	StandardEnd string `json:"standardEnd"`           // first day outside standard support
	ExtendedEnd string `json:"extendedEnd,omitempty"` // first day outside extended support; empty = none offered
}

// Calendar maps minor versions ("1.30") to their lifecycle, per cloud.
type Calendar struct {
	AWS   map[string]Window `json:"aws,omitempty"`
	Azure map[string]Window `json:"azure,omitempty"`
}

// Empty reports whether no dates are configured at all.
func (c Calendar) Empty() bool { return len(c.AWS) == 0 && len(c.Azure) == 0 }

// Rates are control-plane prices used to estimate the extended-support
// premium. They come from configuration — never hard-coded — because list
// prices change and negotiated discounts differ.
type Rates struct {
	Currency string     `json:"currency"`
	AWS      CloudRates `json:"aws"`
	Azure    CloudRates `json:"azure"`
}

// CloudRates are per-cluster hourly control-plane prices.
type CloudRates struct {
	StandardHourly float64 `json:"standardHourly"`
	ExtendedHourly float64 `json:"extendedHourly"`
}

// Status is a cluster's lifecycle risk.
type Status string

const (
	Unsupported Status = "unsupported" // past the end of all support
	Extended    Status = "extended"    // in (paid) extended support
	Ending      Status = "ending"      // standard support ends within the warning window
	Unknown     Status = "unknown"     // no calendar entry, or no parseable version
	OK          Status = "ok"
)

// Rank orders statuses most-at-risk first.
func (s Status) Rank() int {
	switch s {
	case Unsupported:
		return 0
	case Extended:
		return 1
	case Ending:
		return 2
	case Unknown:
		return 3
	default:
		return 4
	}
}

// AtRisk reports whether s needs action (everything but ok). Unknown counts:
// a cluster whose support status cannot be established is an assurance gap.
func (s Status) AtRisk() bool { return s != OK }

// Assessment is one cluster's lifecycle position.
type Assessment struct {
	Status    Status `json:"status"`
	Phase     string `json:"phase,omitempty"`     // standard | extended | unsupported
	PhaseEnds string `json:"phaseEnds,omitempty"` // when the current phase ends
	DaysLeft  *int   `json:"daysLeft,omitempty"`  // days until PhaseEnds
	// PremiumMicros is the extended-support premium per month, in millionths
	// of the currency, while in extended support; ProjectedMicros is what it
	// will be once standard support ends, for clusters still in standard.
	PremiumMicros   int64 `json:"-"`
	ProjectedMicros int64 `json:"-"`
}

// Assess evaluates one cluster version on day today.
func Assess(cal Calendar, rates Rates, cloud inventory.Cloud, version string, today time.Time, warnDays int) Assessment {
	w, ok := cal.window(cloud, version)
	if !ok {
		return Assessment{Status: Unknown}
	}
	day := truncate(today)
	std, _ := time.Parse(dateLayout, w.StandardEnd) // validated at load
	premium := rates.premiumMicros(cloud)

	if day.Before(std) {
		days := daysBetween(day, std)
		a := Assessment{Status: OK, Phase: "standard", PhaseEnds: w.StandardEnd, DaysLeft: &days}
		if days <= warnDays {
			a.Status = Ending
		}
		if w.ExtendedEnd != "" {
			a.ProjectedMicros = premium
		}
		return a
	}
	if w.ExtendedEnd != "" {
		ext, _ := time.Parse(dateLayout, w.ExtendedEnd)
		if day.Before(ext) {
			days := daysBetween(day, ext)
			return Assessment{Status: Extended, Phase: "extended", PhaseEnds: w.ExtendedEnd, DaysLeft: &days, PremiumMicros: premium}
		}
	}
	return Assessment{Status: Unsupported, Phase: "unsupported"}
}

func (c Calendar) window(cloud inventory.Cloud, version string) (Window, bool) {
	m, err := inventory.ParseMinor(version)
	if err != nil {
		return Window{}, false
	}
	table := c.AWS
	if cloud == inventory.Azure {
		table = c.Azure
	}
	for k, w := range table {
		if km, err := inventory.ParseMinor(k); err == nil && km == m {
			return w, true
		}
	}
	return Window{}, false
}

// premiumMicros is the monthly extended-support premium for one cluster, in
// integer micro-units so sums are exact (0.60 − 0.10 in float64 is not 0.5).
func (r Rates) premiumMicros(cloud inventory.Cloud) int64 {
	cr := r.AWS
	if cloud == inventory.Azure {
		cr = r.Azure
	}
	if cr.ExtendedHourly == 0 && cr.StandardHourly == 0 {
		return 0
	}
	return (micros(cr.ExtendedHourly) - micros(cr.StandardHourly)) * HoursPerMonth
}

// Configured reports whether any price is set.
func (r Rates) Configured() bool { return r.AWS != (CloudRates{}) || r.Azure != (CloudRates{}) }

func micros(v float64) int64 { return int64(math.Round(v * 1e6)) }

// Money formats micro-units as a decimal amount with two places.
func Money(microUnits int64) string {
	cents := (microUnits + 5000) / 10000 // round half up to the cent
	if microUnits < 0 {
		cents = (microUnits - 5000) / 10000
	}
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	return fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100)
}

func truncate(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func daysBetween(from, to time.Time) int { return int(to.Sub(from).Hours() / 24) }

// Validate checks every date parses, versions are minors, and each extended
// end falls after its standard end.
func (c Calendar) Validate() error {
	var errs []error
	for _, part := range []struct {
		cloud string
		table map[string]Window
	}{{"aws", c.AWS}, {"azure", c.Azure}} {
		keys := make([]string, 0, len(part.table))
		for k := range part.table {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		seen := map[inventory.Minor]string{}
		for _, k := range keys {
			w := part.table[k]
			at := fmt.Sprintf("supportCalendar.%s[%q]", part.cloud, k)
			m, err := inventory.ParseMinor(k)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: not a Kubernetes minor version like 1.30", at))
				continue
			}
			if prev, dup := seen[m]; dup {
				errs = append(errs, fmt.Errorf("%s: same minor version as %q", at, prev))
			}
			seen[m] = k
			std, err := time.Parse(dateLayout, w.StandardEnd)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: standardEnd %q must be YYYY-MM-DD", at, w.StandardEnd))
				continue
			}
			if w.ExtendedEnd != "" {
				ext, err := time.Parse(dateLayout, w.ExtendedEnd)
				switch {
				case err != nil:
					errs = append(errs, fmt.Errorf("%s: extendedEnd %q must be YYYY-MM-DD", at, w.ExtendedEnd))
				case !ext.After(std):
					errs = append(errs, fmt.Errorf("%s: extendedEnd %s must be after standardEnd %s", at, w.ExtendedEnd, w.StandardEnd))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// Validate rejects negative prices and a missing currency.
func (r Rates) Validate() error {
	if !r.Configured() {
		return nil
	}
	var errs []error
	if r.Currency == "" {
		errs = append(errs, errors.New("costRates.currency is required when rates are set (e.g. \"USD\")"))
	}
	for _, v := range []struct {
		name string
		val  float64
	}{
		{"aws.standardHourly", r.AWS.StandardHourly}, {"aws.extendedHourly", r.AWS.ExtendedHourly},
		{"azure.standardHourly", r.Azure.StandardHourly}, {"azure.extendedHourly", r.Azure.ExtendedHourly},
	} {
		if v.val < 0 || math.IsNaN(v.val) || math.IsInf(v.val, 0) {
			errs = append(errs, fmt.Errorf("costRates.%s must be a non-negative number", v.name))
		}
	}
	return errors.Join(errs...)
}
