// Package reconcile compares the declared fleet inventory with what discovery
// observed in the clouds. It is pure — no I/O — so every rule is unit-tested.
//
// The report is built to support an audit claim ("the inventory is complete
// and accurate for these scopes"), so it errs toward saying less:
//   - InSync requires a complete scan AND zero findings of any kind.
//   - A declared cluster is only reported missing if its scope was fully
//     scanned; otherwise it is "unscanned" — not verified either way.
package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/NeoM404/GoTools/internal/discovery"
	"github.com/NeoM404/GoTools/internal/inventory"
)

// Kind classifies a finding.
type Kind string

const (
	// Shadow: exists in the cloud, absent from the inventory — ungoverned.
	Shadow Kind = "shadow"
	// Missing: declared, but absent from a scope that was fully scanned.
	Missing Kind = "missing"
	// Drift: declared and found, but a field disagrees.
	Drift Kind = "drift"
	// Unscanned: declared in a scope outside the discovery configuration, so
	// its existence was not verified.
	Unscanned Kind = "unscanned"
)

// severity orders findings most-severe first.
var severity = map[Kind]int{Shadow: 0, Missing: 1, Drift: 2, Unscanned: 3}

// Finding is one discrepancy.
type Finding struct {
	Kind     Kind            `json:"kind"`
	Cluster  string          `json:"cluster"`
	Cloud    inventory.Cloud `json:"cloud"`
	Scope    string          `json:"scope"`
	Field    string          `json:"field,omitempty"`
	Declared string          `json:"declared,omitempty"`
	Observed string          `json:"observed,omitempty"`
	Detail   string          `json:"detail"`
}

// Report is the result of a reconciliation.
type Report struct {
	InSync     bool                  `json:"inSync"`
	Complete   bool                  `json:"complete"`
	Declared   int                   `json:"declared"`
	Observed   int                   `json:"observed"`
	Matched    int                   `json:"matched"`
	Findings   []Finding             `json:"findings"`
	Scanned    []discovery.Scope     `json:"scanned"`
	ScanErrors []discovery.ScanError `json:"scanErrors"`
}

// Count returns how many findings are of kind k.
func (r Report) Count(k Kind) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == k {
			n++
		}
	}
	return n
}

// Diff reconciles declared against observed.
func Diff(declared inventory.Fleet, res discovery.Result) Report {
	ix := newIndex(res)
	rep := Report{
		Complete: res.Complete(), Declared: len(declared.Clusters), Observed: len(res.Clusters),
		Findings: []Finding{}, Scanned: nonNil(res.Scanned), ScanErrors: nonNilErrs(res.Errors),
	}

	observed := make(map[string]discovery.Observed, len(res.Clusters))
	for _, o := range res.Clusters {
		observed[ix.observedKey(o)] = o
	}
	declaredNames := map[string]string{} // lower(name) → scope, for shadow hints
	matched := map[string]bool{}

	for _, d := range declared.Clusters {
		scope, key, inScope := ix.declaredKey(d)
		declaredNames[strings.ToLower(d.Name)] = scope
		o, found := observed[key]
		switch {
		case found:
			matched[key] = true
			rep.Matched++
			rep.Findings = append(rep.Findings, drift(d, o, scope)...)
		case inScope:
			rep.Findings = append(rep.Findings, Finding{Kind: Missing, Cluster: d.Name, Cloud: d.Cloud, Scope: scope,
				Detail: "declared in the inventory but not found in a fully scanned scope — decommissioned, renamed, or wrong identity in the inventory"})
		default:
			rep.Findings = append(rep.Findings, Finding{Kind: Unscanned, Cluster: d.Name, Cloud: d.Cloud, Scope: scope,
				Detail: "its scope is not in the discovery configuration (or failed to scan), so its existence was not verified"})
		}
	}

	for _, o := range res.Clusters {
		key := ix.observedKey(o)
		if matched[key] {
			continue
		}
		detail := "exists in the cloud but not in the inventory — ungoverned infrastructure"
		if other, ok := declaredNames[strings.ToLower(o.Name)]; ok {
			detail += fmt.Sprintf("; a cluster with this name is declared in %s — check the inventory's identity fields", other)
		}
		rep.Findings = append(rep.Findings, Finding{Kind: Shadow, Cluster: o.Name, Cloud: o.Cloud, Scope: observedScope(o), Detail: detail})
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if severity[a.Kind] != severity[b.Kind] {
			return severity[a.Kind] < severity[b.Kind]
		}
		if a.Cluster != b.Cluster {
			return a.Cluster < b.Cluster
		}
		return a.Field < b.Field
	})
	rep.InSync = rep.Complete && len(rep.Findings) == 0
	return rep
}

// index normalises identities so declared and observed records compare.
type index struct {
	awsScanned map[string]bool   // "account/region"
	subID      map[string]string // lower(subscription name or ID) → lower(ID)
	azScanned  map[string]bool   // lower(subscription ID)
}

func newIndex(res discovery.Result) index {
	ix := index{awsScanned: map[string]bool{}, subID: map[string]string{}, azScanned: map[string]bool{}}
	for _, s := range res.Scanned {
		switch s.Cloud {
		case inventory.AWS:
			ix.awsScanned[s.Account+"/"+s.Region] = true
		case inventory.Azure:
			id := strings.ToLower(s.Subscription)
			ix.azScanned[id] = true
			ix.subID[id] = id
			if s.SubscriptionName != "" {
				ix.subID[strings.ToLower(s.SubscriptionName)] = id
			}
		}
	}
	return ix
}

func (ix index) observedKey(o discovery.Observed) string {
	if o.Cloud == inventory.AWS {
		return strings.ToLower("aws/" + o.Account + "/" + o.Region + "/" + o.Name)
	}
	return strings.ToLower("azure/" + o.Subscription + "/" + o.ResourceGroup + "/" + o.Name)
}

// declaredKey returns the declared cluster's scope label, its match key, and
// whether its scope was fully scanned.
func (ix index) declaredKey(d inventory.Cluster) (scope, key string, inScope bool) {
	if d.Cloud == inventory.AWS {
		scope = "aws " + d.Account + "/" + d.Region
		return scope, strings.ToLower("aws/" + d.Account + "/" + d.Region + "/" + d.Name), ix.awsScanned[d.Account+"/"+d.Region]
	}
	scope = "azure " + d.Subscription + "/" + d.ResourceGroup
	id, known := ix.subID[strings.ToLower(d.Subscription)]
	if !known {
		return scope, "", false
	}
	return scope, strings.ToLower("azure/" + id + "/" + d.ResourceGroup + "/" + d.Name), ix.azScanned[id]
}

func observedScope(o discovery.Observed) string {
	if o.Cloud == inventory.AWS {
		return "aws " + o.Account + "/" + o.Region
	}
	return "azure " + o.Subscription + "/" + o.ResourceGroup
}

// drift compares the fields both sides know about.
func drift(d inventory.Cluster, o discovery.Observed, scope string) []Finding {
	var out []Finding
	add := func(field, declared, observed, detail string) {
		out = append(out, Finding{Kind: Drift, Cluster: d.Name, Cloud: d.Cloud, Scope: scope,
			Field: field, Declared: declared, Observed: observed, Detail: detail})
	}
	if !sameMinor(d.Version, o.Version) {
		add("version", d.Version, o.Version, "inventory version does not match the running control plane")
	}
	if d.Cloud == inventory.Azure && normLocation(d.Region) != normLocation(o.Region) {
		add("region", d.Region, o.Region, "inventory region does not match the cluster's location")
	}
	// Tag-derived fields: an absent tag is unknown, not a disagreement.
	for _, f := range []struct{ name, declared, observed string }{
		{"environment", d.Environment, o.Environment},
		{"owner", d.Owner, o.Owner},
		{"costCentre", d.CostCentre, o.CostCentre},
	} {
		if f.observed != "" && !strings.EqualFold(strings.TrimSpace(f.declared), strings.TrimSpace(f.observed)) {
			add(f.name, f.declared, f.observed, "inventory disagrees with the cluster's cloud tag")
		}
	}
	return out
}

func sameMinor(a, b string) bool {
	ma, errA := inventory.ParseMinor(a)
	mb, errB := inventory.ParseMinor(b)
	if errA != nil || errB != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return ma == mb
}

func normLocation(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, " ", ""))
}

func nonNil(s []discovery.Scope) []discovery.Scope {
	if s == nil {
		return []discovery.Scope{}
	}
	return s
}

func nonNilErrs(e []discovery.ScanError) []discovery.ScanError {
	if e == nil {
		return []discovery.ScanError{}
	}
	return e
}

// Proposed builds the inventory the scan implies, for `inventory sync`:
//   - every observed cluster, with its identity and running version from the
//     cloud; environment/owner/cost centre from tags where tagged, otherwise
//     carried over from its declared entry (conflicts show up in Diff);
//   - declared clusters in scopes that were not scanned, unchanged — nothing
//     was learned about them, so nothing is dropped;
//   - declared clusters missing from a fully scanned scope are omitted: the
//     scan proved they are not there.
//
// Callers must only use this on a complete scan; a partial scan would
// silently drop clusters in the failed scopes.
func Proposed(declared inventory.Fleet, res discovery.Result) inventory.Fleet {
	ix := newIndex(res)
	byKey := make(map[string]inventory.Cluster, len(declared.Clusters))
	var out []inventory.Cluster
	for _, d := range declared.Clusters {
		_, key, inScope := ix.declaredKey(d)
		if !inScope {
			out = append(out, d)
			continue
		}
		byKey[key] = d
	}
	for _, o := range res.Clusters {
		c := o.Cluster
		if d, ok := byKey[ix.observedKey(o)]; ok {
			c.Environment = firstNonEmpty(c.Environment, d.Environment)
			c.Owner = firstNonEmpty(c.Owner, d.Owner)
			c.CostCentre = firstNonEmpty(c.CostCentre, d.CostCentre)
			if c.Cloud == inventory.Azure {
				c.Subscription = d.Subscription // keep the inventory's own form (name or ID)
			}
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cloud != out[j].Cloud {
			return out[i].Cloud < out[j].Cloud
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if out == nil {
		out = []inventory.Cluster{}
	}
	return inventory.Fleet{Clusters: out}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
