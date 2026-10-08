package reconcile

import (
	"strings"
	"testing"

	"nedctl/internal/discovery"
	"nedctl/internal/inventory"
)

const acct = "111111111111"

func awsC(name, env, version string) inventory.Cluster {
	return inventory.Cluster{Name: name, Cloud: inventory.AWS, Environment: env, Region: "eu-west-1", Account: acct, Version: version, Owner: "payments"}
}

func obsAWS(name, version string, tags map[string]string) discovery.Observed {
	c := inventory.Cluster{Name: name, Cloud: inventory.AWS, Region: "eu-west-1", Account: acct, Version: version}
	c.Environment, c.Owner = tags["environment"], tags["owner"]
	return discovery.Observed{Cluster: c, Tags: tags}
}

var awsScanned = []discovery.Scope{{Cloud: inventory.AWS, Account: acct, Region: "eu-west-1"}}

func only(t *testing.T, r Report, k Kind) Finding {
	t.Helper()
	if len(r.Findings) != 1 || r.Findings[0].Kind != k {
		t.Fatalf("want exactly one %s finding, got %+v", k, r.Findings)
	}
	return r.Findings[0]
}

func TestInSyncWhenIdentical(t *testing.T) {
	r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{awsC("pay-prod", "prod", "1.30")}},
		discovery.Result{Clusters: []discovery.Observed{obsAWS("pay-prod", "1.30", nil)}, Scanned: awsScanned})
	if !r.InSync || r.Matched != 1 || len(r.Findings) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestShadowClusterDetected(t *testing.T) {
	r := Diff(inventory.Fleet{}, discovery.Result{Clusters: []discovery.Observed{obsAWS("rogue", "1.29", nil)}, Scanned: awsScanned})
	f := only(t, r, Shadow)
	if r.InSync || f.Cluster != "rogue" || f.Scope != "aws "+acct+"/eu-west-1" {
		t.Fatalf("got %+v", f)
	}
}

func TestShadowWithSameNameElsewhereGetsHint(t *testing.T) {
	d := awsC("pay", "dev", "1.30")
	d.Account = "222222222222"
	r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{d}},
		discovery.Result{Clusters: []discovery.Observed{obsAWS("pay", "1.30", nil)}, Scanned: awsScanned})
	var shadow Finding
	for _, f := range r.Findings {
		if f.Kind == Shadow {
			shadow = f
		}
	}
	if !strings.Contains(shadow.Detail, "declared in aws 222222222222/eu-west-1") {
		t.Fatalf("missing identity hint: %+v", r.Findings)
	}
}

func TestMissingOnlyWhenScopeScanned(t *testing.T) {
	gone := awsC("decommissioned", "dev", "1.28")
	r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{gone}}, discovery.Result{Scanned: awsScanned})
	only(t, r, Missing)

	// Same cluster, but its region was never scanned → unscanned, never missing.
	r = Diff(inventory.Fleet{Clusters: []inventory.Cluster{gone}},
		discovery.Result{Scanned: []discovery.Scope{{Cloud: inventory.AWS, Account: acct, Region: "eu-central-1"}}})
	only(t, r, Unscanned)
}

func TestFailedScopeNeverYieldsMissing(t *testing.T) {
	d := awsC("pay-prod", "prod", "1.30")
	r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{d}},
		discovery.Result{Errors: []discovery.ScanError{{Target: "aws " + acct + "/eu-west-1", Error: "AccessDenied"}}})
	if r.Complete || r.InSync {
		t.Fatalf("failed scan must be incomplete and not in sync: %+v", r)
	}
	only(t, r, Unscanned)
}

func TestVersionDriftComparesMinorOnly(t *testing.T) {
	scan := func(v string) Report {
		return Diff(inventory.Fleet{Clusters: []inventory.Cluster{awsC("c", "prod", "1.30")}},
			discovery.Result{Clusters: []discovery.Observed{obsAWS("c", v, nil)}, Scanned: awsScanned})
	}
	if r := scan("1.30.4"); !r.InSync {
		t.Fatalf("patch difference is not drift: %+v", r.Findings)
	}
	f := only(t, scan("1.31"), Drift)
	if f.Field != "version" || f.Declared != "1.30" || f.Observed != "1.31" {
		t.Fatalf("got %+v", f)
	}
}

func TestTagDriftOnlyWhenTagPresent(t *testing.T) {
	d := awsC("c", "prod", "1.30")
	// No tags: unknown, not drift.
	r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{d}},
		discovery.Result{Clusters: []discovery.Observed{obsAWS("c", "1.30", nil)}, Scanned: awsScanned})
	if !r.InSync {
		t.Fatalf("absent tags must not be drift: %+v", r.Findings)
	}
	// Tagged dev while declared prod: exactly the mistake that dodges prod checks.
	r = Diff(inventory.Fleet{Clusters: []inventory.Cluster{d}},
		discovery.Result{Clusters: []discovery.Observed{obsAWS("c", "1.30", map[string]string{"environment": "dev", "owner": "PAYMENTS"})}, Scanned: awsScanned})
	f := only(t, r, Drift) // owner differs only by case → not drift
	if f.Field != "environment" || f.Declared != "prod" || f.Observed != "dev" {
		t.Fatalf("got %+v", f)
	}
}

func TestAzureMatchesBySubscriptionNameOrIDCaseInsensitive(t *testing.T) {
	scanned := []discovery.Scope{{Cloud: inventory.Azure, Subscription: "0000-AAAA", SubscriptionName: "sub-core-prod"}}
	o := discovery.Observed{Cluster: inventory.Cluster{Name: "aks-core-prod-weu", Cloud: inventory.Azure, Region: "westeurope",
		Version: "1.30.4", Subscription: "0000-AAAA", ResourceGroup: "RG-AKS-CORE-PROD"}}
	for _, sub := range []string{"sub-core-prod", "0000-aaaa", "SUB-CORE-PROD"} {
		d := inventory.Cluster{Name: "aks-core-prod-weu", Cloud: inventory.Azure, Region: "West Europe", Version: "1.30",
			Subscription: sub, ResourceGroup: "rg-aks-core-prod"}
		r := Diff(inventory.Fleet{Clusters: []inventory.Cluster{d}}, discovery.Result{Clusters: []discovery.Observed{o}, Scanned: scanned})
		if !r.InSync || r.Matched != 1 {
			t.Fatalf("subscription %q: %+v", sub, r.Findings)
		}
	}
}

func TestFindingsOrderedBySeverity(t *testing.T) {
	declared := inventory.Fleet{Clusters: []inventory.Cluster{
		awsC("a-drift", "prod", "1.29"), awsC("b-missing", "dev", "1.30"),
	}}
	unscanned := awsC("c-unscanned", "dev", "1.30")
	unscanned.Region = "eu-central-1"
	declared.Clusters = append(declared.Clusters, unscanned)
	r := Diff(declared, discovery.Result{Clusters: []discovery.Observed{obsAWS("a-drift", "1.30", nil), obsAWS("z-shadow", "1.30", nil)}, Scanned: awsScanned})
	var kinds []string
	for _, f := range r.Findings {
		kinds = append(kinds, string(f.Kind))
	}
	if got := strings.Join(kinds, ","); got != "shadow,missing,drift,unscanned" {
		t.Fatalf("order: %s", got)
	}
}

func TestProposed(t *testing.T) {
	unscanned := awsC("other-region", "dev", "1.30")
	unscanned.Region = "eu-central-1"
	declared := inventory.Fleet{Clusters: []inventory.Cluster{
		{Name: "pay-prod", Cloud: inventory.AWS, Region: "eu-west-1", Account: acct, Version: "1.29", Environment: "prod", Owner: "payments", CostCentre: "CC-1"},
		awsC("gone", "dev", "1.28"),
		unscanned,
	}}
	res := discovery.Result{Scanned: awsScanned, Clusters: []discovery.Observed{
		obsAWS("pay-prod", "1.30", map[string]string{"owner": "payments-platform"}), // tag wins; env from declared
		obsAWS("new-shadow", "1.30", map[string]string{"environment": "dev"}),
	}}
	got := Proposed(declared, res)
	names := map[string]inventory.Cluster{}
	for _, c := range got.Clusters {
		names[c.Name] = c
	}
	if _, ok := names["gone"]; ok {
		t.Fatal("cluster proven missing must be dropped")
	}
	if _, ok := names["other-region"]; !ok {
		t.Fatal("cluster in an unscanned scope must be kept")
	}
	p := names["pay-prod"]
	if p.Version != "1.30" || p.Owner != "payments-platform" || p.Environment != "prod" || p.CostCentre != "CC-1" {
		t.Fatalf("merge: %+v", p)
	}
	if names["new-shadow"].Environment != "dev" {
		t.Fatalf("shadow added from tags: %+v", names["new-shadow"])
	}
}
