package kube

import (
	"testing"

	"nedctl/internal/inventory"
)

func sweepFleet() inventory.Fleet {
	return inventory.Fleet{Clusters: []inventory.Cluster{
		{Name: "eks-payments-prod-euw1", Cloud: inventory.AWS, Region: "eu-west-1", Account: "111111111111", Environment: "prod"},
		{Name: "aks-core-prod-weu", Cloud: inventory.Azure, Subscription: "s", ResourceGroup: "rg-aks-core-prod", Environment: "prod"},
	}}
}

// A kubeconfig as `kubectl config view -o json` renders it.
const view = `{
 "current-context": "arn:aws:eks:eu-west-1:111111111111:cluster/eks-old-current",
 "contexts": [
  {"name": "arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1", "context": {"cluster": "c-prod", "user": "u-prod"}},
  {"name": "arn:aws:eks:eu-west-1:111111111111:cluster/eks-decommissioned", "context": {"cluster": "c-old", "user": "u-old"}},
  {"name": "arn:aws:eks:eu-west-1:999999999999:cluster/personal-sandbox", "context": {"cluster": "c-sbx", "user": "u-sbx"}},
  {"name": "arn:aws:eks:eu-west-1:111111111111:cluster/eks-old-current", "context": {"cluster": "c-cur", "user": "u-cur"}},
  {"name": "payments", "context": {"cluster": "c-renamed", "user": "u-renamed"}},
  {"name": "core-prod", "context": {"cluster": "aks-c1", "user": "clusterUser_rg-aks-core-prod_aks-core-prod-weu"}},
  {"name": "aks-gone", "context": {"cluster": "aks-c2", "user": "clusterUser_rg-old_aks-gone"}},
  {"name": "kind-local", "context": {"cluster": "kind", "user": "kind"}},
  {"name": "shared-stale", "context": {"cluster": "c-prod", "user": "u-shared"}}
 ],
 "clusters": [
  {"name": "c-prod", "cluster": {"server": "https://ABC.gr7.eu-west-1.eks.amazonaws.com"}},
  {"name": "c-old", "cluster": {"server": "https://DEF.gr7.eu-west-1.eks.amazonaws.com"}},
  {"name": "c-sbx", "cluster": {"server": "https://GHI.gr7.eu-west-1.eks.amazonaws.com"}},
  {"name": "c-cur", "cluster": {"server": "https://JKL.gr7.eu-west-1.eks.amazonaws.com"}},
  {"name": "c-renamed", "cluster": {"server": "https://MNO.gr7.eu-west-1.eks.amazonaws.com"}},
  {"name": "aks-c1", "cluster": {"server": "https://core-abc.hcp.westeurope.azmk8s.io:443"}},
  {"name": "aks-c2", "cluster": {"server": "https://gone-def.hcp.westeurope.azmk8s.io:443"}},
  {"name": "kind", "cluster": {"server": "https://127.0.0.1:6443"}}
 ],
 "users": [
  {"name": "u-renamed", "user": {"exec": {"command": "aws", "args": ["--region", "eu-west-1", "eks", "get-token", "--cluster-name", "eks-payments-prod-euw1", "--output", "json"]}}},
  {"name": "u-shared", "user": {"exec": {"command": "/usr/local/bin/aws", "args": ["eks", "get-token", "--cluster-name", "eks-shared-gone", "--region", "eu-west-1"]}}}
 ]
}`

func plans(t *testing.T, fleet inventory.Fleet, includeCurrent bool) map[string]ContextPlan {
	t.Helper()
	k, err := ParseKubeconfig([]byte(view))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ContextPlan{}
	for _, p := range PlanSweep(k, fleet, includeCurrent) {
		out[p.Context] = p
	}
	return out
}

func TestSweepVerdicts(t *testing.T) {
	p := plans(t, sweepFleet(), false)
	want := map[string]Verdict{
		"arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1": Keep,
		"arn:aws:eks:eu-west-1:111111111111:cluster/eks-decommissioned":     Stale,
		"arn:aws:eks:eu-west-1:999999999999:cluster/personal-sandbox":       Unverifiable, // account not covered
		"arn:aws:eks:eu-west-1:111111111111:cluster/eks-old-current":        StaleCurrent,
		"payments":     Keep,  // renamed; resolved through its exec plugin args
		"core-prod":    Keep,  // renamed; resolved through az's clusterUser_<rg>_<name>
		"aks-gone":     Stale, // AKS host, not in inventory
		"kind-local":   Unmanaged,
		"shared-stale": Stale, // exec names a cluster the inventory lacks
	}
	for ctx, v := range want {
		if p[ctx].Verdict != v {
			t.Errorf("%s: %s (%s) want %s", ctx, p[ctx].Verdict, p[ctx].Reason, v)
		}
	}
	if p["payments"].ResolvedTo != "eks-payments-prod-euw1" || p["core-prod"].ResolvedTo != "aks-core-prod-weu" {
		t.Errorf("resolution: %+v %+v", p["payments"], p["core-prod"])
	}
}

func TestSweepDeletesOnlyOrphanedEntries(t *testing.T) {
	p := plans(t, sweepFleet(), false)
	old := p["arn:aws:eks:eu-west-1:111111111111:cluster/eks-decommissioned"]
	if old.DeleteCluster != "c-old" || old.DeleteUser != "u-old" {
		t.Fatalf("orphaned entries must go with the context: %+v", old)
	}
	// shared-stale shares cluster c-prod with a kept context: keep the cluster.
	shared := p["shared-stale"]
	if shared.DeleteCluster != "" || shared.DeleteUser != "u-shared" {
		t.Fatalf("a cluster entry a kept context uses must survive: %+v", shared)
	}
}

func TestSweepIncludeCurrent(t *testing.T) {
	p := plans(t, sweepFleet(), true)
	if v := p["arn:aws:eks:eu-west-1:111111111111:cluster/eks-old-current"].Verdict; v != Stale {
		t.Fatalf("--include-current: %s", v)
	}
}

func TestSweepNeverTrustsAnInventoryThatLacksTheCloud(t *testing.T) {
	awsOnly := sweepFleet()
	awsOnly.Clusters = awsOnly.Clusters[:1]
	p := plans(t, awsOnly, false)
	if v := p["aks-gone"].Verdict; v != Unverifiable {
		t.Fatalf("an AWS-only inventory must not condemn AKS contexts: %s", v)
	}
	if v := p["core-prod"].Verdict; v != Unverifiable {
		t.Fatalf("got %s", v)
	}
	if n := countRemovals(PlanSweep(Kubeconfig{}, inventory.Fleet{}, true)); n != 0 {
		t.Fatalf("empty inputs remove nothing, got %d", n)
	}
}

func countRemovals(ps []ContextPlan) int {
	n := 0
	for _, p := range ps {
		if p.Verdict.Removes() {
			n++
		}
	}
	return n
}

func TestSortPlansRemovalsFirst(t *testing.T) {
	ps := []ContextPlan{{Context: "b", Verdict: Keep}, {Context: "z", Verdict: Stale}, {Context: "a", Verdict: Unmanaged}}
	SortPlans(ps)
	if ps[0].Context != "z" || ps[2].Context != "a" {
		t.Fatalf("got %+v", ps)
	}
}
