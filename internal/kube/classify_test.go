package kube

import (
	"strings"
	"testing"

	"nedctl/internal/inventory"
)

func fleet() inventory.Fleet {
	return inventory.Fleet{Clusters: []inventory.Cluster{
		{Name: "eks-core-live-euw1", Cloud: inventory.AWS, Region: "eu-west-1", Account: "555555555555", Environment: "prod"},
		{Name: "eks-core-uat-euw1", Cloud: inventory.AWS, Region: "eu-west-1", Account: "222222222222", Environment: "uat"},
		{Name: "aks-core-live-weu", Cloud: inventory.Azure, Subscription: "s", ResourceGroup: "rg", Environment: "prod"},
	}}
}

func TestResolveRecognisesToolWrittenNames(t *testing.T) {
	cases := map[string]string{
		"arn:aws:eks:eu-west-1:555555555555:cluster/eks-core-live-euw1": "eks-core-live-euw1", // aws default
		"555555555555.eks-core-live-euw1":                               "eks-core-live-euw1", // nedctl alias
		"EKS-CORE-UAT-EUW1":                                             "eks-core-uat-euw1",  // plain, case-insensitive
		"aks-core-live-weu":                                             "aks-core-live-weu",  // az default
		"aks-core-live-weu-admin":                                       "aks-core-live-weu",  // az --admin
	}
	for ctx, want := range cases {
		c, ok := Resolve(ctx, fleet())
		if !ok || c.Name != want {
			t.Errorf("Resolve(%q) = %q,%v want %q", ctx, c.Name, ok, want)
		}
	}
}

func TestResolveRequiresMatchingAccount(t *testing.T) {
	// Same cluster name, different account: must NOT resolve to the prod one.
	for _, ctx := range []string{
		"arn:aws:eks:eu-west-1:999999999999:cluster/eks-core-live-euw1",
		"999999999999.eks-core-live-euw1",
		"arn:aws:eks:us-east-1:555555555555:cluster/eks-core-live-euw1", // wrong region
	} {
		if c, ok := Resolve(ctx, fleet()); ok {
			t.Errorf("Resolve(%q) wrongly matched %q", ctx, c.Name)
		}
	}
	if _, ok := Resolve("kind-local", fleet()); ok {
		t.Error("an unrelated context must not resolve")
	}
}

func TestClassifyCatchesProdWithoutProdInName(t *testing.T) {
	f := fleet()
	cl := Classify("arn:aws:eks:eu-west-1:555555555555:cluster/eks-core-live-euw1", &f, []string{"prod"}, []string{`(?i)prod`})
	if !cl.Production || cl.Cluster != "eks-core-live-euw1" || cl.Environment != "prod" {
		t.Fatalf("got %+v", cl)
	}
	if len(cl.Reasons) != 1 || !strings.Contains(cl.Reasons[0], "inventory") {
		t.Fatalf("reasons: %q", cl.Reasons)
	}
}

func TestClassifyPatternsStillOverWarn(t *testing.T) {
	f := fleet()
	// Inventory says uat, but the name matches a prod pattern: still prod.
	cl := Classify("eks-core-uat-euw1-prodlike", &f, []string{"prod"}, []string{`(?i)prod`})
	if !cl.Production || !strings.Contains(strings.Join(cl.Reasons, ";"), "pattern") {
		t.Fatalf("got %+v", cl)
	}
	// Inventory unavailable: patterns alone decide, exactly as before.
	if cl := Classify("app-prod", nil, []string{"prod"}, []string{`(?i)prod`}); !cl.Production {
		t.Fatalf("nil fleet: %+v", cl)
	}
	if cl := Classify("eks-core-uat-euw1", &f, []string{"prod"}, []string{`(?i)prod`}); cl.Production || cl.Environment != "uat" {
		t.Fatalf("non-prod: %+v", cl)
	}
}

func TestClassifyCustomProdEnvironments(t *testing.T) {
	f := fleet()
	f.Clusters[1].Environment = "dr"
	cl := Classify("eks-core-uat-euw1", &f, []string{"prod", "dr"}, nil)
	if !cl.Production {
		t.Fatalf("dr configured as prod: %+v", cl)
	}
}

func TestClassifyCurrentUsesEveryKubeconfigIdentity(t *testing.T) {
	f := fleet()
	k := Kubeconfig{CurrentContext: "mine"}
	k.Contexts = append(k.Contexts, struct {
		Name    string `json:"name"`
		Context struct {
			Cluster string `json:"cluster"`
			User    string `json:"user"`
		} `json:"context"`
	}{Name: "mine"})
	k.Contexts[0].Context.Cluster, k.Contexts[0].Context.User = "c", "clusterUser_rg_aks-core-live-weu"
	cl := ClassifyCurrent(k, &f, []string{"prod"}, nil)
	if !cl.Production || cl.Cluster != "aks-core-live-weu" {
		t.Fatalf("got %+v", cl)
	}
	// A dangling current-context still classifies by its name.
	k.CurrentContext = "eks-core-live-euw1"
	if cl := ClassifyCurrent(k, &f, []string{"prod"}, nil); !cl.Production {
		t.Fatalf("got %+v", cl)
	}
}

func TestSharedLocalAccount(t *testing.T) {
	for h, want := range map[HostContext]bool{
		{User: "clusterUser_rg_c"}:                              true,
		{User: "clusterUser_rg_c", Exec: true}:                  false, // kubelogin: a personal Entra ID identity
		{User: "clusterAdmin_rg_c", Exec: true}:                 true,
		{User: "arn:aws:eks:eu-west-1:1:cluster/c", Exec: true}: false,
	} {
		if got := h.SharedLocalAccount(); got != want {
			t.Fatalf("%+v: got %v", h, got)
		}
	}
}
