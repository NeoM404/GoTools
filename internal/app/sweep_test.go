package app

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/NeoM404/GoTools/internal/kube"
)

// A kubeconfig mixing every case. Inventory = the example fleet (accounts
// 111…444; aks-core-prod-weu in rg-aks-core-prod).
const sweepKubeconfig = `apiVersion: v1
kind: Config
current-context: arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1
contexts:
- name: arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1
  context: {cluster: c-prod, user: u-prod}
- name: arn:aws:eks:eu-west-1:111111111111:cluster/eks-decommissioned
  context: {cluster: c-old, user: u-old}
- name: arn:aws:eks:eu-west-1:999999999999:cluster/personal-sandbox
  context: {cluster: c-sbx, user: u-sbx}
- name: core-prod
  context: {cluster: aks-c1, user: clusterUser_rg-aks-core-prod_aks-core-prod-weu}
- name: aks-gone
  context: {cluster: aks-c2, user: clusterUser_rg-old_aks-gone}
- name: kind-local
  context: {cluster: kind, user: kind}
clusters:
- name: c-prod
  cluster: {server: "https://abc.gr7.eu-west-1.eks.amazonaws.com"}
- name: c-old
  cluster: {server: "https://def.gr7.eu-west-1.eks.amazonaws.com"}
- name: c-sbx
  cluster: {server: "https://ghi.gr7.eu-west-1.eks.amazonaws.com"}
- name: aks-c1
  cluster: {server: "https://core.hcp.westeurope.azmk8s.io:443"}
- name: aks-c2
  cluster: {server: "https://gone.hcp.westeurope.azmk8s.io:443"}
- name: kind
  cluster: {server: "https://127.0.0.1:6443"}
users:
- name: u-prod
  user: {token: t1}
- name: u-old
  user: {token: t2}
- name: u-sbx
  user: {token: t3}
- name: clusterUser_rg-aks-core-prod_aks-core-prod-weu
  user: {token: t4}
- name: clusterUser_rg-old_aks-gone
  user: {token: t5}
- name: kind
  user: {token: t6}
`

func sweepSetup(t *testing.T, kubeconfig string) (cfg, kc string) {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	kc = filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kc, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", "")
	return writeConfig(t, ""), kc
}

func entries(t *testing.T, kc, kind string) []string {
	t.Helper()
	out, err := exec.Command("kubectl", "config", "view", "-o", "json", "--kubeconfig", kc).Output()
	if err != nil {
		t.Fatal(err)
	}
	type named []struct{ Name string }
	var doc struct {
		Contexts named `json:"contexts"`
		Clusters named `json:"clusters"`
		Users    named `json:"users"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	list := map[string]named{"contexts": doc.Contexts, "clusters": doc.Clusters, "users": doc.Users}[kind]
	var names []string
	for _, e := range list {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	return names
}

func TestSweepDryRunChangesNothing(t *testing.T) {
	cfg, kc := sweepSetup(t, sweepKubeconfig)
	before, _ := os.ReadFile(kc)
	code, out, errb := run("--config", cfg, "sweep", "--kubeconfig", kc)
	if code != ExitOK || !strings.Contains(out, "dry run: 2 stale context(s) would be removed") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	after, _ := os.ReadFile(kc)
	if !bytes.Equal(before, after) {
		t.Fatal("a dry run must not modify the kubeconfig")
	}
	for _, want := range []string{"unverifiable", "unmanaged", "keep"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing verdict %q in:\n%s", want, out)
		}
	}
}

func TestSweepApplyRemovesExactlyTheStaleEntries(t *testing.T) {
	cfg, kc := sweepSetup(t, sweepKubeconfig)
	original, _ := os.ReadFile(kc)
	code, out, errb := run("--config", cfg, "sweep", "--kubeconfig", kc, "--apply", "-o", "json")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q out=%s", code, errb, out)
	}
	var rep sweepReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Removed.Contexts != 2 || rep.Removed.Clusters != 2 || rep.Removed.Users != 2 || len(rep.Errors) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	wantContexts := []string{
		"arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1",
		"arn:aws:eks:eu-west-1:999999999999:cluster/personal-sandbox",
		"core-prod", "kind-local",
	}
	if got := entries(t, kc, "contexts"); strings.Join(got, ",") != strings.Join(wantContexts, ",") {
		t.Fatalf("contexts after sweep: %v", got)
	}
	if got := entries(t, kc, "clusters"); strings.Join(got, ",") != "aks-c1,c-prod,c-sbx,kind" {
		t.Fatalf("clusters after sweep: %v", got)
	}
	if got := entries(t, kc, "users"); strings.Contains(strings.Join(got, ","), "u-old") || strings.Contains(strings.Join(got, ","), "aks-gone") {
		t.Fatalf("users after sweep: %v", got)
	}
	backup, err := os.ReadFile(rep.Backup)
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup must be byte-identical to the original: err=%v", err)
	}
	if info, _ := os.Stat(rep.Backup); info.Mode().Perm() != 0o600 {
		t.Fatalf("backup holds credentials; must be 0600, got %o", info.Mode().Perm())
	}
	// A second run finds nothing left to do.
	if _, out, _ := run("--config", cfg, "sweep", "--kubeconfig", kc); !strings.Contains(out, "nothing to remove") {
		t.Fatalf("second run: %s", out)
	}
}

func TestSweepIncludeCurrentUnsetsIt(t *testing.T) {
	kcText := strings.Replace(sweepKubeconfig,
		"current-context: arn:aws:eks:eu-west-1:111111111111:cluster/eks-payments-prod-euw1",
		"current-context: aks-gone", 1)
	cfg, kc := sweepSetup(t, kcText)
	if _, out, _ := run("--config", cfg, "sweep", "--kubeconfig", kc); !strings.Contains(out, "stale-current") {
		t.Fatalf("current context must be held back by default: %s", out)
	}
	if code, _, errb := run("--config", cfg, "sweep", "--kubeconfig", kc, "--apply", "--include-current"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	out, _ := exec.Command("kubectl", "config", "view", "-o", "jsonpath={.current-context}", "--kubeconfig", kc).Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("current-context must be unset after removing it, got %q", out)
	}
}

func TestSweepRefusesWithoutInventory(t *testing.T) {
	_, kc := sweepSetup(t, sweepKubeconfig)
	before, _ := os.ReadFile(kc)
	noInv := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(noInv, []byte(`{"inventoryPath":"absent.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := run("--config", noInv, "sweep", "--kubeconfig", kc, "--apply")
	if code != ExitFailure || !strings.Contains(errb, "refusing to sweep without a valid inventory") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if after, _ := os.ReadFile(kc); !bytes.Equal(before, after) {
		t.Fatal("kubeconfig modified without an inventory")
	}
}

func TestSweepRefusesAmbiguousKubeconfigList(t *testing.T) {
	cfg, kc := sweepSetup(t, sweepKubeconfig)
	t.Setenv("KUBECONFIG", kc+string(os.PathListSeparator)+kc+".other")
	code, _, errb := run("--config", cfg, "sweep")
	if code != ExitUsage || !strings.Contains(errb, "pass --kubeconfig") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestVerifySweepCatchesBothFailureModes(t *testing.T) {
	kc := func(names ...string) (k kube.Kubeconfig) {
		for _, n := range names {
			k.Contexts = append(k.Contexts, struct {
				Name    string `json:"name"`
				Context struct {
					Cluster string `json:"cluster"`
					User    string `json:"user"`
				} `json:"context"`
			}{Name: n})
		}
		return k
	}
	before := kc("keep", "stale")
	plan := []kube.ContextPlan{{Context: "stale", Verdict: kube.Stale}}
	if err := verifySweep(kc("keep"), before, plan); err != nil {
		t.Fatalf("clean sweep: %v", err)
	}
	if err := verifySweep(kc("keep", "stale"), before, plan); err == nil || !strings.Contains(err.Error(), "still present") {
		t.Fatalf("undeleted context not caught: %v", err)
	}
	if err := verifySweep(kc(), before, plan); err == nil || !strings.Contains(err.Error(), "not planned for removal") {
		t.Fatalf("collateral deletion not caught: %v", err)
	}
}
