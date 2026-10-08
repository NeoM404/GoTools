package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"nedctl/internal/inventory"
	"nedctl/internal/reconcile"
)

// estate describes a simulated cloud. It is rendered into fake aws and az
// executables so tests exercise the real command path end to end.
type estate struct {
	// profile → account the profile's credentials resolve to
	identity map[string]string
	// account → clusters in eu-west-1
	eks map[string][]eksCluster
	// subscription name → (id, clusters)
	aks map[string]aksSub
}

type eksCluster struct{ name, version, tags string }
type aksSub struct {
	id       string
	clusters []string // raw JSON objects
}

func exampleEstate() estate {
	return estate{
		identity: map[string]string{
			"acct-111111111111": "111111111111", "acct-222222222222": "222222222222",
			"acct-333333333333": "333333333333", "acct-444444444444": "444444444444",
		},
		eks: map[string][]eksCluster{
			"111111111111": {{"eks-payments-prod-euw1", "1.30", `{}`}},
			"222222222222": {{"eks-payments-uat-euw1", "1.30", `{}`}},
			"333333333333": {{"eks-payments-sit-euw1", "1.29", `{}`}},
			"444444444444": {{"eks-payments-dev-euw1", "1.27", `{}`}},
		},
		aks: map[string]aksSub{
			"sub-core-prod": {id: "sub-core-prod-id", clusters: []string{
				`{"name":"aks-core-prod-weu","id":"/x","location":"westeurope","resourceGroup":"rg-aks-core-prod","currentKubernetesVersion":"1.30.4","provisioningState":"Succeeded","tags":{}}`}},
			"sub-core-nonprod": {id: "sub-core-nonprod-id", clusters: []string{
				`{"name":"aks-core-uat-weu","id":"/y","location":"westeurope","resourceGroup":"rg-aks-core-uat","currentKubernetesVersion":"1.28.9","provisioningState":"Succeeded","tags":{}}`}},
		},
	}
}

func sq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (e estate) install(t *testing.T) {
	t.Helper()
	var aws strings.Builder
	aws.WriteString(`case "$*" in` + "\n")
	profiles := make([]string, 0, len(e.identity))
	for p := range e.identity {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, p := range profiles {
		acct := e.identity[p]
		fmt.Fprintf(&aws, "*\"sts get-caller-identity\"*\"--profile %s\"*) echo %s;;\n", p, sq(`{"Account":"`+acct+`"}`))
		var names []string
		for _, c := range e.eks[acct] {
			names = append(names, `"`+c.name+`"`)
			desc := fmt.Sprintf(`{"cluster":{"name":%q,"arn":"arn:aws:eks:eu-west-1:%s:cluster/%s","version":%q,"status":"ACTIVE","tags":%s}}`,
				c.name, acct, c.name, c.version, c.tags)
			fmt.Fprintf(&aws, "*\"describe-cluster --name %s --region\"*\"--profile %s\"*) echo %s;;\n", c.name, p, sq(desc))
		}
		fmt.Fprintf(&aws, "*\"list-clusters\"*\"--profile %s\"*) echo %s;;\n", p, sq(`{"clusters":[`+strings.Join(names, ",")+`]}`))
	}
	aws.WriteString("*) echo \"fake aws: unexpected: $*\" >&2; exit 254;;\nesac")
	fakeCLI(t, "aws", aws.String())

	var az strings.Builder
	az.WriteString(`case "$*" in` + "\n")
	for name, s := range e.aks {
		fmt.Fprintf(&az, "*\"account show --subscription %s \"*) echo %s;;\n", name, sq(`{"id":"`+s.id+`","name":"`+name+`"}`))
		fmt.Fprintf(&az, "*\"aks list --subscription %s \"*) echo %s;;\n", s.id, sq("["+strings.Join(s.clusters, ",")+"]"))
	}
	az.WriteString("*) echo \"ERROR: fake az: unexpected: $*\" >&2; exit 1;;\nesac")
	// fakeCLI prepends its own dir to PATH, so both fakes stay visible.
	fakeCLI(t, "az", az.String())
}

const discoveryBlock = `, "environments": ["dev","sit","uat","prod"], "discovery": {
  "aws": [
    {"profile": "acct-111111111111", "account": "111111111111", "regions": ["eu-west-1"]},
    {"profile": "acct-222222222222", "account": "222222222222", "regions": ["eu-west-1"]},
    {"profile": "acct-333333333333", "account": "333333333333", "regions": ["eu-west-1"]},
    {"profile": "acct-444444444444", "account": "444444444444", "regions": ["eu-west-1"]}
  ],
  "azure": [{"subscription": "sub-core-prod"}, {"subscription": "sub-core-nonprod"}]
}`

func diffJSON(t *testing.T, cfg string) (int, reconcile.Report) {
	t.Helper()
	code, out, errb := run("--config", cfg, "inventory", "diff", "-o", "json")
	var rep reconcile.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON (code=%d err=%q): %v\n%s", code, errb, err, out)
	}
	return code, rep
}

func TestInventoryDiffInSync(t *testing.T) {
	exampleEstate().install(t)
	cfg := writeConfig(t, discoveryBlock)
	code, rep := diffJSON(t, cfg)
	if code != ExitOK || !rep.InSync || rep.Matched != 6 || len(rep.Scanned) != 6 {
		t.Fatalf("code=%d report=%+v", code, rep)
	}
	code, out, _ := run("--config", cfg, "inventory", "diff")
	if code != ExitOK || !strings.Contains(out, "IN SYNC") {
		t.Fatalf("table: code=%d out=%q", code, out)
	}
}

func TestInventoryDiffFindsShadowAndDrift(t *testing.T) {
	e := exampleEstate()
	e.eks["444444444444"] = append(e.eks["444444444444"], eksCluster{"eks-rogue-dev-euw1", "1.29", `{"environment":"dev"}`})
	e.eks["333333333333"] = []eksCluster{{"eks-payments-sit-euw1", "1.30", `{}`}} // upgraded, inventory not updated
	e.install(t)
	code, rep := diffJSON(t, writeConfig(t, discoveryBlock))
	if code != ExitFailure || rep.InSync || !rep.Complete {
		t.Fatalf("code=%d report=%+v", code, rep)
	}
	if rep.Count(reconcile.Shadow) != 1 || rep.Findings[0].Cluster != "eks-rogue-dev-euw1" {
		t.Fatalf("shadow: %+v", rep.Findings)
	}
	if rep.Count(reconcile.Drift) != 1 || rep.Findings[1].Field != "version" {
		t.Fatalf("drift: %+v", rep.Findings)
	}
}

func TestInventoryDiffWrongAccountIsIncomplete(t *testing.T) {
	e := exampleEstate()
	e.identity["acct-111111111111"] = "999999999999" // profile misconfigured
	e.install(t)
	code, rep := diffJSON(t, writeConfig(t, discoveryBlock))
	if code != ExitFailure || rep.Complete || rep.InSync || len(rep.ScanErrors) != 1 {
		t.Fatalf("code=%d report=%+v", code, rep)
	}
	if rep.Count(reconcile.Missing) != 0 || rep.Count(reconcile.Unscanned) != 1 {
		t.Fatalf("prod cluster in the failed scope must be unscanned, never missing: %+v", rep.Findings)
	}
	_, out, errb := run("--config", writeConfig(t, discoveryBlock), "inventory", "diff")
	if !strings.Contains(errb, "INCOMPLETE") || !strings.Contains(out, "scan incomplete") {
		t.Fatalf("table must flag incompleteness: out=%q err=%q", out, errb)
	}
}

func TestInventoryDiffWithoutDiscoveryScope(t *testing.T) {
	code, _, errb := run("--config", writeConfig(t, ""), "inventory", "diff")
	if code != ExitFailure || !strings.Contains(errb, "no discovery scope configured") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestInventorySyncWritesValidInventory(t *testing.T) {
	e := exampleEstate()
	e.eks["444444444444"] = append(e.eks["444444444444"], eksCluster{"eks-rogue-dev-euw1", "1.29", `{"environment":"dev","owner":"data-eng"}`})
	e.install(t)
	cfg := writeConfig(t, discoveryBlock)
	out := filepath.Join(t.TempDir(), "fleet.json")

	code, _, errb := run("--config", cfg, "inventory", "sync", "--out", out)
	if code != ExitOK || !strings.Contains(errb, "7 cluster(s): 1 added, 0 removed, 0 updated") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	f, err := inventory.LoadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate([]string{"dev", "sit", "uat", "prod"}); err != nil {
		t.Fatalf("written inventory must pass validation: %v", err)
	}
	var rogue *inventory.Cluster
	for i := range f.Clusters {
		if f.Clusters[i].Name == "eks-rogue-dev-euw1" {
			rogue = &f.Clusters[i]
		}
	}
	if rogue == nil || rogue.Environment != "dev" || rogue.Owner != "data-eng" || rogue.Account != "444444444444" {
		t.Fatalf("shadow cluster not adopted correctly: %+v", rogue)
	}
	for _, c := range f.Clusters {
		if c.Name == "aks-core-prod-weu" && c.Subscription != "sub-core-prod" {
			t.Fatalf("declared subscription form must be preserved, got %q", c.Subscription)
		}
	}

	if code, _, errb := run("--config", cfg, "inventory", "sync", "--out", out); code != ExitFailure || !strings.Contains(errb, "--force") {
		t.Fatalf("must refuse to overwrite: code=%d err=%q", code, errb)
	}
	if code, _, _ := run("--config", cfg, "inventory", "sync", "--out", out, "--force"); code != ExitOK {
		t.Fatalf("--force overwrite: code=%d", code)
	}
}

func TestInventorySyncRefusesPartialScan(t *testing.T) {
	e := exampleEstate()
	e.identity["acct-111111111111"] = "999999999999"
	e.install(t)
	out := filepath.Join(t.TempDir(), "fleet.json")
	code, _, errb := run("--config", writeConfig(t, discoveryBlock), "inventory", "sync", "--out", out)
	if code != ExitFailure || !strings.Contains(errb, "refusing to write an inventory from a partial scan") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("no file may be written from a partial scan")
	}
}

func TestInventorySyncRefusesInvalidResult(t *testing.T) {
	e := exampleEstate()
	// Untagged shadow cluster: no environment, which the allow-list rejects.
	e.eks["444444444444"] = append(e.eks["444444444444"], eksCluster{"eks-mystery", "1.29", `{}`})
	e.install(t)
	out := filepath.Join(t.TempDir(), "fleet.json")
	code, _, errb := run("--config", writeConfig(t, discoveryBlock), "inventory", "sync", "--out", out)
	if code != ExitFailure || !strings.Contains(errb, `"eks-mystery": environment "" is not one of`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("no file may be written when the result is invalid")
	}
}

func TestInvalidDiscoveryConfigRejected(t *testing.T) {
	cfg := writeConfig(t, `, "discovery": {"aws": [{"account": "12", "profile": "--evil", "regions": ["Europe"]}], "concurrency": 999}`)
	code, _, errb := run("--config", cfg, "inventory", "diff")
	for _, want := range []string{"12-digit", "must not start with '-'", "not an AWS region", "concurrency"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q in: %s", want, errb)
		}
	}
	if code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
}

func TestInvalidInventoryRejectedByCommands(t *testing.T) {
	dir := t.TempDir()
	fleet := filepath.Join(dir, "fleet.json")
	if err := os.WriteFile(fleet, []byte(`{"clusters":[
	  {"name":"pay","cloud":"aws","environment":"dev","region":"eu-west-1","account":"222222222222"},
	  {"name":"PAY","cloud":"aws","environment":"prod","region":"eu-west-1","account":"111111111111"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"inventoryPath":"fleet.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb := run("--config", cfg, "kubeconfig", "pay", "--dry-run")
	if code != ExitFailure || !strings.Contains(errb, "duplicate of cluster #1") {
		t.Fatalf("ambiguous name must be refused before acting: code=%d err=%q", code, errb)
	}
}

func TestInventoryDiffWritesReport(t *testing.T) {
	exampleEstate().install(t)
	cfg := writeConfig(t, discoveryBlock)
	report := filepath.Join(t.TempDir(), "diff.json")
	code, out, errb := run("--config", cfg, "inventory", "diff", "--report", report)
	if code != ExitOK || !strings.Contains(out, "IN SYNC") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var rep reconcile.Report
	if err := json.Unmarshal(data, &rep); err != nil || !rep.InSync || rep.Matched == 0 {
		t.Fatalf("report: err=%v %+v", err, rep)
	}
}

// Bootstrapping from an empty inventory: every cluster is new, and the
// environment comes from the naming convention when clusters are untagged.
func TestInventorySyncDerivesEnvironmentFromName(t *testing.T) {
	estate{aks: map[string]aksSub{"sub-apps": {id: "sub-apps-id", clusters: []string{
		`{"name":"payments-k8s-qa-cluster","location":"southafricanorth","resourceGroup":"rg-p-qa","currentKubernetesVersion":"1.30.4","tags":{}}`,
		`{"name":"payments-k8s-prod-cluster","location":"southafricanorth","resourceGroup":"rg-p-prod","currentKubernetesVersion":"1.30.4","tags":{"Environment":"prod"}}`,
	}}}}.install(t)
	empty := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(empty, []byte(`{"clusters":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"inventoryPath": `+quote(empty)+`, "environments": ["dev","ete","qa","prod"],
	  "discovery": {"azure": [{"subscription": "sub-apps"}], "nameEnvironmentPattern": "^.+-k8s-(?P<env>[a-z]+)-cluster$"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("--config", cfg, "inventory", "sync")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	var fleet inventory.Fleet
	if err := json.Unmarshal([]byte(out), &fleet); err != nil {
		t.Fatal(err)
	}
	envs := map[string]string{}
	for _, c := range fleet.Clusters {
		envs[c.Name] = c.Environment
	}
	if envs["payments-k8s-qa-cluster"] != "qa" || envs["payments-k8s-prod-cluster"] != "prod" {
		t.Fatalf("environments: %v", envs)
	}
}
