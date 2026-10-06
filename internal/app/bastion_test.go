package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoM404/GoTools/internal/audit"
)

const bastionConfig = "../../configs/bankctl.bastion.example.json"

// bastionKubeconfig is a kubeconfig shaped like the one the platform
// provisions on an AKS bastion: one context per cluster, named after it, each
// authenticating as the AKS local account az writes.
type kcContext struct {
	name, cluster, user string
	exec                bool // user authenticates via kubelogin
}

func writeBastionKubeconfig(t *testing.T, current string, contexts ...kcContext) string {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\ncurrent-context: " + current + "\ncontexts:\n")
	for _, c := range contexts {
		b.WriteString("- name: " + c.name + "\n  context: {cluster: " + c.cluster + ", user: " + c.user + "}\n")
	}
	b.WriteString("clusters:\n")
	seen := map[string]bool{}
	for _, c := range contexts {
		if !seen["c/"+c.cluster] {
			seen["c/"+c.cluster] = true
			b.WriteString("- name: " + c.cluster + "\n  cluster: {server: \"https://" + c.cluster + "-abc123.hcp.southafricanorth.azmk8s.io:443\"}\n")
		}
	}
	b.WriteString("users:\n")
	for _, c := range contexts {
		if seen["u/"+c.user] {
			continue
		}
		seen["u/"+c.user] = true
		if c.exec {
			b.WriteString("- name: " + c.user + "\n  user:\n    exec: {apiVersion: client.authentication.k8s.io/v1beta1, command: kubelogin, args: [get-token]}\n")
		} else {
			b.WriteString("- name: " + c.user + "\n  user: {token: redacted}\n")
		}
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	return path
}

func aksContext(cluster, rg string) kcContext {
	return kcContext{name: cluster, cluster: cluster, user: "clusterUser_" + rg + "_" + cluster}
}

// bastionCfg writes the bastion example config with an isolated audit log
// and any extra fields.
func bastionCfg(t *testing.T, extra string) (cfg, logPath string) {
	t.Helper()
	fleet, err := filepath.Abs("../../configs/fleet.bastion.example.json")
	if err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(t.TempDir(), "audit.jsonl")
	body := `{"mode": "bastion", "inventoryPath": ` + quote(fleet) + `,
	  "environments": ["dev","ete","qa","prod"], "prodEnvironments": ["qa","prod"],
	  "prodPatterns": ["(?i)(^|[-_.])(prod|prd|qa)([-_.]|$)"],
	  "audit": {"logPath": ` + quote(logPath) + `}` + extra + `}`
	cfg = filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg, logPath
}

func currentContext(t *testing.T, kubeconfig string) string {
	t.Helper()
	out, err := exec.Command("kubectl", "config", "current-context", "--kubeconfig", kubeconfig).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func guardJSON(t *testing.T, cfg string) contextStatus {
	t.Helper()
	code, out, errb := run("--config", cfg, "guard", "-o", "json")
	if code != ExitOK {
		t.Fatalf("guard: code=%d err=%q", code, errb)
	}
	var st contextStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return st
}

func TestGuardTreatsQAAsProduction(t *testing.T) {
	writeBastionKubeconfig(t, "payments-k8s-qa-cluster", aksContext("payments-k8s-qa-cluster", "rg-payments-qa"))
	st := guardJSON(t, bastionConfig)
	if !st.Production || st.Environment != "qa" || st.Cluster != "payments-k8s-qa-cluster" {
		t.Fatalf("QA is a production copy and must be guarded as production: %+v", st)
	}
}

func TestGuardPatternDoesNotFlagProductInName(t *testing.T) {
	writeBastionKubeconfig(t, "product-api-k8s-dev-cluster", aksContext("product-api-k8s-dev-cluster", "rg-product-api-dev"))
	if st := guardJSON(t, bastionConfig); st.Production {
		t.Fatalf("\"product\" is not \"prod\": %+v", st)
	}
}

// A context renamed by hand is still recognised from the user entry az wrote.
func TestGuardResolvesRenamedContextByAKSUser(t *testing.T) {
	writeBastionKubeconfig(t, "pay", kcContext{name: "pay", cluster: "c1",
		user: "clusterUser_rg-payments-prod_payments-k8s-prod-cluster"})
	st := guardJSON(t, bastionConfig)
	if !st.Production || st.Cluster != "payments-k8s-prod-cluster" {
		t.Fatalf("got %+v", st)
	}
}

// Without an inventory, the kubeconfig's cluster entry name is still checked
// against the prod patterns.
func TestGuardChecksClusterEntryAgainstPatterns(t *testing.T) {
	writeBastionKubeconfig(t, "pay", kcContext{name: "pay", cluster: "payments-k8s-prod-cluster", user: "u"})
	cfg := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"prodPatterns": ["(?i)(^|[-_.])(prod|prd|qa)([-_.]|$)"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	st := guardJSON(t, cfg)
	if !st.Production || !strings.Contains(strings.Join(st.Reasons, ";"), "kubeconfig cluster payments-k8s-prod-cluster") {
		t.Fatalf("got %+v", st)
	}
}

func TestBastionLoginSwitchesContextAndAudits(t *testing.T) {
	kc := writeBastionKubeconfig(t, "payments-k8s-ete-cluster",
		aksContext("payments-k8s-ete-cluster", "rg-payments-ete"),
		aksContext("payments-k8s-prod-cluster", "rg-payments-prod"))
	fakeCLI(t, "az", "echo az must not be called on a bastion >&2; exit 1")
	cfg, logPath := bastionCfg(t, "")

	code, out, errb := run("--config", cfg, "login", "payments-k8s-prod-cluster")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "PRODUCTION") {
		t.Fatalf("login must warn about production: %q", out)
	}
	if got := currentContext(t, kc); got != "payments-k8s-prod-cluster" {
		t.Fatalf("current context: %q", got)
	}
	ev := readAudit(t, logPath)
	if len(ev) != 2 {
		t.Fatalf("want start+end, got %+v", ev)
	}
	end := ev[1]
	if end.Action != "use-context" || end.Outcome != audit.OutcomeSuccess || !end.Production || end.Environment != "prod" ||
		end.Principal != "kubeconfig-user:clusterUser_rg-payments-prod_payments-k8s-prod-cluster" ||
		!strings.Contains(end.Detail, "shared AKS local account") || end.User == "" {
		t.Fatalf("end event: %+v", end)
	}
}

func TestBastionLoginKubeloginUserIsNotShared(t *testing.T) {
	writeBastionKubeconfig(t, "payments-k8s-ete-cluster", kcContext{name: "payments-k8s-ete-cluster",
		cluster: "payments-k8s-ete-cluster", user: "clusterUser_rg-payments-ete_payments-k8s-ete-cluster", exec: true})
	cfg, logPath := bastionCfg(t, "")
	if code, _, errb := run("--config", cfg, "login", "payments-k8s-ete-cluster"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if ev := readAudit(t, logPath); strings.Contains(ev[1].Detail, "shared") {
		t.Fatalf("a kubelogin (Entra ID) user is personal, not shared: %+v", ev[1])
	}
}

func TestBastionLoginWithoutProvisionedContext(t *testing.T) {
	writeBastionKubeconfig(t, "payments-k8s-ete-cluster", aksContext("payments-k8s-ete-cluster", "rg-payments-ete"))
	cfg, _ := bastionCfg(t, "")
	code, _, errb := run("--config", cfg, "login", "payments-k8s-prod-cluster")
	if code != ExitFailure || !strings.Contains(errb, "no kube-context for payments-k8s-prod-cluster on this host") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestBastionLoginAmbiguousNeedsContextFlag(t *testing.T) {
	kc := writeBastionKubeconfig(t, "payments-k8s-ete-cluster",
		aksContext("payments-k8s-ete-cluster", "rg-payments-ete"),
		kcContext{name: "payments-k8s-prod-cluster", cluster: "payments-k8s-prod-cluster", user: "clusterUser_rg-payments-prod_payments-k8s-prod-cluster"},
		kcContext{name: "payments-k8s-prod-cluster-admin", cluster: "payments-k8s-prod-cluster", user: "clusterAdmin_rg-payments-prod_payments-k8s-prod-cluster"})
	cfg, _ := bastionCfg(t, "")

	code, _, errb := run("--config", cfg, "login", "payments-k8s-prod-cluster")
	if code != ExitFailure || !strings.Contains(errb, "choose one with --context") {
		t.Fatalf("ambiguous: code=%d err=%q", code, errb)
	}
	code, _, errb = run("--config", cfg, "login", "payments-k8s-prod-cluster", "--context", "payments-k8s-ete-cluster")
	if code != ExitFailure || !strings.Contains(errb, "does not belong to payments-k8s-prod-cluster") {
		t.Fatalf("foreign --context: code=%d err=%q", code, errb)
	}
	if code, _, errb = run("--config", cfg, "login", "payments-k8s-prod-cluster", "--context", "payments-k8s-prod-cluster"); code != ExitOK {
		t.Fatalf("explicit --context: code=%d err=%q", code, errb)
	}
	if got := currentContext(t, kc); got != "payments-k8s-prod-cluster" {
		t.Fatalf("current context: %q", got)
	}
}

func TestBastionChangeControlRefusalLeavesContextAlone(t *testing.T) {
	kc := writeBastionKubeconfig(t, "payments-k8s-ete-cluster",
		aksContext("payments-k8s-ete-cluster", "rg-payments-ete"),
		aksContext("payments-k8s-qa-cluster", "rg-payments-qa"))
	cfg, logPath := bastionCfg(t, `, "changeControl": {"requireFor": ["qa", "prod"]}`)
	code, _, errb := run("--config", cfg, "login", "payments-k8s-qa-cluster")
	if code != ExitFailure || !strings.Contains(errb, "a change record is required for qa clusters") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if got := currentContext(t, kc); got != "payments-k8s-ete-cluster" {
		t.Fatalf("a refused login must not switch context; current is %q", got)
	}
	if ev := readAudit(t, logPath); len(ev) != 2 || ev[1].Outcome != audit.OutcomeRefused {
		t.Fatalf("refusal must be recorded: %+v", ev)
	}
}

func TestBastionDryRunPrintsKubectlCommand(t *testing.T) {
	kc := writeBastionKubeconfig(t, "payments-k8s-ete-cluster",
		aksContext("payments-k8s-ete-cluster", "rg-payments-ete"),
		aksContext("payments-k8s-prod-cluster", "rg-payments-prod"))
	cfg, logPath := bastionCfg(t, "")
	code, out, errb := run("--config", cfg, "login", "payments-k8s-prod-cluster", "--dry-run")
	if code != ExitOK || strings.TrimSpace(strings.Split(out, "\n")[0]) != "kubectl config use-context payments-k8s-prod-cluster" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	if got := currentContext(t, kc); got != "payments-k8s-ete-cluster" {
		t.Fatalf("dry run switched context to %q", got)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("a dry run must record nothing")
	}
}

func TestModeFlagMisuse(t *testing.T) {
	cfg, _ := bastionCfg(t, "")
	for _, tc := range []struct {
		cfg  string
		args []string
		want string
	}{
		{cfg, []string{"kubeconfig", "payments-k8s-prod-cluster"}, "does not fetch any"},
		{cfg, []string{"login", "payments-k8s-prod-cluster", "--file", "/tmp/x"}, "--file does not apply on a bastion"},
		{exampleConfig, []string{"login", "eks-payments-prod-euw1", "--context", "x"}, "--context applies only in bastion mode"},
	} {
		code, _, errb := run(append([]string{"--config", tc.cfg}, tc.args...)...)
		if code != ExitUsage || !strings.Contains(errb, tc.want) {
			t.Fatalf("%v: code=%d err=%q", tc.args, code, errb)
		}
	}
}

func TestBastionRefusesDiscovery(t *testing.T) {
	cfg, _ := bastionCfg(t, `, "discovery": {"azure": [{"subscription": "s"}]}`)
	for _, sub := range []string{"diff", "sync"} {
		code, _, errb := run("--config", cfg, "inventory", sub)
		if code != ExitFailure || !strings.Contains(errb, "does not run on a bastion") {
			t.Fatalf("%s: code=%d err=%q", sub, code, errb)
		}
	}
}

func TestBastionDoctorNeedsNoCloudCLI(t *testing.T) {
	cfg, _ := bastionCfg(t, "")
	_, out, _ := run("--config", cfg, "doctor", "-o", "json")
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	for _, tl := range rep.Tools {
		if (tl.Name == "aws" || tl.Name == "az") && tl.Required {
			t.Fatalf("%s must not be required on a bastion", tl.Name)
		}
		if tl.Name == "kubectl" && !tl.Required {
			t.Fatal("kubectl stays required")
		}
	}
}

func TestInventoryValidate(t *testing.T) {
	code, out, errb := run("--config", bastionConfig, "inventory", "validate")
	if code != ExitOK || !strings.Contains(out, "inventory valid: 4 cluster(s) — dev 1, ete 1, prod 1, qa 1") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	bad := filepath.Join(t.TempDir(), "fleet.json")
	if err := os.WriteFile(bad, []byte(`{"clusters":[
	  {"name":"a-k8s-uat-cluster","cloud":"azure","environment":"uat","subscription":"s","resourceGroup":"rg"},
	  {"name":"b-k8s-dev-cluster","cloud":"azure","environment":"dev"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb = run("--config", bastionConfig, "inventory", "validate", "--file", bad)
	if code != ExitFailure || !strings.Contains(errb, "3 problems") || !strings.Contains(errb, `environment "uat" is not one of`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestInitBastionMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	if code, _, errb := run("init", "--path", path, "--mode", "bastion"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"mode": "bastion"`) {
		t.Fatalf("err=%v config=%s", err, data)
	}
	if code, _, errb := run("init", "--path", path, "--force", "--mode", "jumpbox"); code != ExitUsage || !strings.Contains(errb, "want workstation or bastion") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
