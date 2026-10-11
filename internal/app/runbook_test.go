package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func TestBuiltInRunbooksAreValidAndListed(t *testing.T) {
	code, out, errb := run("run", "ls")
	if code != ExitOK || errb != "" {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, n := range []string{"restart-deployment", "scale-deployment", "rollback-deployment"} {
		if !strings.Contains(out, n) {
			t.Fatalf("missing %s:\n%s", n, out)
		}
	}
	code, out, _ = run("run", "show", "scale-deployment")
	if code != ExitOK || !strings.Contains(out, "replicas") || !strings.Contains(out, "kubectl scale deployment/{deployment} -n {namespace} --replicas={replicas}") {
		t.Fatalf("show:\n%s", out)
	}
}

func restartFixture(t *testing.T, extra string) *clusterFixture {
	f := newClusterFixture(t, extra, "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get deployment api -n payments -o wide", "NAME  READY\napi   3/3\n")
	f.answer(t, c, "rollout restart deployment/api -n payments --dry-run=server", "deployment.apps/api restarted (server dry run)\n")
	f.answer(t, c, "rollout restart deployment/api -n payments", "deployment.apps/api restarted\n")
	f.answer(t, c, "rollout status deployment/api -n payments --timeout=5m", "deployment \"api\" successfully rolled out\n")
	return f
}

func TestRunbookShowsDryRunsAndAsksBeforeAChange(t *testing.T) {
	f := restartFixture(t, "")
	c := "acm-k8s-qa-cluster"
	answer(t, "y\n")
	code, out, errb := run("--config", f.cfg, "run", "restart-deployment", "deployment=api", "namespace=payments", "--cluster", c)
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"Runbook restart-deployment on QA · acm-k8s-qa-cluster", "2. ✎ Restart: kubectl rollout restart deployment/api -n payments",
		"✔ the cluster accepts it (server-side dry run):\n    deployment.apps/api restarted (server dry run)", "Run it: kubectl rollout restart deployment/api -n payments ? [y/N]", "restart-deployment done"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("missing %q in:\n%s", want, errb)
		}
	}
	if !strings.Contains(out, "successfully rolled out") || !f.called(t, c, "rollout restart deployment/api -n payments") {
		t.Fatalf("out=%q calls=%s", out, f.kubectlCalls(t))
	}
	ev := readAudit(t, f.logPath)
	if len(ev) != 2 || ev[1].Action != "runbook" || ev[1].Outcome != "success" || !strings.Contains(ev[1].Detail, "deployment=api namespace=payments") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestRunbookStopsWithoutApproval(t *testing.T) {
	f := restartFixture(t, "")
	c := "acm-k8s-qa-cluster"
	answer(t, "n\n")
	code, _, errb := run("--config", f.cfg, "run", "restart-deployment", "deployment=api", "namespace=payments", "--cluster", c)
	if code != ExitFailure || !strings.Contains(errb, "stopped — nothing more was changed") || f.called(t, c, "rollout restart deployment/api -n payments") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	// --dry-run changes nothing and asks nothing.
	code, _, errb = run("--config", f.cfg, "run", "restart-deployment", "deployment=api", "namespace=payments", "--cluster", c, "--dry-run")
	if code != ExitOK || !strings.Contains(errb, "skipped (--dry-run)") || f.called(t, c, "rollout restart deployment/api -n payments") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, f.logPath)
	if ev[1].Outcome != "refused" {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestRunbookParametersAreChecked(t *testing.T) {
	f := restartFixture(t, "")
	for _, args := range [][]string{{"deployment=api;rm -rf /"}, {"deployment=--all"}, {"namespace=payments"}, {"deployment=api", "nope=1"}, {"deployment"}} {
		code, _, errb := run(append([]string{"--config", f.cfg, "run", "restart-deployment", "--cluster", "acm-k8s-qa-cluster"}, args...)...)
		if code != ExitUsage {
			t.Errorf("%v: code=%d err=%q", args, code, errb)
		}
	}
	if code, _, _ := run("--config", f.cfg, "run", "scale-deployment", "deployment=api", "replicas=lots", "--cluster", "acm-k8s-qa-cluster"); code != ExitUsage {
		t.Error("replicas=lots accepted")
	}
}

func TestTeamRunbooksAreAddedAndCheckedOnLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ingress-check.json"), []byte(`{"name":"ingress-check","description":"Ingresses of a namespace",
 "params":[{"name":"namespace","description":"ns"}],"steps":[{"name":"List","kubectl":["get","ingress","-n","{namespace}"]}]}`), 0o600)
	os.WriteFile(filepath.Join(dir, "sneaky.json"), []byte(`{"name":"sneaky","description":"x","params":[],"steps":[{"name":"x","kubectl":["get","pods","--context","prod"]}]}`), 0o600)
	os.WriteFile(filepath.Join(dir, "typo.json"), []byte(`{"name":"typo","description":"x","steps":[{"name":"x","kubectl":["get","{ns}"]}]}`), 0o600)
	f := restartFixture(t, `,"runbooksDir":`+quote(dir))
	code, out, errb := run("--config", f.cfg, "run", "ls")
	if code != ExitOK || !strings.Contains(out, "ingress-check") || strings.Contains(out, "sneaky") ||
		!strings.Contains(errb, "--context is not allowed") || !strings.Contains(errb, "uses {ns}, which is not a parameter") {
		t.Fatalf("out=%s err=%s", out, errb)
	}
	f.answer(t, "acm-k8s-qa-cluster", "get ingress -n web", "NAME  HOSTS\nweb   web.example\n")
	code, out, errb = run("--config", f.cfg, "run", "ingress-check", "namespace=web", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitOK || !strings.Contains(out, "web.example") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}

// Every runbook committed to the repository must load: CI catches a broken
// team runbook before anyone runs it.
func TestRepositoryRunbooksAreValid(t *testing.T) {
	books, errs := loadRunbooks(config.Config{RunbooksDir: "../../runbooks"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if _, ok := books["ingress-overview"]; !ok {
		t.Fatal("ingress-overview missing")
	}
}
