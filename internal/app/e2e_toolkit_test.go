package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestE2EToolkitJourney is the end-to-end regression for the developer,
// DevOps and DevSecOps commands: one QA estate (a bastion with two AKS
// clusters, served by the fixture's kubectl), every command run the way an
// engineer runs it, each one's result checked, and at the end the audit
// trail records what changed or read data and its hash chain verifies.
func TestE2EToolkitJourney(t *testing.T) {
	today := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	old := now
	now = func() time.Time { return today }
	t.Cleanup(func() { now = old })
	approved := filepath.Join(t.TempDir(), "approved.json")
	os.WriteFile(approved, []byte(`{"rules":[{"subject":"Group:platform-admins","roles":["cluster-admin"]}]}`), 0o600)
	f := newClusterFixture(t, `,"azure":{"bastions":{"qa":"aks-qa"}},"security":{"approvedAccess":`+quote(approved)+`}`, "pay-k8s-qa-cluster", "acm-k8s-qa-cluster")
	p, a := "pay-k8s-qa-cluster", "acm-k8s-qa-cluster"
	both := func(args, out string) { f.answer(t, p, args, out); f.answer(t, a, args, out) }

	// The estate.
	f.answer(t, p, strings.Join(appProbe, " "), "Deployment\tpayments\tpayments-api\t2\t1\treg.example/pay/api:1.4.2\t2026-10-10T09:00:00Z\n")
	f.answer(t, a, strings.Join(appProbe, " "), "")
	f.answer(t, p, "get deployment payments-api -n payments -o json", `{"kind":"Deployment","metadata":{"name":"payments-api"},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"payments-api"}}},"status":{"readyReplicas":1}}`)
	f.answer(t, p, "get pods -n payments -l app=payments-api -o json", `{"items":[`+oomPod+`,`+healthyPod+`]}`)
	f.answer(t, p, "get events -n payments -o json", `{"items":[]}`)
	f.answer(t, p, "logs api-1 -n payments -c api --previous --tail=15", "java.lang.OutOfMemoryError\n")
	f.answer(t, p, "get pod payments-api -n payments -o name", "")
	f.fail(t, p, "get pod payments-api -n payments -o name", "not found")
	f.answer(t, p, "logs -n payments -l app=payments-api --max-log-requests=20 --prefix --since=1h --tail=200 --all-containers", "[pod/api-1/api] ERROR out of memory\n[pod/api-6/api] ok\n")
	for i, out := range []string{`{"gitVersion":"v1.30.4"}`, "n1\tReady=True,\t\n", "payments\tapi-1\tRunning\tCrashLoopBackOff\t4\t2026-10-10T08:00:00Z\t\n", "Deployment\tpayments\tpayments-api\t2\t1\n", "", ""} {
		f.answer(t, p, strings.Join(healthProbes[i], " "), out)
	}
	for i, out := range []string{`{"gitVersion":"v1.30.4"}`, "n1\tReady=True,\t\n", "", "", "", ""} {
		f.answer(t, a, strings.Join(healthProbes[i], " "), out)
	}
	both("get nodes", "NAME  STATUS\nn1    Ready\n")
	f.answer(t, p, "get deployment payments-api -n payments -o wide", "payments-api 1/2\n")
	f.answer(t, p, "rollout restart deployment/payments-api -n payments --dry-run=server", "restarted (server dry run)\n")
	f.answer(t, p, "get node n1 -o name", "node/n1")
	f.answer(t, p, `get pods -A --field-selector spec.nodeName=n1 -o jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].kind}{"\n"}{end}`, "payments\tapi-1\tReplicaSet\n")
	f.answer(t, p, `get pdb -A -o jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.disruptionsAllowed}{"\n"}{end}`, "")
	f.answer(t, p, "drain n1 --ignore-daemonsets --delete-emptydir-data --timeout=5m --dry-run=server", "evicting pod payments/api-1 (server dry run)\n")
	f.answer(t, p, strings.Join(postureProbes[0], " "), "P\tpayments\tapi-1\t\t\t\ttrue\t1000\t\nC\tapi\treg.example/pay/api:1.4.2\t\t\t\tfalse\t\t256Mi\tDB_PASSWORD \n")
	f.answer(t, p, strings.Join(postureProbes[1], " "), "")
	f.answer(t, a, strings.Join(postureProbes[0], " "), "")
	f.answer(t, a, strings.Join(postureProbes[1], " "), "")
	both(strings.Join(imagesProbe, " "), "P\tpayments\tapi-1\nC\tapi\treg.example/pay/api:1.4.2\treg.example/pay/api@sha256:aaaaaaaaaaaaaaaa\n")
	f.answer(t, p, strings.Join(accessProbes[0], " "), "platform\tcluster-admin\tGroup::platform-admins User::someone \n")
	f.answer(t, p, strings.Join(accessProbes[1], " "), "")
	f.answer(t, a, strings.Join(accessProbes[0], " "), "platform\tcluster-admin\tGroup::platform-admins \n")
	f.answer(t, a, strings.Join(accessProbes[1], " "), "")

	step := func(name string, want int, contains string, args ...string) string {
		t.Helper()
		code, out, errb := run(append([]string{"--config", f.cfg}, args...)...)
		if code != want || (contains != "" && !strings.Contains(out+errb, contains)) {
			t.Fatalf("%s: code=%d (want %d), want %q\nout:\n%s\nerr:\n%s", name, code, want, contains, out, errb)
		}
		return out
	}
	// A developer.
	step("app across environments", ExitOK, "1.4.2", "app", "payments-api", "--env", "qa")
	step("explain why it fails", ExitFailure, "killed for using more memory than its limit (256Mi)", "explain", "deploy/payments-api", "-n", "payments", "--cluster", p)
	step("read its logs", ExitOK, "ERROR out of memory", "logs", "payments-api", "-n", "payments", "--grep", "error", "--cluster", p)
	// DevOps.
	step("morning health check", ExitFailure, "pod payments/api-1: CrashLoopBackOff", "health", "--env", "qa")
	step("fleet-wide read", ExitOK, "== QA pay-k8s-qa-cluster", "fleet", "run", "--env", "qa", "--", "kubectl", "get", "nodes")
	step("fleet-wide write refused", ExitUsage, "read-only", "fleet", "run", "--env", "qa", "--", "kubectl", "delete", "pod", "x")
	step("runbook dry run", ExitOK, "skipped (--dry-run)", "run", "restart-deployment", "deployment=payments-api", "namespace=payments", "--cluster", p, "--dry-run")
	step("drain dry run", ExitOK, "evicting pod payments/api-1 (server dry run)", "node", "drain", "n1", "--cluster", p, "--dry-run")
	// DevSecOps.
	step("posture", ExitFailure, "secret-in-env", "posture", "--env", "qa")
	step("images", ExitOK, "reg.example/pay/api:1.4.2", "images", "--env", "qa")
	step("access review", ExitFailure, "User:someone", "access", "review", "--env", "qa")

	// The record: what read data or could change something is there, with
	// the cluster, and the chain is intact.
	actions := map[string]int{}
	for _, e := range readAudit(t, f.logPath) {
		if e.Phase == "end" {
			actions[e.Action]++
			if e.Cluster != p {
				t.Errorf("%s recorded for %q", e.Action, e.Cluster)
			}
		}
	}
	for _, want := range []string{"logs-read", "runbook"} {
		if actions[want] != 1 {
			t.Errorf("audit lacks %s: %v", want, actions)
		}
	}
	step("audit chain intact", ExitOK, "", "audit", "verify")
}
