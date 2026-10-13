package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func pinNow(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func answerProbes(t *testing.T, f *clusterFixture, cluster string, probes []probe, outs map[int]string) {
	t.Helper()
	for i, p := range probes {
		key := strings.Join(p, " ")
		if out, ok := outs[i]; ok {
			f.answer(t, cluster, key, out)
		}
	}
}

func TestChangesTimeline(t *testing.T) {
	pinNow(t, time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster")
	probes := changesProbes("")
	answerProbes(t, f, "pay-k8s-qa-cluster", probes, map[int]string{
		0: `{"gitVersion":"v1.31.2"}`,
		chRS: "payments\tpayments-api\t4\t\t2026-10-01T09:00:00Z\treg/payments-api:1.4.1\t2026-10-01T09:00:00Z=kube-controller-manager=Update,\n" +
			"payments\tpayments-api\t5\t\t2026-10-13T11:20:00Z\treg/payments-api:1.4.2\t2026-10-13T11:20:00Z=kube-controller-manager=Update,\n" +
			"payments\tworker\t2\t\t2026-10-13T10:50:00Z\treg/worker:2.0\t\n" +
			"payments\tworker\t3\t\t2026-10-13T11:00:00Z\treg/worker:2.0\t\n" +
			"kube-system\tcoredns\t9\t\t2026-10-13T11:30:00Z\tcoredns:1.11\t\n",
		chRevisions:      "payments\tStatefulSet/ledger\t7\t2026-10-13T11:40:00Z\treg/ledger:3.1\n",
		chConfigMaps:     "payments\tpayments-config\t2026-09-01T00:00:00Z\t2026-09-01T00:00:00Z=kubectl-client-side-apply=Update,2026-10-13T11:15:00Z=argocd-application-controller=Apply,\n",
		chObjects:        "RoleBinding\tpayments\tdebug-access\t2026-10-13T11:45:00Z\t2026-10-13T11:45:00Z=kubectl-create=Update,\n",
		chClusterObjects: "ClusterRoleBinding\t\tbreakglass-admin\t2026-10-13T11:50:00Z\t2026-10-13T11:50:00Z=kubectl-create=Update,\n",
		chNodes:          "ip-10-0-1-1\t2026-10-13T11:05:00Z\tTrue\t2026-10-13T11:06:00Z\t\nip-10-0-1-2\t2026-01-01T00:00:00Z\tFalse\t2026-10-13T11:10:00Z\ttrue\n",
		chHPA:            "payments\tpayments-api\t2026-10-13T11:25:00Z\t6\t8\n",
		chPods:           "payments\tpayments-api-1\nC\tapi\t3\t2026-10-13T11:35:00Z\tOOMKilled\t137\n",
		chEvents:         "payments\tPod/payments-api-1\tBackOff\t2026-10-13T11:36:00Z\t\t4\tBack-off restarting failed container\n",
	})
	f.fail(t, "pay-k8s-qa-cluster", strings.Join(probes[chIstio], " "), `error: the server doesn't have a resource type "virtualservices"`)

	code, out, errb := run("--config", f.cfg, "changes", "--env", "qa")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"revision 5: reg/payments-api:1.4.1 → reg/payments-api:1.4.2",
		"revision 3: same image, the pod template changed",
		"statefulset/payments/ledger", "revision 7: reg/ledger:3.1",
		"configmap/payments/payments-config", "edited by argocd-application-controller",
		"rolebinding/payments/debug-access", "clusterrolebinding/breakglass-admin", "created by kubectl-create",
		"node/ip-10-0-1-1", "joined", "turned NotReady (False); cordoned",
		"scaled to 8 (now 6 running)",
		"container api restarted (OOMKilled, exit 137)",
		"BackOff: Back-off restarting failed container (×4)",
		"revision 2: reg/worker:2.0 (the revision before is no longer kept)", "WHEN", "Secrets are not read",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "CLUSTER") {
		t.Fatalf("one cluster: no cluster column:\n%s", out)
	}
	if strings.Contains(out, "coredns") || strings.Contains(out, "revision 4") {
		t.Fatalf("platform namespaces and older changes are left out:\n%s", out)
	}
	if strings.Contains(errb, "Istio") {
		t.Fatalf("Istio not installed is not a problem: %q", errb)
	}
	// Newest first.
	if strings.Index(out, "breakglass-admin") > strings.Index(out, "payments-api:1.4.2") {
		t.Fatalf("not newest first:\n%s", out)
	}
	// Every list is paged; Secrets are never listed.
	calls := f.kubectlCalls(t)
	if strings.Contains(calls, "secrets") || strings.Count(calls, listChunk) != len(probes)-1 {
		t.Fatalf("calls:\n%s", calls)
	}

	_, out, _ = run("--config", f.cfg, "changes", "--env", "qa", "--kind", "rbac", "-o", "json", "--include-system")
	var doc struct {
		Changes []clusterChange `json:"changes"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Changes) != 2 || doc.Changes[0].Object != "clusterrolebinding/breakglass-admin" {
		t.Fatalf("json: %v %s", err, out)
	}
	if code, _, _ := run("--config", f.cfg, "changes", "--env", "qa", "--since", "1000h"); code != ExitUsage {
		t.Fatal("--since is bounded")
	}
}

func TestChangesNamespaceNarrowsTheLists(t *testing.T) {
	for i, p := range changesProbes("payments") {
		s := strings.Join(p, " ")
		if i == chClusterObjects || i == chNodes || i == 0 {
			continue
		}
		if !strings.Contains(s, "-n payments") || strings.Contains(s, " -A ") {
			t.Fatalf("probe %d lists more than the namespace: %s", i, s)
		}
	}
}
