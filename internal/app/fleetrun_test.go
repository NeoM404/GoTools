package app

import (
	"strings"
	"testing"
)

func TestFleetRunOnEveryClusterOfAnEnvironment(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster", "pay-k8s-qa-cluster", "gone-k8s-qa-cluster")
	f.answer(t, "acm-k8s-qa-cluster", "get nodes", "NAME  STATUS\nn1    Ready\n")
	f.answer(t, "pay-k8s-qa-cluster", "get nodes", "NAME  STATUS\np1    Ready\n")
	f.fail(t, "gone-k8s-qa-cluster", "get nodes", "Unable to connect to the server")
	code, out, errb := run("--config", f.cfg, "fleet", "run", "--env", "qa", "--", "kubectl", "get", "nodes")
	if code != ExitFailure || !strings.Contains(errb, "1 of 3 cluster(s) failed") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "== QA acm-k8s-qa-cluster\nNAME  STATUS\nn1    Ready\n\n== QA gone-k8s-qa-cluster\n✖ Unable to connect to the server\n\n== QA pay-k8s-qa-cluster\nNAME  STATUS\np1    Ready\n") {
		t.Fatalf("out:\n%s", out)
	}
	_, out, _ = run("--config", f.cfg, "fleet", "run", "--env", "qa", "--match", "-k8s-qa", "--prefix", "--", "kubectl", "get", "nodes")
	if !strings.Contains(out, "acm-k8s-qa-cluster  n1    Ready\n") || !strings.Contains(out, "pay-k8s-qa-cluster  p1    Ready\n") {
		t.Fatalf("prefix:\n%s", out)
	}
}

func TestFleetRunIsReadOnly(t *testing.T) {
	for _, cmd := range [][]string{{"kubectl", "delete", "pod", "x"}, {"kubectl", "apply", "-f", "x"}, {"kubectl", "get", "pods", "--context", "other"},
		{"kubectl", "get", "pods", "--kubeconfig=/tmp/x"}, {"kubectl", "logs", "-f", "x"}, {"kubectl", "get", "pods", "-w"}, {"helm", "list"}, {"kubectl"},
		{"kubectl", "auth", "reconcile"}, {"kubectl", "get", "pods", "--as=system:admin"}} {
		if checkReadOnly(cmd) == nil {
			t.Errorf("%v accepted", cmd)
		}
	}
	for _, cmd := range [][]string{{"kubectl", "get", "pods", "-A", "-o", "wide"}, {"kubectl", "auth", "can-i", "list", "secrets"}, {"kubectl", "top", "nodes"}, {"kubectl", "logs", "x", "--tail=5"}} {
		if err := checkReadOnly(cmd); err != nil {
			t.Errorf("%v refused: %v", cmd, err)
		}
	}
	if code, _, errb := run("fleet", "run", "--env", "qa", "--", "kubectl", "delete", "ns", "x"); code != ExitUsage || !strings.Contains(errb, "read-only") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
