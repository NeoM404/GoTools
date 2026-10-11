package app

import (
	"strings"
	"testing"
)

func drainFixture(t *testing.T) *clusterFixture {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get node n1 -o name", "node/n1")
	f.answer(t, c, `get pods -A --field-selector spec.nodeName=n1 -o jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].kind}{"\n"}{end}`,
		"payments\tapi-1\tReplicaSet\nkube-system\tkube-proxy-x\tDaemonSet\nops\tscratch\t\n")
	f.answer(t, c, `get pdb -A -o jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.disruptionsAllowed}{"\n"}{end}`,
		"payments\tapi-pdb\t0\nother\tx-pdb\t0\n")
	f.answer(t, c, "drain n1 --ignore-daemonsets --delete-emptydir-data --timeout=5m --dry-run=server", "node/n1 cordoned (server dry run)\nevicting pod payments/api-1 (server dry run)\n")
	f.answer(t, c, "drain n1 --ignore-daemonsets --delete-emptydir-data --timeout=5m", "node/n1 drained\n")
	return f
}

func TestNodeDrainPreviewsDryRunsAndAsks(t *testing.T) {
	f := drainFixture(t)
	c := "acm-k8s-qa-cluster"
	code, _, errb := run("--config", f.cfg, "node", "drain", "n1", "--cluster", c, "--dry-run")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"1 pod(s) will move to other nodes; 1 DaemonSet pod(s) stay", "payments/api-1",
		"✖ pod ops/scratch belongs to no controller", "⚠ disruption budget payments/api-pdb allows no disruption", "evicting pod payments/api-1 (server dry run)", "Dry run only"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("missing %q in:\n%s", want, errb)
		}
	}
	if strings.Contains(errb, "other/x-pdb") || f.called(t, c, "drain n1 --ignore-daemonsets --delete-emptydir-data --timeout=5m") {
		t.Fatalf("unrelated budget shown, or drained on a dry run:\n%s", errb)
	}
	code, _, errb = run("--config", f.cfg, "node", "drain", "n1", "--cluster", c)
	if code != ExitUsage || !strings.Contains(errb, "pass --yes") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	answer(t, "y\n")
	code, out, errb := run("--config", f.cfg, "node", "drain", "n1", "--cluster", c)
	if code != ExitOK || !strings.Contains(out, "node/n1 drained") || !strings.Contains(errb, "drain n1 done") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	ev := readAudit(t, f.logPath)
	if len(ev) != 2 || ev[1].Action != "node-drain" || !ev[1].Production || ev[1].Outcome != "success" {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestNodeCordonAndBadInput(t *testing.T) {
	f := drainFixture(t)
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "cordon n1 --dry-run=server", "node/n1 cordoned (server dry run)\n")
	f.answer(t, c, "cordon n1", "node/n1 cordoned\n")
	code, out, errb := run("--config", f.cfg, "node", "cordon", "n1", "--cluster", c, "--yes")
	if code != ExitOK || !strings.Contains(out, "node/n1 cordoned") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	f.fail(t, c, "get node nope -o name", `nodes "nope" not found`)
	if code, _, _ := run("--config", f.cfg, "node", "drain", "nope", "--cluster", c, "--yes"); code != ExitFailure {
		t.Fatal("missing node accepted")
	}
	for _, bad := range [][]string{{"node"}, {"node", "reboot", "n1"}, {"node", "drain"}, {"node", "drain", "n1", "--timeout", "1d"}} {
		if code, _, _ := run(append([]string{"--config", f.cfg}, bad...)...); code != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}
