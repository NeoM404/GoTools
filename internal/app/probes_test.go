package app

import (
	"context"
	"io"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func TestProbesRunOnEveryClusterOfABastionInOneConnection(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster", "pay-k8s-qa-cluster", "broken-k8s-qa-cluster")
	f.answer(t, "acm-k8s-qa-cluster", "get nodes -o name", "node/a1\nnode/a2\n")
	f.answer(t, "acm-k8s-qa-cluster", "version -o json", `{"serverVersion":{"gitVersion":"v1.30.4"}}`)
	f.answer(t, "pay-k8s-qa-cluster", "get nodes -o name", "node/p1")
	f.answer(t, "pay-k8s-qa-cluster", "version -o json", `{}`)
	f.fail(t, "broken-k8s-qa-cluster", "get nodes -o name", "Unable to connect to the server: dial tcp: i/o timeout\nsecond line")
	cfg, _, err := config.Load(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, code := runProbes(context.Background(), cfg, clusterSel{env: "qa"}, []probe{{"get", "nodes", "-o", "name"}, {"version", "-o", "json"}}, io.Discard)
	if code != ExitOK || len(res) != 3 {
		t.Fatalf("code=%d res=%+v", code, res)
	}
	byName := map[string]clusterOut{}
	for _, r := range res {
		byName[r.Cluster] = r
	}
	if got := string(byName["acm-k8s-qa-cluster"].Outs[0].Out); got != "node/a1\nnode/a2\n" {
		t.Fatalf("acm nodes: %q", got)
	}
	if got := string(byName["pay-k8s-qa-cluster"].Outs[1].Out); got != "{}" || byName["pay-k8s-qa-cluster"].Outs[1].Err != nil {
		t.Fatalf("pay version: %q %v", got, byName["pay-k8s-qa-cluster"].Outs[1].Err)
	}
	if err := byName["broken-k8s-qa-cluster"].reachErr(); err == nil || !strings.Contains(err.Error(), "i/o timeout second line") {
		t.Fatalf("broken: %v", err)
	}
	if n := strings.Count(f.sshCalls(t), "bash -lc"); n != 2 { // one listing, one run
		t.Fatalf("ssh connections: %d\n%s", n, f.sshCalls(t))
	}
	res, _ = runProbes(context.Background(), cfg, clusterSel{env: "qa", match: "pay"}, []probe{{"get", "nodes", "-o", "name"}}, io.Discard)
	if len(res) != 1 || res[0].Cluster != "pay-k8s-qa-cluster" {
		t.Fatalf("match: %+v", res)
	}
}

func TestProbesQuoteTheirArguments(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	f.answer(t, "acm-k8s-qa-cluster", "get pods -l app=x;touch /tmp/pwned", "ok")
	cfg, _, _ := config.Load(f.cfg)
	res, _ := runProbes(context.Background(), cfg, clusterSel{env: "qa"}, []probe{{"get", "pods", "-l", "app=x;touch /tmp/pwned"}}, io.Discard)
	if len(res) != 1 || string(res[0].Outs[0].Out) != "ok" {
		t.Fatalf("%+v", res)
	}
}

func TestProbesOnOneClusterUseASession(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	f.answer(t, "acm-k8s-qa-cluster", "get ns -o name", "namespace/default")
	cfg, _, _ := config.Load(f.cfg)
	res, code := runProbes(context.Background(), cfg, clusterSel{cluster: "acm-k8s-qa-cluster"}, []probe{{"get", "ns", "-o", "name"}}, io.Discard)
	if code != ExitOK || len(res) != 1 || string(res[0].Outs[0].Out) != "namespace/default" || res[0].Where != "on bastion aks-qa" {
		t.Fatalf("code=%d %+v", code, res)
	}
}
