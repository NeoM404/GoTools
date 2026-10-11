package app

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestForwardOnAKSChainsBastionAndSSH(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	old := bastionPort
	bastionPort = func() int { return 41234 }
	t.Cleanup(func() { bastionPort = old })
	port, _ := freePort()
	f.answer(t, "acm-k8s-qa-cluster", "port-forward -n payments svc/payments-db 41234:5432 --address 127.0.0.1", "Forwarding from 127.0.0.1:41234 -> 5432\n")
	code, _, errb := run("--config", f.cfg, "forward", "svc/payments-db", strconv.Itoa(port)+":5432", "-n", "payments", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitOK || !strings.Contains(errb, "Forwarding 127.0.0.1:"+strconv.Itoa(port)+" → svc/payments-db:5432 in payments on QA · acm-k8s-qa-cluster") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(f.sshCalls(t), "-o ExitOnForwardFailure=yes -L 127.0.0.1:"+strconv.Itoa(port)+":127.0.0.1:41234 ") {
		t.Fatalf("ssh: %s", f.sshCalls(t))
	}
	if !f.called(t, "acm-k8s-qa-cluster", "port-forward -n payments svc/payments-db 41234:5432 --address 127.0.0.1") {
		t.Fatalf("kubectl: %s", f.kubectlCalls(t))
	}
	ev := readAudit(t, f.logPath)
	if len(ev) != 2 || ev[1].Action != "port-forward" || !strings.Contains(ev[1].Detail, "svc/payments-db in payments port 5432") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestForwardRefusesABusyLocalPortAndBadInput(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, busy, _ := net.SplitHostPort(ln.Addr().String())
	code, _, errb := run("--config", f.cfg, "forward", "svc/db", busy+":5432", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitFailure || !strings.Contains(errb, "is in use on this machine") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, bad := range [][]string{{"forward", "db", "5432"}, {"forward", "svc/db", "70000"}, {"forward", "svc/db"}, {"forward", "cm/x", "80"}} {
		if code, _, _ := run(append([]string{"--config", f.cfg}, bad...)...); code != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestParsePorts(t *testing.T) {
	for in, want := range map[string][2]int{"5432": {5432, 5432}, "443": {8443, 443}, "15432:5432": {15432, 5432}} {
		l, r, err := parsePorts(in)
		if err != nil || l != want[0] || r != want[1] {
			t.Errorf("%s: %d:%d %v", in, l, r, err)
		}
	}
}
