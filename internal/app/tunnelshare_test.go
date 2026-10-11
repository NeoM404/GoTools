package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
)

func writeTunnelRecord(t *testing.T, cfgPath string, r tunnelRecord) string {
	t.Helper()
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := tunnelRecordPath(cfg, r.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(r)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKubeUsesTheTunnelAlreadyOpen(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "prod", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port) // stands in for the tunnel another nedctl holds
	installKubeFake(t, w, ca, "")
	rec := writeTunnelRecord(t, w.cfg, tunnelRecord{Cluster: "payments-eks-prod", Host: eksHost, Profile: "payments-prod", Port: port,
		PID: os.Getpid(), Hop: "i-0aaaaaaaaaaaaaaa1", HopName: "payments-devops"})
	out := filepath.Join(w.home, "version.txt")

	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--", "sh", "-c", "kubectl get --raw /version > "+out)
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "v1.30.4-eks") {
		t.Fatalf("kubectl through the open tunnel: %q", got)
	}
	if calls := w.awsCalls(t); strings.Contains(calls, "ssm start-session") || strings.Contains(calls, "describe-instances") {
		t.Fatalf("a second tunnel was opened:\n%s", calls)
	}
	if !strings.Contains(errb, "already open through payments-devops") || strings.Contains(errb, "tunnel closed") {
		t.Fatalf("stderr: %q", errb)
	}
	if _, err := os.Stat(rec); err != nil {
		t.Fatal("the holder's record must stay")
	}
	if entries, _ := os.ReadDir(leaseDir(rec)); len(entries) != 0 {
		t.Fatalf("lease left behind: %v", entries)
	}
	ev := readAudit(t, w.logPath)
	if last := ev[len(ev)-1]; !strings.Contains(last.Detail, "tunnel already open") {
		t.Fatalf("audit: %+v", last)
	}
}

func TestKubeIgnoresATunnelWhoseHolderIsGoneAndPublishesItsOwn(t *testing.T) {
	w := newEC2World(t, "prod", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	pidFile := installKubeFake(t, w, ca, "")
	rec := writeTunnelRecord(t, w.cfg, tunnelRecord{Cluster: "payments-eks-prod", Host: eksHost, Port: port, PID: 999999, Hop: "i-0aaaaaaaaaaaaaaa1"})
	old := processAlive
	processAlive = func(pid int) bool { return pid == os.Getpid() }
	t.Cleanup(func() { processAlive = old })
	seen := filepath.Join(w.home, "seen.json")

	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port), "--", "sh", "-c", "cat "+sq(rec)+" > "+sq(seen))
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(w.awsCalls(t), "ssm start-session") {
		t.Fatal("a stale record must not stop a new tunnel opening")
	}
	var during tunnelRecord
	data, _ := os.ReadFile(seen)
	if err := json.Unmarshal(data, &during); err != nil || during.PID != os.Getpid() || during.Port != port || during.Hop != "i-0aaaaaaaaaaaaaaa1" {
		t.Fatalf("while open, the record names this holder: %s (%v)", data, err)
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Fatal("the holder removes its record when it closes")
	}
	if alive(pidFile) {
		t.Fatal("the tunnel must be closed")
	}
}

func TestOpenTunnelChecksHostAndPort(t *testing.T) {
	cfg := config.Config{KubeconfigDir: t.TempDir()}
	c := eksTarget{Name: "eks-a", Host: "a.eks.example"}
	p, _ := tunnelRecordPath(cfg, c.Name)
	write := func(r tunnelRecord) {
		data, _ := json.Marshal(r)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldAlive, oldPort := processAlive, portAnswers
	t.Cleanup(func() { processAlive, portAnswers = oldAlive, oldPort })
	processAlive = func(int) bool { return true }
	answering := true
	portAnswers = func(int) bool { return answering }

	write(tunnelRecord{Cluster: "eks-a", Host: "a.eks.example", Port: 40000, PID: 1})
	if r, ok := openTunnel(cfg, c); !ok || r.Port != 40000 {
		t.Fatal("a live tunnel is found")
	}
	if _, ok := openTunnel(cfg, eksTarget{Name: "eks-a", Host: "other-account.eks.example"}); ok {
		t.Fatal("the same name in another account is another cluster")
	}
	answering = false
	if _, ok := openTunnel(cfg, c); ok {
		t.Fatal("a port that does not answer is not used")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("while the holder lives its record stays (it may still be opening)")
	}
	processAlive = func(int) bool { return false }
	if _, ok := openTunnel(cfg, c); ok {
		t.Fatal("a dead holder's tunnel is not used")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("a dead holder's record is removed")
	}
}

func TestHolderWaitsForSessionsUsingItsTunnel(t *testing.T) {
	cfg := config.Config{KubeconfigDir: t.TempDir()}
	p, _ := tunnelRecordPath(cfg, "eks-a")
	dir := leaseDir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"4242", "4343"} {
		if err := os.WriteFile(filepath.Join(dir, pid), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldAlive, oldWait := processAlive, leaseWait
	t.Cleanup(func() { processAlive, leaseWait = oldAlive, oldWait })
	processAlive = func(pid int) bool { return pid == 4242 } // 4343 is a stale lease
	leaseWait = 10 * time.Millisecond
	if n := tunnelUsers(cfg, "eks-a"); n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "4343")); !os.IsNotExist(err) {
		t.Fatal("a stale lease is removed")
	}

	var errb bytes.Buffer
	done := make(chan struct{})
	go func() { waitForTunnelUsers(context.Background(), cfg, "eks-a", &errb); close(done) }()
	select {
	case <-done:
		t.Fatal("must wait while a session uses the tunnel")
	case <-time.After(80 * time.Millisecond):
	}
	_ = os.Remove(filepath.Join(dir, "4242"))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("must stop waiting once the session is gone")
	}
	if !strings.Contains(errb.String(), "1 other session(s) still use this tunnel") {
		t.Fatalf("stderr: %q", errb.String())
	}

	// Ctrl-C closes it anyway.
	_ = os.WriteFile(filepath.Join(dir, "4242"), nil, 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waitForTunnelUsers(ctx, cfg, "eks-a", &bytes.Buffer{})
}

func TestSharedPlanKeepsTheHoldersKubeconfig(t *testing.T) {
	cfg := config.Config{KubeconfigDir: t.TempDir()}
	c := eksTarget{Name: "eks-a", Host: "a.eks.example", Region: "af-south-1", CAData: "Zm9v"}
	r := tunnelRecord{Cluster: "eks-a", Profile: "squad-prod", Port: 40001, Hop: "i-1", HopName: "devops"}
	same, err := sharedPlan(cfg, c, r, "squad-prod")
	if err != nil || filepath.Base(same.kubeconfig) != "eks-a.json" || !same.shared || same.port != 40001 {
		t.Fatalf("same profile: %+v %v", same, err)
	}
	other, err := sharedPlan(cfg, c, r, "squad:readonly")
	if err != nil || filepath.Base(other.kubeconfig) != "eks-a.squad_readonly.json" {
		t.Fatalf("another profile gets its own kubeconfig: %+v %v", other, err)
	}
}
