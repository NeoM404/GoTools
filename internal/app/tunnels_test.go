package app

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
)

// holdConnect runs `nedctl connect` in the background until its tunnel is
// open, and returns a function that closes it the way an engineer would
// (`nedctl tunnels close`) and gives connect's result.
func holdConnect(t *testing.T, cfgPath string, args ...string) func() (int, string) {
	t.Helper()
	type result struct {
		code int
		errb string
	}
	done := make(chan result, 1)
	go func() {
		code, _, errb := run(append([]string{"--config", cfgPath, "connect"}, args...)...)
		done <- result{code, errb}
	}()
	cfg, _, _ := config.Load(cfgPath)
	rec, _ := tunnelRecordPath(cfg, args[0])
	deadline := time.Now().Add(30 * time.Second)
	for {
		if data, err := os.ReadFile(rec); err == nil {
			var r tunnelRecord
			if json.Unmarshal(data, &r) == nil && r.State != nil && r.State.Session == "open" {
				break
			}
		}
		select {
		case r := <-done:
			t.Fatalf("connect ended before its tunnel opened: code=%d err=%q", r.code, r.errb)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel did not open")
		}
	}
	var once bool
	var res result
	return func() (int, string) {
		if once {
			return res.code, res.errb
		}
		once = true
		if code, out, errb := run("--config", cfgPath, "tunnels", "close", args[0]); code != ExitOK || !strings.Contains(out, "closed the tunnel to "+args[0]) {
			t.Errorf("tunnels close: code=%d out=%q err=%q", code, out, errb)
		}
		select {
		case res = <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("connect did not end after its tunnel was closed")
		}
		return res.code, res.errb
	}
}

// echoUpstream is a TCP echo server standing in for the cluster's API.
func echoUpstream(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("NEDCTL_TEST_UPSTREAM", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
}

func roundTrip(t *testing.T, port int, msg string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("through the tunnel: %q %v", buf, err)
	}
}

func TestManagedTunnelClosesWhenIdleAndReopensOnUse(t *testing.T) {
	echoUpstream(t)
	calls := filepath.Join(t.TempDir(), "calls")
	fakeCLI(t, "aws", `echo "$*" >> `+sq(calls)+`; `+fakeSSMForward)
	cfg := config.Config{KubeconfigDir: t.TempDir()}
	port, _ := freePort()
	plan := tunnelPlan{cluster: eksTarget{Name: "eks-a", Host: "a.eks.example", Region: "af-south-1"}, hop: ec2Instance{ID: "i-1", Name: "devops"}, port: port}
	logf, _ := os.CreateTemp(t.TempDir(), "log")
	defer logf.Close()
	var events lockedBuffer
	tun, err := openManagedTunnel(t.Context(), cfg, plan, "p", logf, &events)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()
	tun.setIdle(300 * time.Millisecond)

	roundTrip(t, port, "hello")
	// Idle: the Session Manager session closes, the port stays.
	deadline := time.Now().Add(5 * time.Second)
	for tun.snapshot().Session != "idle-closed" {
		if time.Now().After(deadline) {
			t.Fatalf("the idle session was not closed; events: %s", events.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(events.String(), "Session Manager session closed") {
		t.Fatalf("events: %q", events.String())
	}
	// Used again: it reopens by itself.
	roundTrip(t, port, "again")
	if s := tun.snapshot(); s.Session != "open" || s.Opened != 2 {
		t.Fatalf("after reuse: %+v", s)
	}
	if data, _ := os.ReadFile(calls); strings.Count(string(data), "start-session") != 2 {
		t.Fatalf("expected two sessions:\n%s", data)
	}
	// A close request stops it for good.
	p, _ := closeRequestPath(cfg, "eks-a")
	os.WriteFile(p, nil, 0o600)
	select {
	case <-tun.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a close request must stop the tunnel")
	}
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		t.Fatal("the port must be closed")
	}
}

func TestTunnelsListsAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.json")
	os.WriteFile(cfgPath, []byte(`{"kubeconfigDir": `+quote(filepath.Join(dir, "kube"))+`}`), 0o600)
	cfg, _, _ := config.Load(cfgPath)
	live := writeTunnelRecord(t, cfgPath, tunnelRecord{Cluster: "eks-live", Port: 40001, PID: os.Getpid(), HopName: "devops", Holder: "kube",
		Started: time.Now().Add(-2 * time.Hour), State: &tunnelState{Session: "idle-closed"}})
	dead := writeTunnelRecord(t, cfgPath, tunnelRecord{Cluster: "eks-dead", Port: 40002, PID: 999999, Holder: "connect"})
	old := processAlive
	processAlive = func(pid int) bool { return pid == os.Getpid() }
	t.Cleanup(func() { processAlive = old })

	code, out, _ := run("--config", cfgPath, "tunnels")
	if code != ExitOK || !strings.Contains(out, "eks-live") || !strings.Contains(out, "closed when idle (reopens on use)") || !strings.Contains(out, "kube (pid") || strings.Contains(out, "eks-dead") {
		t.Fatalf("ls: code=%d out=%q", code, out)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Fatal("a dead holder's record is cleared")
	}
	_ = live
	if code, _, errb := run("--config", cfgPath, "tunnels", "close", "eks-liv"); code != ExitFailure || !strings.Contains(errb, "did you mean eks-live") {
		t.Fatalf("typo: code=%d err=%q", code, errb)
	}
	if code, _, _ := run("--config", cfgPath, "tunnels", "close"); code != ExitUsage {
		t.Fatal("close needs a cluster or --all")
	}
	_ = cfg
}
