package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nedctl/internal/audit"
)

// installKubeFake is the connect fake, except the port-forward behaves like
// the real plugin: it stays running (recording its pid) until stopped. The
// fake EKS API already listens on the tunnel's port, standing in for it.
func installKubeFake(t *testing.T, w *ec2World, caData, ssm string) string {
	t.Helper()
	pidFile := filepath.Join(w.home, "tunnel.pid")
	desc := `{"cluster":{"name":"payments-eks-prod","arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","endpoint":"https://` + eksHost +
		`","version":"1.30","certificateAuthority":{"data":"` + caData + `"}}}`
	if ssm == "" {
		ssm = `echo $$ > ` + sq(pidFile) + `; echo "Port opened. Waiting for connections..."; exec sleep 300`
	}
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-regions"*) echo '["af-south-1"]';;
"eks list-clusters"*) echo '{"clusters":["payments-eks-prod"]}';;
"eks describe-cluster"*) printf '%s' `+sq(desc)+`;;
"ec2 describe-instances"*) printf '%s' `+sq(instancesJSON)+`;;
"ssm start-session"*) `+ssm+`;;
"eks get-token"*) echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","status":{"token":"k8s-aws-v1.fake","expirationTimestamp":"2099-01-01T00:00:00Z"}}';;
esac`)
	return pidFile
}

func alive(pidFile string) bool {
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	out, _ := exec.Command("sh", "-c", "kill -0 "+strings.TrimSpace(string(pid))+" 2>/dev/null && echo yes").Output()
	return strings.Contains(string(out), "yes")
}

func TestKubeRunsACommandThroughTheTunnelThenClosesIt(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "prod", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	pidFile := installKubeFake(t, w, ca, "")
	out := filepath.Join(w.home, "version.txt")

	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port),
		"--", "sh", "-c", "kubectl get --raw /version > "+out)
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "v1.30.4-eks") {
		t.Fatalf("kubectl through the tunnel: %q", got)
	}
	if alive(pidFile) {
		t.Fatal("the tunnel must be closed when the command ends")
	}
	if !strings.Contains(errb, "PRODUCTION") || !strings.Contains(errb, "tunnel closed") {
		t.Fatalf("stderr: %q", errb)
	}
	ev := readAudit(t, w.logPath)
	if last := ev[len(ev)-1]; last.Action != "eks-connect" || last.Outcome != audit.OutcomeSuccess || !strings.Contains(last.Detail, "kube command sh") {
		t.Fatalf("audit: %+v", last)
	}
	// The command's own exit code reaches the caller, for scripts.
	if code, _, _ := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port), "--", "sh", "-c", "exit 7"); code != 7 {
		t.Fatalf("exit code: got %d, want 7", code)
	}
}

func TestKubeShellGetsKubeconfigAndCluster(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installKubeFake(t, w, ca, "")
	seen := filepath.Join(w.home, "shell-env")
	shell := filepath.Join(w.home, "fake-shell")
	os.WriteFile(shell, []byte("#!/bin/sh\nprintf '%s|%s' \"$KUBECONFIG\" \"$NEDCTL_KUBE\" > "+sq(seen)+"\n"), 0o755)
	t.Setenv("SHELL", shell)
	if code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port)); code != ExitOK {
		t.Fatalf("err=%q", errb)
	}
	got, _ := os.ReadFile(seen)
	want := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json") + "|payments-eks-prod"
	if string(got) != want {
		t.Fatalf("shell saw %q, want %q", got, want)
	}
}

func TestKubeTunnelThatFailsNeverStartsTheShell(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort() // nothing listens here
	ran := filepath.Join(w.home, "shell-ran")
	shell := filepath.Join(w.home, "fake-shell")
	os.WriteFile(shell, []byte("#!/bin/sh\ntouch "+sq(ran)+"\n"), 0o755)
	t.Setenv("SHELL", shell)
	old := tunnelReadyTimeout
	tunnelReadyTimeout = 5 * time.Second
	t.Cleanup(func() { tunnelReadyTimeout = old })
	// describe-cluster needs a valid CA: take one from a fake API on another port.
	ca := fakeEKSAPI(t, func() int { p, _ := freePort(); return p }())
	installKubeFake(t, w, ca, `echo "An error occurred (TargetNotConnected) when calling the StartSession operation" >&2; exit 254`)
	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port))
	if code != ExitFailure || !strings.Contains(errb, "the tunnel did not open") || !strings.Contains(errb, "TargetNotConnected") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("no shell may start without a tunnel")
	}
	if ev := readAudit(t, w.logPath); ev[len(ev)-1].Outcome != audit.OutcomeFailure {
		t.Fatalf("audit: %+v", ev[len(ev)-1])
	}
}

func TestKubeUsage(t *testing.T) {
	w := newEC2World(t, "dev", "")
	for _, args := range [][]string{{"kube"}, {"kube", "bad name"}, {"kube", "c", "--"}, {"kube", "c", "--port", "99999"}} {
		if code, _, _ := run(append([]string{"--config", w.cfg}, args...)...); code != ExitUsage {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
}

func TestKubeBashPromptShowsClusterInEnvironmentColour(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("NO_COLOR", "")
	cfg := mustLoad(t, newEC2World(t, "prod", "").cfg)
	name, args, cleanup := kubeShell(cfg, profileContext{Environment: "prod"}, "payments-eks-prod")
	if name != "/bin/bash" || len(args) != 3 || args[0] != "--rcfile" || args[2] != "-i" {
		t.Fatalf("got %s %v", name, args)
	}
	rc, _ := os.ReadFile(args[1])
	for _, want := range []string{"[ -f ~/.bashrc ] && . ~/.bashrc", "⎈ payments-eks-prod PROD", `\[\e[1;38;2;239;68;68m\]`} {
		if !strings.Contains(string(rc), want) {
			t.Fatalf("rcfile lacks %q:\n%s", want, rc)
		}
	}
	if fi, _ := os.Stat(args[1]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("rcfile mode %v", fi.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(args[1]); !os.IsNotExist(err) {
		t.Fatal("the rcfile must be removed afterwards")
	}
	t.Setenv("SHELL", "/bin/zsh")
	if name, args, _ := kubeShell(cfg, profileContext{}, "c"); name != "/bin/zsh" || args != nil {
		t.Fatalf("other shells start as they are: %s %v", name, args)
	}
}
