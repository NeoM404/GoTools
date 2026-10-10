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
	for _, args := range [][]string{{"kube", "a", "b"}, {"kube", "bad name"}, {"kube", "c", "--"}, {"kube", "c", "--port", "99999"}} {
		if code, _, _ := run(append([]string{"--config", w.cfg}, args...)...); code != ExitUsage {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
}

func TestKubeBashPromptShowsClusterInEnvironmentColour(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("NO_COLOR", "")
	cfg := mustLoad(t, newEC2World(t, "prod", "").cfg)
	name, args, _, cleanup := kubeShell(cfg, profileContext{Environment: "prod"}, "payments-eks-prod")
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
	t.Setenv("SHELL", "/bin/fish")
	if name, args, env, _ := kubeShell(cfg, profileContext{}, "c"); name != "/bin/fish" || args != nil || env != nil {
		t.Fatalf("other shells start as they are: %s %v %v", name, args, env)
	}
}

// pointDirectAt makes the fake EKS API on port the cluster's "real"
// endpoint, as if the VPN routed to it.
func pointDirectAt(t *testing.T, port int) {
	t.Helper()
	old := directServer
	directServer = func(eksTarget) (string, string) { return "https://127.0.0.1:" + strconv.Itoa(port), eksHost }
	t.Cleanup(func() { directServer = old })
}

func TestKubeConnectsDirectlyWhenTheEndpointAnswers(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installKubeFake(t, w, ca, "")
	pointDirectAt(t, port)
	out := filepath.Join(w.home, "v.txt")
	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--", "sh", "-c", "kubectl get --raw /version > "+out)
	if code != ExitOK || !strings.Contains(errb, "Direct: the endpoint answers from here") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if got, _ := os.ReadFile(out); !strings.Contains(string(got), "v1.30.4-eks") {
		t.Fatalf("kubectl: %q", got)
	}
	if calls := w.awsCalls(t); strings.Contains(calls, "ssm start-session") || strings.Contains(calls, "describe-instances") {
		t.Fatalf("a direct connection needs no tunnel and no instance:\n%s", calls)
	}
	if ev := readAudit(t, w.logPath); !strings.Contains(ev[len(ev)-1].Detail, "direct to "+eksHost) {
		t.Fatalf("audit: %+v", ev[len(ev)-1])
	}
}

func TestConnectDirectWritesKubeconfigAndRecords(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installKubeFake(t, w, ca, "")
	pointDirectAt(t, port)
	code, _, errb := run("--config", w.cfg, "connect", "payments-eks-prod", "--via", "direct")
	if code != ExitOK || !strings.Contains(errb, "export KUBECONFIG=") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	kc, _ := os.ReadFile(filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json"))
	if !strings.Contains(string(kc), `"server": "https://127.0.0.1:`) || !strings.Contains(string(kc), `"tls-server-name": "`+eksHost) {
		t.Fatalf("kubeconfig:\n%s", kc)
	}
	if ev := readAudit(t, w.logPath); ev[len(ev)-1].Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit: %+v", ev[len(ev)-1])
	}
}

func TestViaDirectExplainsAnUnreachableEndpoint(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort() // nothing listens: unreachable
	ca := fakeEKSAPI(t, func() int { p, _ := freePort(); return p }())
	installKubeFake(t, w, ca, "")
	pointDirectAt(t, port)
	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--via", "direct")
	if code != ExitFailure || !strings.Contains(errb, "is not reachable directly from here") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if code, _, _ := run("--config", w.cfg, "kube", "payments-eks-prod", "--via", "sideways"); code != ExitUsage {
		t.Fatalf("bad --via: code=%d", code)
	}
}

func TestAutoWithoutDevopsInstanceOrDirectRouteExplainsBoth(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, func() int { p, _ := freePort(); return p }())
	installKubeFake(t, w, ca, "")
	pointDirectAt(t, port)
	body, _ := os.ReadFile(w.cfg)
	os.WriteFile(w.cfg, []byte(strings.Replace(string(body), `"aws": {`, `"aws": {"devopsInstance": "no-such-box", `, 1)), 0o600)
	code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod")
	for _, want := range []string{`no running instance named like "no-such-box"`, "not reachable directly", "--via direct", "--via-instance"} {
		if code != ExitFailure || !strings.Contains(errb, want) {
			t.Fatalf("code=%d, lacks %q:\n%s", code, want, errb)
		}
	}
}

// The bug from the first real run: a ~/.bashrc (or ~/.zshrc) that exports
// KUBECONFIG silently pointed kubectl away from the cluster. The shell must
// end up with nedctl's kubeconfig, and say it corrected it.
func TestKubeShellRestoresKubeconfigAfterStartupFiles(t *testing.T) {
	for _, sh := range []string{"bash", "zsh"} {
		t.Run(sh, func(t *testing.T) {
			path, err := exec.LookPath(sh)
			if err != nil {
				t.Skip(sh + " not installed")
			}
			w := newEC2World(t, "dev", "")
			port, _ := freePort()
			ca := fakeEKSAPI(t, port)
			installKubeFake(t, w, ca, "")
			seen := filepath.Join(w.home, "seen")
			rcName := map[string]string{"bash": ".bashrc", "zsh": ".zshrc"}[sh]
			os.WriteFile(filepath.Join(w.home, rcName), []byte("export KUBECONFIG=/somewhere/else\ntrap 'printf %s \"$KUBECONFIG\" > "+seen+"' EXIT\n"), 0o600)
			t.Setenv("SHELL", path)
			code, _, errb := run("--config", w.cfg, "kube", "payments-eks-prod", "--port", strconv.Itoa(port))
			if code != ExitOK {
				t.Fatalf("code=%d err=%q", code, errb)
			}
			want := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json")
			if got, _ := os.ReadFile(seen); string(got) != want {
				t.Fatalf("%s ended with KUBECONFIG=%q, want %q", sh, got, want)
			}
			if !strings.Contains(errb, "other terminals: export KUBECONFIG="+want) {
				t.Fatalf("ready message must show the export line: %q", errb)
			}
		})
	}
}

// twoClusterFake is installKubeFake with a second cluster in the account.
func twoClusterFake(t *testing.T, w *ec2World, ca string) {
	t.Helper()
	installKubeFake(t, w, ca, "")
	pidFile := filepath.Join(w.home, "tunnel.pid")
	desc := `{"cluster":{"name":"payments-eks-prod","arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","endpoint":"https://` + eksHost +
		`","version":"1.30","certificateAuthority":{"data":"` + ca + `"}}}`
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-regions"*) echo '["af-south-1"]';;
"eks list-clusters"*) echo '{"clusters":["payments-eks-prod","payments-eks-tools"]}';;
"eks describe-cluster"*) printf '%s' `+sq(desc)+`;;
"ec2 describe-instances"*) printf '%s' `+sq(instancesJSON)+`;;
"ssm start-session"*) echo $$ > `+sq(pidFile)+`; exec sleep 300;;
"eks get-token"*) echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","status":{"token":"k8s-aws-v1.fake","expirationTimestamp":"2099-01-01T00:00:00Z"}}';;
esac`)
}

func TestKubeWithoutNameUsesTheOnlyCluster(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	installKubeFake(t, w, ca, "")
	code, _, errb := run("--config", w.cfg, "kube", "--port", strconv.Itoa(port), "--", "true")
	if code != ExitOK || !strings.Contains(errb, "Using payments-eks-prod, the only cluster in payments · DEV (af-south-1)") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestKubeWithoutNameAsksAndRemembersTheLastCluster(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	twoClusterFake(t, w, ca)
	// No terminal and two clusters: refuse, naming them.
	code, _, errb := run("--config", w.cfg, "kube", "--port", strconv.Itoa(port), "--", "true")
	if code != ExitUsage || !strings.Contains(errb, "2 clusters in payments · DEV — name one: payments-eks-prod, payments-eks-tools") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	// Pick the first (payments-eks-prod) at a terminal.
	answer(t, "prod\n1\n")
	if code, _, errb = run("--config", w.cfg, "kube", "--port", strconv.Itoa(port), "--", "true"); code != ExitOK {
		t.Fatalf("pick: code=%d err=%q", code, errb)
	}
	// Next time it is listed first and marked.
	answer(t, "q\n")
	_, _, errb = run("--config", w.cfg, "kube", "--port", strconv.Itoa(port), "--", "true")
	prod, tools := strings.Index(errb, "payments-eks-prod"), strings.Index(errb, "payments-eks-tools")
	if prod < 0 || tools < 0 || prod > tools || !strings.Contains(errb, "last used") {
		t.Fatalf("the last cluster must come first, marked:\n%s", errb)
	}
}
