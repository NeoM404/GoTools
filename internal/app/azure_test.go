package app

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/audit"
	"nedctl/internal/config"
)

// azureWorld has two bastions and a fake ssh that runs the remote command
// here with a real bash, as the bastion would, against a fake kubectl with
// three contexts. Everything ssh was asked to do is kept in calls.
type azureWorld struct {
	cfg, calls, logPath, remoteHome, remoteTmp string
}

func newAzureWorld(t *testing.T, extra string) *azureWorld {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	w := &azureWorld{calls: filepath.Join(dir, "ssh-calls"), logPath: filepath.Join(dir, "audit.log"), remoteHome: filepath.Join(dir, "bastion-home"), remoteTmp: filepath.Join(dir, "bastion-tmp")}
	// As on the real bastions, ~/.kube belongs to the platform: read-only.
	for _, d := range []string{filepath.Join(w.remoteHome, ".kube"), w.remoteTmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(w.remoteHome, ".kube"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(w.remoteHome, ".kube"), 0o700) })
	w.cfg = filepath.Join(dir, "cfg.json")
	body := `{"environments":["dev","ete","qa","prod"],"prodEnvironments":["qa","prod"],"audit":{"logPath":` + quote(w.logPath) + `},
 "azure":{"bastions":{"qa":"aks-qa","dev":"neo@10.0.0.4"},"hosts":[{"name":"jenkins-dev","environment":"dev","jump":"bastion"}]}` + extra + `}`
	if err := os.WriteFile(w.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeCLI(t, "ssh", `printf '%s\n' "$*" >> `+sq(w.calls)+`
while [ $# -gt 0 ]; do
  case "$1" in -o|-l|-J) shift 2;; -t|-T) shift;; *) break;; esac
done
case "$1" in unreachable*) echo "ssh: connect to host: timed out" >&2; exit 255;; esac
shift
[ $# -eq 0 ] && { echo "interactive login"; exit 0; }
# A login shell here would load this machine's profile and lose the fake
# kubectl from PATH; on a bastion -l is what loads its PATH.
remote=$(printf '%s' "$1" | sed '1s/^bash -lc /bash -c /')
HOME=`+sq(w.remoteHome)+` TMPDIR=`+sq(w.remoteTmp)+` KUBECONFIG= exec sh -c "$remote"`)
	fakeCLI(t, "kubectl", `case "$*" in
"config get-contexts -o name") printf 'Last login banner\nacm-k8s-qa-cluster\npayments-k8s-qa-cluster\npayments-k8s-qa-blue\n';;
"config get-contexts "*) case "$3" in acm-k8s-qa-cluster|payments-k8s-qa-cluster|payments-k8s-qa-blue) exit 0;; *) exit 1;; esac;;
*) echo "kubectl $* KUBECONFIG=$KUBECONFIG"; cat "${KUBECONFIG%%:*}";;
esac`)
	return w
}

func (w *azureWorld) sshCalls(t *testing.T) string {
	t.Helper()
	data, _ := os.ReadFile(w.calls)
	return string(data)
}

func TestAzureKubeOneCommandSelectsTheClusterForThatCommandOnly(t *testing.T) {
	w := newAzureWorld(t, "")
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "azure", "kube", "payments-k8s-qa-cluster", "--yes", "--", "kubectl", "get", "pods", "-A")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	// The cluster name says qa, so the qa bastion is used, and the command
	// sees a session file that sets only current-context, in front of the
	// bastion's own kubeconfig.
	if !strings.Contains(w.sshCalls(t), " aks-qa bash -lc ") {
		t.Fatalf("ssh calls:\n%s", w.sshCalls(t))
	}
	if !strings.Contains(out, "kubectl get pods -A KUBECONFIG="+w.remoteTmp+"/nedctl-ctx.") ||
		!strings.Contains(out, ":"+w.remoteHome+"/.kube/config") || !strings.Contains(out, `current-context: "payments-k8s-qa-cluster"`) {
		t.Fatalf("remote output: %q", out)
	}
	if strings.Contains(out, "client-key") || strings.Contains(out, "users:") {
		t.Fatalf("the session file must not hold credentials: %q", out)
	}
	// The session file is removed after the command.
	if left, _ := filepath.Glob(filepath.Join(w.remoteTmp, "nedctl-ctx.*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "aks-session" || ev[1].Cloud != "azure" || ev[1].Cluster != "payments-k8s-qa-cluster" ||
		ev[1].Environment != "qa" || !ev[1].Production || ev[1].Outcome != audit.OutcomeSuccess || !strings.Contains(ev[1].Detail, "bastion aks-qa") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestAzureKubeInteractiveShellHasTheClusterAndCleansUp(t *testing.T) {
	w := newAzureWorld(t, "")
	old := childStdin
	childStdin = func() io.Reader {
		return strings.NewReader(`echo "KC=$KUBECONFIG"; cat "$NEDCTL_CTX"; echo "PS1=$PS1"; exit` + "\n")
	}
	t.Cleanup(func() { childStdin = old })
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "azure", "kube", "acm-k8s-qa-cluster", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "KC="+w.remoteTmp+"/nedctl-ctx.") || !strings.Contains(out, `current-context: "acm-k8s-qa-cluster"`) ||
		!strings.Contains(out, "PS1=[QA acm-k8s-qa-cluster] ") {
		t.Fatalf("remote shell: %q", out)
	}
	if left, _ := filepath.Glob(filepath.Join(w.remoteTmp, "nedctl-ctx.*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if !strings.Contains(errb, "▶ QA · acm-k8s-qa-cluster on aks-qa") || !strings.Contains(errb, "PRODUCTION") {
		t.Fatalf("banner: %q", errb)
	}
	if !strings.Contains(w.sshCalls(t), "-t aks-qa") {
		t.Fatalf("an interactive session needs a terminal: %s", w.sshCalls(t))
	}
}

func TestAzureKubeWordsListTheBastionAndRememberClusters(t *testing.T) {
	w := newAzureWorld(t, "")
	// Two clusters match "payments": without a terminal nedctl names them.
	code, _, errb := run("--config", w.cfg, "azure", "kube", "qa", "payments")
	if code != ExitUsage || !strings.Contains(errb, "payments-k8s-qa-blue, payments-k8s-qa-cluster") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	// The listing's stray banner line is not a cluster; the rest are
	// remembered for completion and `azure clusters`.
	code, out, _ := run("--config", w.cfg, "azure", "clusters", "qa", "-o", "json")
	if code != ExitOK || strings.Contains(out, "banner") || !strings.Contains(out, `"cluster": "acm-k8s-qa-cluster"`) || !strings.Contains(out, `"bastion": "aks-qa"`) {
		t.Fatalf("code=%d clusters: %s", code, out)
	}
	_, comp, _ := run("--config", w.cfg, "__complete", "azure", "kube", "pay")
	if comp != "payments-k8s-qa-blue\npayments-k8s-qa-cluster\n" {
		t.Fatalf("completion: %q", comp)
	}
	// One match goes straight in.
	answer(t, "qa\n")
	code, _, errb = run("--config", w.cfg, "azure", "kube", "blue", "qa", "--", "true")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAzureKubeUnknownClusterFails(t *testing.T) {
	w := newAzureWorld(t, "")
	code, _, errb := run("--config", w.cfg, "azure", "kube", "nosuch-k8s-qa-cluster", "--yes")
	if code != ExitFailure || !strings.Contains(errb, `no cluster on QA (aks-qa) matches "nosuch-k8s-qa-cluster"`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAzureKubeNeedsEnvironmentWithoutTerminal(t *testing.T) {
	w := newAzureWorld(t, "")
	code, _, errb := run("--config", w.cfg, "azure", "kube")
	if code != ExitUsage || !strings.Contains(errb, "which environment? add one of: dev, qa") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAzureKubeProductionConfirmation(t *testing.T) {
	w := newAzureWorld(t, `,"confirmProduction":true`)
	code, _, errb := run("--config", w.cfg, "azure", "kube", "acm-k8s-qa-cluster")
	if code != ExitFailure || !strings.Contains(errb, "pass --yes") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if strings.Contains(w.sshCalls(t), "--rcfile") {
		t.Fatal("no session may start before confirmation")
	}
}

func TestAzureShellBastionAndHostThroughJump(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"user":"nb000001","bastions":{"qa":"aks-qa","dev":"neo@10.0.0.4"},"hosts":[{"name":"jenkins-dev","environment":"dev","jump":"bastion"}]}`)
	code, _, errb := run("--config", w.cfg, "azure", "shell", "jenkins", "--plain")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	code, _, errb = run("--config", w.cfg, "azure", "shell", "qa", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	calls := w.sshCalls(t)
	if !strings.HasPrefix(calls, "-o ServerAliveInterval=30 -o AddKeysToAgent=yes -t -l nb000001 -J neo@10.0.0.4 jenkins-dev\n") {
		t.Fatalf("plain ssh through the dev bastion: %q", calls)
	}
	if !strings.Contains(calls, "\n-o ServerAliveInterval=30 -o AddKeysToAgent=yes -t -l nb000001 aks-qa bash -lc ") {
		t.Fatalf("bastion shell: %q", calls)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 4 || ev[1].Action != "ssh-session" || ev[1].Environment != "dev" || !strings.Contains(ev[1].Detail, "via neo@10.0.0.4") ||
		ev[3].Environment != "qa" || !ev[3].Production {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestAzureUnreachableBastionIsExplained(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"bastions":{"qa":"unreachable-qa"}}`)
	code, _, errb := run("--config", w.cfg, "azure", "kube", "acm-k8s-qa-cluster", "--yes")
	if code != ExitFailure || !strings.Contains(errb, "could not reach unreachable-qa over SSH") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAzureNotConfigured(t *testing.T) {
	code, _, errb := run("azure", "kube")
	if code != ExitFailure || !strings.Contains(errb, "Azure access is not set up") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAzureConfigRejectsOptionLikeDestinations(t *testing.T) {
	for _, bad := range []string{`{"bastions":{"qa":"-oProxyCommand=x"}}`, `{"bastions":{"qa":"aks qa"}}`, `{"user":"-x","bastions":{"qa":"aks-qa"}}`,
		`{"hosts":[{"name":"a","jump":"-J"}]}`, `{"hosts":[{"name":"a","environment":"dev","jump":"bastion"}]}`} {
		path := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(path, []byte(`{"azure":`+bad+`}`), 0o600)
		if _, _, err := config.Load(path); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSSHArgsQuoteTheRemoteCommand(t *testing.T) {
	remote := remoteBash("echo \"$1\"", "it's; rm -rf /")
	out, err := exec.Command("sh", "-c", remote).Output()
	if err != nil || string(out) != "it's; rm -rf /\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// runCapturingStdout runs nedctl with the process's stdout captured too,
// since an ssh session writes to the terminal, not to nedctl's writer.
func runCapturingStdout(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	r, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = wr
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	code, _, errb := run(args...)
	os.Stdout = old
	wr.Close()
	return code, <-done, errb
}

func TestDoctorChecksAgentAndBastions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	// ssh -G resolves the alias as ~/.ssh/config would: qa to the listener,
	// dev to a port nothing listens on.
	fakeCLI(t, "ssh", `for a; do dest=$a; done
case "$dest" in
aks-qa) printf 'user neo\nhostname 127.0.0.1\nport `+port+`\n';;
*) printf 'hostname 127.0.0.1\nport 1\n';;
esac`)
	old := sshAgentState
	sshAgentState = func(context.Context) (int, int) { return 1, 0 }
	t.Cleanup(func() { sshAgentState = old })
	cfg := writeConfig(t, `,"azure":{"bastions":{"qa":"aks-qa","dev":"aks-dev"}}`)
	_, out, _ := run("--config", cfg, "doctor", "-o", "json")
	for _, want := range []string{`"name": "ssh agent",
      "status": "info"`, `"name": "bastion qa",
      "status": "ok"`, `"name": "bastion dev",
      "status": "warn"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
}

func TestPromptInitStartsOneSSHAgentOnlyForAzure(t *testing.T) {
	_, out, _ := run("prompt", "init", "bash")
	if strings.Contains(out, "nedctl-agent.sock") {
		t.Fatal("no agent without Azure access")
	}
	w := newAzureWorld(t, "")
	_, out, _ = run("--config", w.cfg, "prompt", "init", "bash")
	if !strings.Contains(out, `eval "$(ssh-agent -s -t 12h -a "$SSH_AUTH_SOCK")"`) {
		t.Fatalf("init: %s", out)
	}
}
