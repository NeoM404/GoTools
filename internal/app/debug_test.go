package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/audit"
)

// debugWorld is an azureWorld whose fake kubectl plays a cluster: it
// records each call, keeps what was created, and can refuse a manifest or
// fail to start a pod.
type debugWorld struct {
	*azureWorld
	dir, kcalls string
}

func newDebugWorld(t *testing.T, extra string) *debugWorld {
	t.Helper()
	w := &debugWorld{azureWorld: newAzureWorld(t, extra), dir: t.TempDir()}
	w.kcalls = filepath.Join(w.dir, "kubectl-calls")
	old := randomSuffix
	randomSuffix = func() string { return "abc123" }
	t.Cleanup(func() { randomSuffix = old })
	nodes := `{"items":[
 {"metadata":{"name":"aks-pool1-000001","labels":{"kubernetes.azure.com/agentpool":"pool1","topology.kubernetes.io/zone":"southafricanorth-1"}},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"kubeletVersion":"v1.30.4"}}},
 {"metadata":{"name":"aks-pool2-000002","labels":{"kubernetes.azure.com/agentpool":"pool2"}},"status":{"conditions":[{"type":"Ready","status":"False"}],"nodeInfo":{"kubeletVersion":"v1.30.4"}}}]}`
	pods := `{"items":[
 {"metadata":{"name":"nedctl-debug-me-1","namespace":"default","labels":{"nedctl.io/owner":"` + debugOwner() + `","nedctl.io/kind":"pod"},"creationTimestamp":"2026-10-11T08:00:00Z"},"spec":{"nodeName":"aks-pool1-000001"},"status":{"phase":"Running"}},
 {"metadata":{"name":"nedctl-debug-other-2","namespace":"payments","labels":{"nedctl.io/owner":"someone-else","nedctl.io/kind":"node"},"creationTimestamp":"2026-10-11T09:00:00Z"},"spec":{"nodeName":"aks-pool2-000002"},"status":{"phase":"Running"}}]}`
	d := sq(w.dir)
	fakeCLI(t, "kubectl", `printf '%s\n' "$*" >> `+sq(w.kcalls)+`
case "$*" in
"config get-contexts -o name") echo acm-k8s-qa-cluster;;
"config get-contexts "*) exit 0;;
"create --dry-run=server -f - -o name") cat > `+d+`/dry.yaml
  if grep -q privileged `+d+`/dry.yaml && [ -f `+d+`/refuse ]; then echo 'admission webhook "policy" denied the request: privileged containers are not allowed' >&2; exit 1; fi
  echo pod/x;;
"create -f -") cat > `+d+`/created.yaml; echo "pod/x created";;
"wait "*) [ -f `+d+`/nostart ] && { echo "timed out waiting" >&2; exit 1; }; echo "condition met";;
"get pod "*"{.spec.containers[*].name}") echo "api sidecar";;
"get pod "*) echo "Pending ErrImagePull pull access denied for nicolaka/netshoot";;
"get nodes -o json") printf '%s' `+sq(nodes)+`;;
"get pods -A -l nedctl.io/debug=true -o json") printf '%s' `+sq(pods)+`;;
"exec "*) echo "EXEC $*";;
"debug "*) echo "DEBUG $*";;
"delete "*) echo "deleted";;
*) echo "fake kubectl: unexpected: $*" >&2; exit 1;;
esac`)
	return w
}

func (w *debugWorld) calls(t *testing.T) string {
	t.Helper()
	data, _ := os.ReadFile(w.kcalls)
	return string(data)
}

func (w *debugWorld) file(name string) string {
	data, _ := os.ReadFile(filepath.Join(w.dir, name))
	return string(data)
}

func TestDebugPodDryRunShowsAndChecksButDeploysNothing(t *testing.T) {
	w := newDebugWorld(t, "")
	code, _, errb := run("--config", w.cfg, "debug", "pod", "--cluster", "acm-k8s-qa-cluster", "--dry-run")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"To deploy a debug pod on QA · acm-k8s-qa-cluster (on bastion aks-qa)", `namespace: "default"`,
		`image: "docker.io/nicolaka/netshoot:v0.13"`, "automountServiceAccountToken: false", "activeDeadlineSeconds: 7200",
		`nedctl.io/owner: "` + debugOwner() + `"`, "The cluster accepts it (server-side dry run).", "Dry run only — nothing was deployed."} {
		if !strings.Contains(errb, want) {
			t.Fatalf("missing %q in:\n%s", want, errb)
		}
	}
	// What was checked is exactly what was shown.
	if !strings.Contains(errb, "    "+strings.ReplaceAll(strings.TrimSpace(w.file("dry.yaml")), "\n", "\n    ")) {
		t.Fatalf("checked manifest differs from the one shown:\n%s", w.file("dry.yaml"))
	}
	if strings.Contains(w.calls(t), "create -f -") || fileExists(w.logPath) {
		t.Fatalf("a dry run deployed something: %s", w.calls(t))
	}
}

func TestDebugPodNeedsApproval(t *testing.T) {
	w := newDebugWorld(t, "")
	code, _, errb := run("--config", w.cfg, "debug", "pod", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitUsage || !strings.Contains(errb, "pass --yes") || strings.Contains(w.calls(t), "create -f -") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	answer(t, "n\n")
	code, _, errb = run("--config", w.cfg, "debug", "pod", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitFailure || !strings.Contains(errb, "Deploy it? [y/N] not deployed") || strings.Contains(w.calls(t), "create -f -") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestDebugPodApprovedRunsAndIsRemoved(t *testing.T) {
	w := newDebugWorld(t, "")
	answer(t, "y\n")
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "debug", "pod", "--cluster", "acm-k8s-qa-cluster", "-n", "payments", "--image", "busybox", "--profile", "netadmin")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	name := "nedctl-debug-" + debugOwner() + "-abc123"
	calls := w.calls(t)
	order := []string{"create --dry-run=server -f - -o name", "create -f -", "wait --for=condition=Ready pod/" + name + " -n payments",
		"exec -it " + name + " -n payments -- sh -c", "delete pod " + name + " -n payments --wait=false --ignore-not-found"}
	at := 0
	for _, o := range order {
		i := strings.Index(calls[at:], o)
		if i < 0 {
			t.Fatalf("%q not after position %d in:\n%s", o, at, calls)
		}
		at += i
	}
	created := w.file("created.yaml")
	if created != w.file("dry.yaml") || !strings.Contains(created, `namespace: "payments"`) || !strings.Contains(created, `image: "docker.io/library/busybox:1.36"`) ||
		!strings.Contains(created, "add: [NET_ADMIN, NET_RAW]") {
		t.Fatalf("created:\n%s", created)
	}
	if !strings.Contains(out, "EXEC exec -it") || !strings.Contains(errb, "removed debug pod payments/"+name) {
		t.Fatalf("out=%q err=%q", out, errb)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "debug-pod" || ev[1].Cloud != "azure" || ev[1].Cluster != "acm-k8s-qa-cluster" || !ev[1].Production ||
		ev[1].Outcome != audit.OutcomeSuccess || !strings.Contains(ev[1].Detail, "image docker.io/library/busybox:1.36, profile netadmin") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestDebugRefusedByTheClusterDeploysNothing(t *testing.T) {
	w := newDebugWorld(t, "")
	os.WriteFile(filepath.Join(w.dir, "refuse"), nil, 0o600)
	code, _, errb := run("--config", w.cfg, "debug", "node", "aks-pool1-000001", "--cluster", "acm-k8s-qa-cluster", "--profile", "sysadmin", "--yes")
	if code != ExitFailure || !strings.Contains(errb, "The cluster refuses it (server-side dry run): admission webhook") || strings.Contains(w.calls(t), "create -f -") {
		t.Fatalf("code=%d err=%q calls=%s", code, errb, w.calls(t))
	}
}

func TestDebugNodeGetsTheNodesNamespacesAndFiles(t *testing.T) {
	w := newDebugWorld(t, "")
	code, _, errb := run("--config", w.cfg, "debug", "node", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitUsage || !strings.Contains(errb, "2 nodes — name one: aks-pool1-000001, aks-pool2-000002") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	code, _, errb = run("--config", w.cfg, "debug", "node", "pool1", "--cluster", "acm-k8s-qa-cluster", "--profile", "sysadmin", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	m := w.file("created.yaml")
	for _, want := range []string{`nodeName: "aks-pool1-000001"`, "hostPID: true", "hostNetwork: true", "- operator: Exists", "privileged: true", "mountPath: /host", `nedctl.io/kind: "node"`} {
		if !strings.Contains(m, want) {
			t.Fatalf("missing %q in:\n%s", want, m)
		}
	}
	if !strings.Contains(errb, "chroot /host") {
		t.Fatalf("hint: %q", errb)
	}
	code, _, errb = run("--config", w.cfg, "debug", "node", "pool1", "--cluster", "acm-k8s-qa-cluster", "--profile", "restricted")
	if code != ExitUsage {
		t.Fatalf("restricted node: code=%d err=%q", code, errb)
	}
}

func TestDebugPodThatCannotStartIsExplainedAndRemoved(t *testing.T) {
	w := newDebugWorld(t, "")
	os.WriteFile(filepath.Join(w.dir, "nostart"), nil, 0o600)
	code, _, errb := run("--config", w.cfg, "debug", "pod", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitFailure || !strings.Contains(errb, "ErrImagePull") || !strings.Contains(errb, `"debug": {"images"`) || !strings.Contains(w.calls(t), "delete pod nedctl-debug-") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Outcome != audit.OutcomeFailure {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestDebugAttachUsesAnEphemeralContainer(t *testing.T) {
	w := newDebugWorld(t, "")
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "debug", "attach", "payments-api-7f9c", "-n", "payments", "-c", "sidecar", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	want := "debug pod/payments-api-7f9c -n payments -it --image docker.io/nicolaka/netshoot:v0.13 --target sidecar --container nedctl-debug-abc123 --profile general"
	if !strings.Contains(out, "DEBUG "+want) || !strings.Contains(errb, "kubectl "+want) {
		t.Fatalf("out=%q err=%q", out, errb)
	}
	code, _, errb = run("--config", w.cfg, "debug", "attach", "payments-api-7f9c", "-c", "nope", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitUsage || !strings.Contains(errb, "it has api, sidecar") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestDebugNetRunsTheChecksInsideTheCluster(t *testing.T) {
	w := newDebugWorld(t, "")
	code, out, errb := run("--config", w.cfg, "debug", "net", "payments-db.internal:5432", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "EXEC exec nedctl-debug-") || !strings.Contains(out, "nedctl payments-db.internal 5432") || !strings.Contains(w.calls(t), "delete pod") {
		t.Fatalf("out=%q", out)
	}
	for _, bad := range []string{"db;rm:5432", "db:99999", "db:x"} {
		if code, _, _ := run("--config", w.cfg, "debug", "net", bad, "--cluster", "acm-k8s-qa-cluster"); code != ExitUsage {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestDebugLsAndCleanOnlyYours(t *testing.T) {
	w := newDebugWorld(t, "")
	old := now
	now = func() time.Time { return time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = old })
	code, out, errb := run("--config", w.cfg, "debug", "ls", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitOK || !strings.Contains(out, "nedctl-debug-me-1") || !strings.Contains(out, "someone-else") || !strings.Contains(out, "running  2h\n") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	code, _, errb = run("--config", w.cfg, "debug", "clean", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitOK || !strings.Contains(errb, "delete pod default/nedctl-debug-me-1") || strings.Contains(errb, "nedctl-debug-other-2") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(w.calls(t), "delete pod -n default --wait=false --ignore-not-found nedctl-debug-me-1") || strings.Contains(w.calls(t), "nedctl-debug-other-2") {
		t.Fatalf("calls: %s", w.calls(t))
	}
}

func TestDebugManifestProfiles(t *testing.T) {
	p := debugPod{Name: "n", Namespace: "default", Image: "busybox", Owner: "me", Kind: "pod", Profile: "restricted", TTL: time.Hour}
	m := p.manifest()
	for _, want := range []string{"runAsNonRoot: true", "drop: [ALL]", "type: RuntimeDefault", `command: ["sleep", "3600"]`} {
		if !strings.Contains(m, want) {
			t.Fatalf("missing %q in:\n%s", want, m)
		}
	}
	if strings.Contains(m, "hostPID") || strings.Contains(m, "/host") {
		t.Fatalf("a pod must not get the node's namespaces:\n%s", m)
	}
}

func TestDebugRejectsBadInput(t *testing.T) {
	w := newDebugWorld(t, "")
	for _, args := range [][]string{{"pod", "-n", "Bad_NS"}, {"pod", "--image", "x; rm -rf /"}, {"pod", "--profile", "root"}, {"pod", "extra"}, {"attach"}, {"frob"}} {
		if code, _, _ := run(append([]string{"--config", w.cfg, "debug"}, args...)...); code != ExitUsage {
			t.Errorf("%v accepted", args)
		}
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestDebugPodOnEKSHoldsOneTunnelForTheSession(t *testing.T) {
	w := newEC2World(t, "dev", "")
	port, _ := freePort()
	ca := fakeEKSAPI(t, port)
	pidFile := installKubeFake(t, w, ca, "")
	old := sessionTunnelPort
	sessionTunnelPort = port
	t.Cleanup(func() { sessionTunnelPort = old })
	kcalls := filepath.Join(w.home, "kubectl-calls")
	fakeCLI(t, "kubectl", `printf '%s %s\n' "$KUBECONFIG" "$*" >> `+sq(kcalls)+`
case "$*" in create*) cat >/dev/null;; esac
echo ok`)
	code, _, errb := run("--config", w.cfg, "debug", "pod", "--cluster", "payments-eks-prod", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, _ := os.ReadFile(kcalls)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 || !strings.Contains(lines[1], "payments-eks-prod.json create -f -") || !strings.Contains(lines[4], " delete pod nedctl-debug-") {
		t.Fatalf("kubectl calls:\n%s", data)
	}
	if strings.Count(w.awsCalls(t), "ssm start-session") != 1 || alive(pidFile) {
		t.Fatalf("one tunnel for the whole session, closed at the end: %s", w.awsCalls(t))
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "debug-pod" || ev[1].Cloud != "aws" || ev[1].Account != "222222222222" || !strings.Contains(ev[1].Detail, "through payments-devops") {
		t.Fatalf("audit: %+v", ev)
	}
}
