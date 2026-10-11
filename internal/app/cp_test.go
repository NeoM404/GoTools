package app

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/audit"
)

func tarOf(t *testing.T, files map[string]string) string {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, body := range files {
		if strings.HasSuffix(name, "/") {
			tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755})
			continue
		}
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	return b.String()
}

func TestCpDownloadsAFileAndADirectory(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "exec -n payments api-1 -- tar cf - -C /tmp heap.hprof", tarOf(t, map[string]string{"heap.hprof": "HEAPDATA"}))
	f.answer(t, c, "exec -n payments api-1 -c api -- tar cf - -C /var/log app", tarOf(t, map[string]string{"app/": "", "app/a.log": "one", "app/sub/b.log": "two"}))
	dir := t.TempDir()
	code, _, errb := run("--config", f.cfg, "cp", "api-1:/tmp/heap.hprof", dir, "-n", "payments", "--cluster", c)
	if code != ExitOK || !strings.Contains(errb, "(1 file(s), 8 bytes)") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "heap.hprof")); string(data) != "HEAPDATA" {
		t.Fatalf("file: %q", data)
	}
	code, _, errb = run("--config", f.cfg, "cp", "api-1:/var/log/app", filepath.Join(dir, "logs"), "-n", "payments", "-c", "api", "--cluster", c)
	if data, _ := os.ReadFile(filepath.Join(dir, "logs", "sub", "b.log")); code != ExitOK || string(data) != "two" {
		t.Fatalf("code=%d err=%q data=%q", code, errb, data)
	}
	ev := readAudit(t, f.logPath)
	if len(ev) != 4 || ev[1].Action != "cp-download" || !strings.Contains(ev[1].Detail, "1 file(s), 8 bytes") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestCpRefusesPathsThatEscape(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "exec -n default api-1 -- tar cf - -C /tmp x", tarOf(t, map[string]string{"x/../../evil": "boom"}))
	dir := t.TempDir()
	code, _, errb := run("--config", f.cfg, "cp", "api-1:/tmp/x", filepath.Join(dir, "out"), "--cluster", c)
	if code != ExitFailure || !strings.Contains(errb, "refusing") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil")); err == nil {
		t.Fatal("wrote outside the target")
	}
	for _, bad := range [][]string{{"cp", "api-1:relative", "."}, {"cp", "a", "b"}, {"cp", "api-1:/", "."}, {"cp", "api-1:/x;rm", "."}} {
		if code, _, _ := run(append([]string{"--config", f.cfg}, bad...)...); code != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestCpUploadAsksAndStreamsATar(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	key := "exec -i -n payments api-1 -- tar xf - -C /tmp"
	f.keepStdin(t, c, key, "")
	src := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(src, []byte("a: 1\n"), 0o600)
	code, _, errb := run("--config", f.cfg, "cp", src, "api-1:/tmp/config.yaml", "-n", "payments", "--cluster", c)
	if code != ExitUsage || !strings.Contains(errb, "nothing copied") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	answer(t, "y\n")
	code, _, errb = run("--config", f.cfg, "cp", src, "api-1:/tmp/config.yaml", "-n", "payments", "--cluster", c)
	if code != ExitOK || !strings.Contains(errb, "To copy "+src+" (1 file(s), 5 bytes) into api-1:/tmp/config.yaml") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	tr := tar.NewReader(bytes.NewReader(f.stdinOf(c, key)))
	h, err := tr.Next()
	if err != nil || h.Name != "config.yaml" {
		t.Fatalf("archive: %v %+v", err, h)
	}
}

func TestAzureCpUsesScpWithTheSSHSettings(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"user":"nb000001","bastions":{"qa":"aks-qa","dev":"neo@10.0.0.4"},"hosts":[{"name":"jenkins-dev","environment":"dev","jump":"bastion"}]}`)
	calls := filepath.Join(t.TempDir(), "scp-calls")
	fakeCLI(t, "scp", `printf '%s\n' "$*" >> `+sq(calls))
	if code, _, errb := run("--config", w.cfg, "azure", "cp", "qa:/tmp/capture.pcap", "."); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if code, _, errb := run("--config", w.cfg, "azure", "cp", "./x.sh", "jenkins-dev:/tmp/"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, _ := os.ReadFile(calls)
	want := "-r -o ServerAliveInterval=30 -o User=nb000001 -- aks-qa:/tmp/capture.pcap .\n" +
		"-r -o ServerAliveInterval=30 -o User=nb000001 -o ProxyJump=neo@10.0.0.4 -- ./x.sh jenkins-dev:/tmp/\n"
	if string(data) != want {
		t.Fatalf("scp:\n%s", data)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 4 || ev[1].Action != "scp-download" || ev[3].Action != "scp-upload" {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestCpSaveWritesToDownloadsWithoutOverwriting(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "exec -n payments api-1 -- tar cf - -C /tmp heap.hprof", tarOf(t, map[string]string{"heap.hprof": "HEAPDATA"}))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, want := range []string{"heap.hprof", "heap-1.hprof"} {
		code, _, errb := run("--config", f.cfg, "cp", "api-1:/tmp/heap.hprof", "--save", "-n", "payments", "--cluster", c)
		if code != ExitOK || !strings.Contains(errb, filepath.Join(home, "Downloads", want)) {
			t.Fatalf("code=%d err=%q", code, errb)
		}
		if data, _ := os.ReadFile(filepath.Join(home, "Downloads", want)); string(data) != "HEAPDATA" {
			t.Fatalf("%s: %q", want, data)
		}
	}
	for _, bad := range [][]string{{"cp", "api-1:/tmp/x", ".", "--save"}, {"cp", "./x", "--save"}, {"cp", "api-1:/tmp/x"}} {
		if code, _, _ := run(append([]string{"--config", f.cfg}, bad...)...); code != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSaveFromWSLGoesToWindowsDownloads(t *testing.T) {
	fakeWSL(t, map[string]string{"WSL_DISTRO_NAME": "Ubuntu"})
	prof := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prof, "Downloads"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := windowsProfile
	windowsProfile = func(context.Context) string { return prof }
	t.Cleanup(func() { windowsProfile = old })
	got, err := saveTarget(context.Background(), "capture.pcap")
	if err != nil || got != filepath.Join(prof, "Downloads", "capture.pcap") {
		t.Fatalf("got %q %v", got, err)
	}
	if w := windowsForm("/mnt/c/Users/nb000001/Downloads/capture.pcap"); w != `C:\Users\nb000001\Downloads\capture.pcap` {
		t.Fatalf("windows form: %q", w)
	}
	if windowsForm("/home/x/Downloads/a") != "" || windowsForm("/mnt/wsl/x") != "" {
		t.Fatal("only /mnt/<drive>/ paths have a Windows form")
	}
}

func TestUniquePathKeepsTheExtension(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.tar.gz", "a.tar-1.gz", ".bashrc"} {
		os.WriteFile(filepath.Join(dir, n), nil, 0o600)
	}
	if got := filepath.Base(uniquePath(dir, "a.tar.gz")); got != "a.tar-2.gz" {
		t.Errorf("a.tar.gz → %s", got)
	}
	if got := filepath.Base(uniquePath(dir, ".bashrc")); got != ".bashrc-1" {
		t.Errorf(".bashrc → %s", got)
	}
	if got := filepath.Base(uniquePath(dir, "new.log")); got != "new.log" {
		t.Errorf("new.log → %s", got)
	}
}

func TestCpFromANodeThroughAReadOnlyHelperPod(t *testing.T) {
	w := newAzureWorld(t, "")
	dir := t.TempDir()
	old := randomSuffix
	randomSuffix = func() string { return "abc123" }
	t.Cleanup(func() { randomSuffix = old })
	archive := filepath.Join(dir, "syslog.tar")
	os.WriteFile(archive, []byte(tarOf(t, map[string]string{"syslog": "kernel: oom-kill"})), 0o600)
	calls := filepath.Join(dir, "calls")
	d := sq(dir)
	fakeCLI(t, "kubectl", `printf '%s\n' "$*" >> `+sq(calls)+`
case "$*" in
"config get-contexts -o name") echo acm-k8s-qa-cluster;;
"config get-contexts "*) exit 0;;
"get node aks-pool1-000001 -o name") echo node/aks-pool1-000001;;
"create --dry-run=server -f - -o name") cat > `+d+`/dry.yaml; echo pod/x;;
"create -f -") cat > `+d+`/created.yaml; echo "pod/x created";;
"wait "*) echo "condition met";;
"exec -n default "*" -- tar cf - -C /host/var/log syslog") cat `+sq(archive)+`;;
"delete "*) echo deleted;;
*) echo "fake kubectl: unexpected: $*" >&2; exit 1;;
esac`)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	// --dry-run shows the helper pod and deploys nothing.
	code, _, errb := run("--config", w.cfg, "cp", "node/aks-pool1-000001:/var/log/syslog", "--save", "--cluster", "acm-k8s-qa-cluster", "--dry-run")
	if code != ExitOK || !strings.Contains(errb, "Dry run only") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, _ := os.ReadFile(calls)
	if strings.Contains(string(data), "create -f -") {
		t.Fatal("a dry run deploys nothing")
	}

	answer(t, "y\n")
	code, _, errb = run("--config", w.cfg, "cp", "node/aks-pool1-000001:/var/log/syslog", "--save", "--cluster", "acm-k8s-qa-cluster")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "Downloads", "syslog")); string(got) != "kernel: oom-kill" {
		t.Fatalf("saved: %q", got)
	}
	created, _ := os.ReadFile(filepath.Join(dir, "created.yaml"))
	m := string(created)
	for _, want := range []string{`nodeName: "aks-pool1-000001"`, "mountPath: /host", "readOnly: true", `nedctl.io/kind: "cp"`, "- operator: Exists"} {
		if !strings.Contains(m, want) {
			t.Errorf("helper pod lacks %q:\n%s", want, m)
		}
	}
	for _, never := range []string{"hostPID", "hostNetwork", "hostIPC", "privileged"} {
		if strings.Contains(m, never) {
			t.Errorf("helper pod must not have %s:\n%s", never, m)
		}
	}
	data, _ = os.ReadFile(calls)
	if !strings.Contains(string(data), "delete pod nedctl-cp-"+debugOwner()+"-abc123 -n default") {
		t.Fatalf("the helper pod must be removed:\n%s", data)
	}
	ev := readAudit(t, w.logPath)
	if last := ev[len(ev)-1]; last.Action != "cp-node" || last.Outcome != audit.OutcomeSuccess || !strings.Contains(last.Detail, "node aks-pool1-000001:/var/log/syslog") {
		t.Fatalf("audit: %+v", last)
	}
	if code, _, errb := run("--config", w.cfg, "cp", "./x", "node/aks-pool1-000001:/tmp/x", "--cluster", "acm-k8s-qa-cluster"); code != ExitUsage || !strings.Contains(errb, "not supported") {
		t.Fatalf("upload to a node: code=%d err=%q", code, errb)
	}
}

func TestAzureCpSave(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"bastions":{"qa":"aks-qa"}}`)
	calls := filepath.Join(t.TempDir(), "scp-calls")
	fakeCLI(t, "scp", `printf '%s\n' "$*" >> `+sq(calls))
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if code, _, errb := run("--config", w.cfg, "azure", "cp", "qa:/tmp/capture.pcap", "--save"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, _ := os.ReadFile(calls)
	if want := "-- aks-qa:/tmp/capture.pcap " + filepath.Join(home, "Downloads", "capture.pcap") + "\n"; !strings.HasSuffix(string(data), want) {
		t.Fatalf("scp: %q", data)
	}
	if code, _, _ := run("--config", w.cfg, "azure", "cp", "./x", "--save"); code != ExitUsage {
		t.Fatal("--save needs a remote source")
	}
}
