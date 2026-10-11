package app

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
