package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func TestRecordingPolicy(t *testing.T) {
	off := false
	for _, c := range []struct {
		r    config.Recording
		prod bool
		want bool
	}{
		{config.Recording{}, true, true}, {config.Recording{}, false, false},
		{config.Recording{Production: &off}, true, false}, {config.Recording{All: true}, false, true},
	} {
		if got := c.r.Records(c.prod); got != c.want {
			t.Errorf("%+v prod=%v: %v", c.r, c.prod, got)
		}
	}
}

func TestExecIsRecordedRedactedAndVerifiable(t *testing.T) {
	w := newDebugWorld(t, `, "recording": {"all": true}`)
	fakeCLI(t, "kubectl", `case "$*" in
"config get-contexts -o name") echo acm-k8s-qa-cluster;;
"config get-contexts "*) exit 0;;
"exec -it api-1 -n payments -- sh -c "*) printf 'root@api-1:/# env | grep DB\r\nDB_PASSWORD=hunter22\r\ncard 4111 1111 1111 1111\r\nroot@api-1:/# exit\r\n';;
*) echo "fake kubectl: unexpected: $*" >&2; exit 1;;
esac`)
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "exec", "api-1", "-n", "payments", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "DB_PASSWORD=hunter22") {
		t.Fatalf("the engineer sees the session as it is:\n%s", out)
	}
	if !strings.Contains(errb, "This session is recorded") || !strings.Contains(errb, "recording saved:") {
		t.Fatalf("the engineer is told: %q", errb)
	}
	ev := readAudit(t, w.logPath)
	end := ev[len(ev)-1]
	if end.Action != "kube-exec" || !strings.Contains(end.Detail, "a shell in pod payments/api-1") || !strings.Contains(end.Detail, "; recorded ") || !strings.Contains(end.Detail, " sha256 ") {
		t.Fatalf("audit: %+v", end)
	}
	cfg, _, _ := config.Load(w.cfg)
	dir, _ := recordingDir(cfg)
	files, _ := filepath.Glob(filepath.Join(dir, "*.cast"))
	if len(files) != 1 {
		t.Fatalf("recordings: %v", files)
	}
	cast, _ := os.ReadFile(files[0])
	if strings.Contains(string(cast), "hunter22") || strings.Contains(string(cast), "4111 1111 1111 1111") || !strings.Contains(string(cast), "‹redacted›") ||
		!strings.HasPrefix(string(cast), `{"height":`) || !strings.Contains(string(cast), `"command":"kubectl exec -it api-1`) {
		t.Fatalf("recording:\n%s", cast)
	}
	if fi, _ := os.Stat(files[0]); fi.Mode().Perm() != 0o600 {
		t.Fatalf("recording mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", fi.Mode().Perm())
	}
	// Replay: checked against the trail, then played (cleaned).
	code, out, errb = run("--config", w.cfg, "audit", "replay", files[0], "--fast")
	if code != ExitOK || !strings.Contains(errb, "matches the audit trail") || !strings.Contains(out, "env | grep DB") || !strings.Contains(out, "DB_PASSWORD=‹redacted›") {
		t.Fatalf("replay: %d %q\n%s", code, errb, out)
	}
	// A changed recording is caught.
	os.WriteFile(files[0], append(cast, []byte(`[9.9,"o","rm -rf / # added later\r\n"]`+"\n")...), 0o600)
	if code, _, errb := run("--config", w.cfg, "audit", "replay", files[0], "--verify"); code != ExitFailure || !strings.Contains(errb, "does NOT match") {
		t.Fatalf("tampered: %d %q", code, errb)
	}
}

func TestExecRefusedWhenItCannotBeRecorded(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	os.WriteFile(blocker, nil, 0o600)
	w := newDebugWorld(t, `, "recording": {"all": true, "dir": "`+blocker+`/sessions"}`)
	code, out, errb := runCapturingStdout(t, "--config", w.cfg, "exec", "api-1", "-n", "payments", "--cluster", "acm-k8s-qa-cluster", "--yes")
	if code != ExitFailure || !strings.Contains(errb, "production sessions are recorded") || strings.Contains(out, "EXEC") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	ev := readAudit(t, w.logPath)
	if ev[len(ev)-1].Outcome != "refused" {
		t.Fatalf("audit: %+v", ev[len(ev)-1])
	}
}
