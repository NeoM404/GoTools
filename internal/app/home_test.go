package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
)

func TestHomeShowsTunnelsActivityAndChecks(t *testing.T) {
	w := newAzureWorld(t, `,"kubeconfigDir":`+quote(filepath.Join(t.TempDir(), "kube")))
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.WriteFile(filepath.Join(home, ".git-credentials"), []byte("https://neo:pat@dev.azure.com\n"), 0o600)
	cfg, _, _ := config.Load(w.cfg)

	// An open tunnel held by this (live) process.
	p, _ := tunnelRecordPath(cfg, "payments-eks-prod")
	os.MkdirAll(filepath.Dir(p), 0o700)
	data, _ := json.Marshal(tunnelRecord{Cluster: "payments-eks-prod", Port: 40123, PID: os.Getpid(), HopName: "payments-devops", Started: time.Now().Add(-75 * time.Minute)})
	os.WriteFile(p, data, 0o600)
	// Some activity in the audit trail.
	if code, _, errb := run("--config", w.cfg, "azure", "cp", "qa:/tmp/x", "."); code != ExitOK && !strings.Contains(errb, "copy failed") {
		t.Logf("cp: %d %s", code, errb)
	}

	_, out, _ := run("--config", w.cfg, "status")
	for _, want := range []string{"tunnel payments-eks-prod via payments-devops on 127.0.0.1:40123", "open 1h15m", "recently", "scp-download", "1 risky leftover(s) on this machine", "tip: "} {
		if !strings.Contains(out, want) {
			t.Fatalf("home lacks %q:\n%s", want, out)
		}
	}

	// A tampered audit trail is called out.
	log, _ := os.ReadFile(w.logPath)
	os.WriteFile(w.logPath, []byte(strings.Replace(string(log), "scp-download", "scp-dowNload", 1)), 0o600)
	if _, out, _ := run("--config", w.cfg, "status"); !strings.Contains(out, "fails its integrity check") {
		t.Fatalf("broken chain not shown:\n%s", out)
	}
}
