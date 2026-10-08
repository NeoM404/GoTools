package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/evidence"
)

// recordQuarter produces a real audit log by running nedctl: a verified
// prod access, a break-glass access, a refused prod attempt and a uat access.
func recordQuarter(t *testing.T) (cfg, logPath string) {
	t.Helper()
	fakeServiceNow(t, "approved", http.StatusOK)
	cfg, _, logPath = changeSetup(t, changePolicy)
	steps := [][]string{
		{"kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345"},
		{"kubeconfig", "eks-payments-prod-euw1", "--break-glass", "P1 INC0099887: payments ingress down"},
		{"kubeconfig", "eks-payments-prod-euw1"}, // refused: no change record
	}
	for _, s := range steps {
		run(append([]string{"--config", cfg}, s...)...)
	}
	fakeAWS(t, "222222222222", "exit 0")
	if code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-uat-euw1"); code != ExitOK {
		t.Fatalf("uat: %d %q", code, errb)
	}
	return cfg, logPath
}

func TestEvidenceFromRealAccesses(t *testing.T) {
	cfg, logPath := recordQuarter(t)
	code, out, errb := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath, "-o", "json")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	var rep evidence.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	s := rep.Summary
	if !rep.Complete || s.Accesses != 4 || s.Production != 3 || s.ProdVerifiedChange != 1 || s.BreakGlass != 1 || s.Refused != 1 {
		t.Fatalf("summary: %+v complete=%v", s, rep.Complete)
	}
	if len(rep.Exceptions) != 1 || !strings.Contains(rep.Exceptions[0].Reason, "break-glass") {
		t.Fatalf("only the break-glass access needs review: %+v", rep.Exceptions)
	}
	if code, out, _ := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath, "--production", "-o", "json"); code != ExitOK || !strings.Contains(out, `"productionOnly": true`) {
		t.Fatalf("--production: code=%d", code)
	}

	// Table view for humans.
	_, table, _ := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath)
	for _, want := range []string{"chains intact", "accesses 4 · production 3 (1 verified change", "NEEDS REVIEW (1)", "break-glass access: P1 INC0099887"} {
		if !strings.Contains(table, want) {
			t.Errorf("missing %q in:\n%s", want, table)
		}
	}
}

func TestTamperedLogCannotProduceCleanEvidence(t *testing.T) {
	cfg, logPath := recordQuarter(t)
	raw, _ := os.ReadFile(logPath)
	// Hide the break-glass: rewrite its flag in place.
	tampered := strings.Replace(string(raw), `"breakGlass":true`, `"breakGlass":false`, 1)
	if tampered == string(raw) {
		t.Fatal("fixture has no break-glass event to tamper with")
	}
	if err := os.WriteFile(logPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errb := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath)
	if code != ExitFailure || !strings.Contains(errb, "chain BROKEN") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	code, out, _ := run("--config", cfg, "audit", "verify", "--log", logPath)
	if code != ExitFailure || !strings.Contains(out, "BROKEN") || !strings.Contains(out, "modified") {
		t.Fatalf("audit verify: code=%d out=%q", code, out)
	}
}

func TestAuditVerifyIntact(t *testing.T) {
	cfg, logPath := recordQuarter(t)
	code, out, _ := run("--config", cfg, "audit", "verify", "--log", logPath, "-o", "json")
	var res []struct {
		OK     bool `json:"ok"`
		Events int  `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if code != ExitOK || len(res) != 1 || !res[0].OK || res[0].Events != 8 {
		t.Fatalf("code=%d res=%+v", code, res)
	}
	if code, _, _ := run("--config", cfg, "audit", "verify", "--log", filepath.Join(t.TempDir(), "missing.jsonl")); code != ExitFailure {
		t.Fatalf("a missing log must not verify: code=%d", code)
	}
}

func TestEvidenceOutFileWithDigest(t *testing.T) {
	cfg, logPath := recordQuarter(t)
	out := filepath.Join(t.TempDir(), "evidence-2026Q3.json")
	code, _, errb := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath, "--out", out)
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if !strings.Contains(errb, hex.EncodeToString(sum[:])) {
		t.Fatalf("printed digest must match the file: %q", errb)
	}
	if info, _ := os.Stat(out); info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence names people and principals; want 0600, got %o", info.Mode().Perm())
	}
	if code, _, _ := run("--config", cfg, "evidence", "--period", "2026-Q3", "--log", logPath, "--out", out); code != ExitFailure {
		t.Fatal("must refuse to overwrite without --force")
	}
}

func TestEvidencePeriodUsage(t *testing.T) {
	for _, args := range [][]string{
		{"evidence"},
		{"evidence", "--period", "2026-Q3", "--from", "2026-07-01", "--to", "2026-09-30"},
		{"evidence", "--from", "2026-09-30", "--to", "2026-07-01"},
		{"evidence", "--period", "last-quarter"},
	} {
		if code, _, _ := run(args...); code != ExitUsage {
			t.Errorf("%v: code=%d want usage", args, code)
		}
	}
}
