package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/change"
	"github.com/NeoM404/GoTools/internal/config"
)

// fakeServiceNow serves CHG0012345 (approved, Implement, window 08:00–18:00
// UTC on 2026-09-29) unless status overrides, and routes the app's checker to it.
func fakeServiceNow(t *testing.T, approval string, status int) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer snow-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		fmt.Fprintf(w, `{"result":[{"number":{"display_value":"CHG0012345","value":"CHG0012345"},
		  "state":{"display_value":"Implement","value":"-1"},"approval":{"display_value":"x","value":%q},
		  "start_date":{"display_value":"x","value":"2026-09-29 08:00:00"},"end_date":{"display_value":"x","value":"2026-09-29 18:00:00"},
		  "short_description":{"display_value":"Rotate ingress certificates","value":"x"}}]}`, approval)
	}))
	t.Cleanup(srv.Close)
	prev := newChangeChecker
	newChangeChecker = func(s config.ServiceNowConfig, token string) *change.ServiceNow {
		c := prev(s, token)
		c.Instance, c.Client = srv.URL, srv.Client()
		return c
	}
	t.Cleanup(func() { newChangeChecker = prev })
	t.Setenv("BANKCTL_TEST_SNOW", "snow-token")
}

const changePolicy = `, "environments": ["dev","sit","uat","prod"], "changeControl": {
  "requireFor": ["prod"],
  "serviceNow": {"instanceUrl": "https://bank.service-now.example", "tokenEnv": "BANKCTL_TEST_SNOW"}
}`

// changeSetup: AWS creds for the prod account, a marker proving whether the
// cloud CLI fetched anything, and an isolated audit log.
func changeSetup(t *testing.T, policy string) (cfg, marker, logPath string) {
	t.Helper()
	pinToday(t, "2026-09-29") // 10:00 UTC, inside the window
	marker = filepath.Join(t.TempDir(), "fetched")
	fakeAWS(t, "111111111111", "touch "+marker)
	logPath = filepath.Join(t.TempDir(), "audit.jsonl")
	cfg = writeConfig(t, policy+`, "audit": {"logPath": `+quote(logPath)+`}`)
	return cfg, marker, logPath
}

func fetchedCreds(marker string) bool { _, err := os.Stat(marker); return err == nil }

func TestProdWithoutChangeRecordRefused(t *testing.T) {
	cfg, marker, logPath := changeSetup(t, changePolicy)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitFailure || !strings.Contains(errb, "a change record is required for prod clusters") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if fetchedCreds(marker) {
		t.Fatal("credentials fetched without a change record")
	}
	if ev := readAudit(t, logPath); len(ev) != 2 || ev[1].Outcome != audit.OutcomeRefused {
		t.Fatalf("refused attempts must be recorded: %+v", ev)
	}
}

func TestNonProdNeedsNoChangeRecord(t *testing.T) {
	cfg, _, _ := changeSetup(t, changePolicy)
	fakeAWS(t, "222222222222", "exit 0")
	if code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-uat-euw1"); code != ExitOK {
		t.Fatalf("uat is not in requireFor: code=%d err=%q", code, errb)
	}
}

func TestVerifiedChangeRecordAllowsAccess(t *testing.T) {
	fakeServiceNow(t, "approved", http.StatusOK)
	cfg, marker, logPath := changeSetup(t, changePolicy)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitOK || !strings.Contains(errb, "change record CHG0012345 verified: Rotate ingress certificates") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !fetchedCreds(marker) {
		t.Fatal("credentials not fetched")
	}
	end := readAudit(t, logPath)[1]
	if end.ChangeRecord != "CHG0012345" || !end.ChangeVerified || end.Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit: %+v", end)
	}
}

func TestRejectedChangeRecordRefused(t *testing.T) {
	fakeServiceNow(t, "requested", http.StatusOK)
	cfg, marker, logPath := changeSetup(t, changePolicy)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitFailure || !strings.Contains(errb, `approval is "requested"`) || fetchedCreds(marker) {
		t.Fatalf("code=%d err=%q fetched=%v", code, errb, fetchedCreds(marker))
	}
	if end := readAudit(t, logPath)[1]; end.Outcome != audit.OutcomeRefused || end.ChangeVerified {
		t.Fatalf("audit: %+v", end)
	}
}

func TestServiceNowDownFailsClosed(t *testing.T) {
	fakeServiceNow(t, "approved", http.StatusServiceUnavailable)
	cfg, marker, _ := changeSetup(t, changePolicy)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitFailure || !strings.Contains(errb, "could not verify") || !strings.Contains(errb, "--break-glass") || fetchedCreds(marker) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestMissingServiceNowTokenFailsClosed(t *testing.T) {
	fakeServiceNow(t, "approved", http.StatusOK)
	cfg, marker, _ := changeSetup(t, changePolicy)
	t.Setenv("BANKCTL_TEST_SNOW", "")
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitFailure || !strings.Contains(errb, "$BANKCTL_TEST_SNOW is empty") || fetchedCreds(marker) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestBreakGlass(t *testing.T) {
	cfg, marker, logPath := changeSetup(t, changePolicy)
	reason := "P1 INC0099887: payments ingress down, change system unavailable"
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--break-glass", reason)
	if code != ExitOK || !strings.Contains(errb, "BREAK-GLASS access") || !fetchedCreds(marker) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, logPath)
	if !ev[0].BreakGlass || ev[0].BreakGlassReason != reason || ev[1].Outcome != audit.OutcomeSuccess {
		t.Fatalf("break-glass must be flagged from the start event on: %+v", ev)
	}
}

func TestChangeFlagUsageErrors(t *testing.T) {
	cfg, marker, logPath := changeSetup(t, changePolicy)
	for _, args := range [][]string{
		{"--break-glass", "too short"},
		{"--change-record", "CHG0012345", "--break-glass", "P1 incident, all hands, change system down"},
		{"--change-record", "INC0012345"},
	} {
		code, _, _ := run(append([]string{"--config", cfg, "kubeconfig", "eks-payments-prod-euw1"}, args...)...)
		if code != ExitUsage {
			t.Errorf("%v: code=%d want usage", args, code)
		}
	}
	if fetchedCreds(marker) {
		t.Fatal("a usage error must attempt nothing")
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("usage errors are typos, not access attempts: nothing to audit")
	}
}

func TestChangeRecordWithoutServiceNowIsFormatChecked(t *testing.T) {
	cfg, _, logPath := changeSetup(t, `, "changeControl": {"requireFor": ["prod"]}`)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitOK || !strings.Contains(errb, "format-checked only") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if end := readAudit(t, logPath)[1]; end.ChangeVerified {
		t.Fatal("an unverified record must not be marked verified")
	}
}

// Regression: login used to re-parse flags with a narrower set, so any new
// flag made it silently skip the production warning.
func TestLoginStillWarnsWithChangeFlags(t *testing.T) {
	fakeServiceNow(t, "approved", http.StatusOK)
	cfg, _, _ := changeSetup(t, changePolicy)
	code, out, errb := run("--config", cfg, "login", "eks-payments-prod-euw1", "--change-record", "CHG0012345")
	if code != ExitOK || !strings.Contains(out, "is a PRODUCTION cluster") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}

func TestChangeControlConfigValidated(t *testing.T) {
	cfg := writeConfig(t, `, "environments": ["dev","prod"], "changeControl": {"requireFor": ["production"], "pattern": "(",
	  "serviceNow": {"instanceUrl": "http://snow.bank"}}`)
	code, _, errb := run("--config", cfg, "clusters", "list")
	for _, want := range []string{`requireFor has "production"`, "changeControl.pattern", "instanceUrl must be https", "tokenEnv is required"} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q in %q", want, errb)
		}
	}
	if code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
}
