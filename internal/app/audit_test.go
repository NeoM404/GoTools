package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeoM404/GoTools/internal/audit"
)

func auditConfig(t *testing.T, extra string) (cfg, logPath string) {
	t.Helper()
	logPath = filepath.Join(t.TempDir(), "audit.jsonl")
	return writeConfig(t, `, "audit": {"logPath": `+quote(logPath)+extra+`}`), logPath
}

func readAudit(t *testing.T, path string) []audit.Event {
	t.Helper()
	events, res, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("audit chain invalid: %+v", res)
	}
	return events
}

func TestWrongAWSAccountRefusedAndAudited(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "fetched")
	fakeAWS(t, "999999999999", "touch "+marker)
	cfg, logPath := auditConfig(t, "")
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitFailure || !strings.Contains(errb, "active AWS credentials are for account 999999999999") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("credentials were fetched from the wrong account")
	}
	ev := readAudit(t, logPath)
	if len(ev) != 2 || ev[0].Phase != audit.PhaseStart || ev[1].Outcome != audit.OutcomeRefused || ev[0].ID != ev[1].ID {
		t.Fatalf("want start + refused end for one access: %+v", ev)
	}
	if !strings.Contains(ev[1].Principal, "999999999999") {
		t.Fatalf("the refused principal must be recorded: %+v", ev[1])
	}
}

func TestSuccessfulFetchIsAudited(t *testing.T) {
	fakeAWS(t, "111111111111", "exit 0")
	cfg, logPath := auditConfig(t, "")
	if code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, logPath)
	if len(ev) != 2 {
		t.Fatalf("got %d events", len(ev))
	}
	end := ev[1]
	if end.Outcome != audit.OutcomeSuccess || !end.Production || end.Cluster != "eks-payments-prod-euw1" ||
		end.Account != "111111111111" || end.Environment != "prod" || !strings.HasPrefix(end.Principal, "arn:aws:sts::111111111111:") {
		t.Fatalf("end event: %+v", end)
	}
	if end.User == "" || end.Host == "" || end.Tool != "bankctl" {
		t.Fatalf("attribution missing: %+v", end)
	}
}

func TestAzureFetchVerifiesSubscriptionAndRecordsPrincipal(t *testing.T) {
	fakeCLI(t, "az", `case "$*" in
*"account show --subscription sub-core-prod "*) echo '{"id":"0000-aaaa","name":"sub-core-prod","user":{"name":"neo@bank.example","type":"user"}}';;
*"aks get-credentials"*) exit 0;;
*) echo "unexpected $*" >&2; exit 1;;
esac`)
	cfg, logPath := auditConfig(t, "")
	if code, _, errb := run("--config", cfg, "kubeconfig", "aks-core-prod-weu"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if ev := readAudit(t, logPath); ev[1].Principal != "neo@bank.example" {
		t.Fatalf("principal: %+v", ev[1])
	}
}

func TestFetchRefusedWhenAuditLogUnwritable(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "called")
	fakeCLI(t, "aws", "touch "+marker)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, `, "audit": {"logPath": `+quote(filepath.Join(blocker, "audit.jsonl"))+`}`)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitFailure || !strings.Contains(errb, "every credential fetch must be recorded") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the cloud CLI ran although the access could not be recorded")
	}
}

func TestDryRunIsNotAudited(t *testing.T) {
	cfg, logPath := auditConfig(t, "")
	if code, _, _ := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1", "--dry-run"); code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatal("a dry run fetches nothing and must record nothing")
	}
}

func TestForwardWithoutTokenWarnsButRecordsLocally(t *testing.T) {
	fakeAWS(t, "111111111111", "exit 0")
	t.Setenv("BANKCTL_TEST_HEC", "")
	cfg, logPath := auditConfig(t, `, "forward": {"url": "https://siem.invalid/collector", "tokenEnv": "BANKCTL_TEST_HEC"}`)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitOK || !strings.Contains(errb, "$BANKCTL_TEST_HEC is empty") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if len(readAudit(t, logPath)) != 2 {
		t.Fatal("local record must be kept")
	}
}

func TestAuditForwardConfigValidated(t *testing.T) {
	cfg := writeConfig(t, `, "audit": {"forward": {"url": "http://siem.bank/collector", "format": "xml"}}`)
	code, _, errb := run("--config", cfg, "clusters", "list")
	for _, want := range []string{"must be https", "tokenEnv is required", `format "xml"`} {
		if !strings.Contains(errb, want) {
			t.Errorf("missing %q in %q", want, errb)
		}
	}
	if code != ExitFailure {
		t.Fatalf("code=%d", code)
	}
}

func TestSweepApplyIsAudited(t *testing.T) {
	_, kc := sweepSetup(t, sweepKubeconfig)
	cfg, logPath := auditConfig(t, "")
	if code, _, errb := run("--config", cfg, "sweep", "--kubeconfig", kc, "--apply"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, logPath)
	if len(ev) != 2 || ev[1].Action != "kubeconfig-sweep" || !strings.Contains(ev[1].Detail, "removed 2 context(s)") {
		t.Fatalf("got %+v", ev)
	}
}
