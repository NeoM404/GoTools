package app

import (
	"strings"
	"testing"
)

func TestDiffShowsWhatDiffersAndOnlyNames(t *testing.T) {
	f := newClusterFixture(t, "", "pay-k8s-qa-cluster", "pay2-k8s-qa-cluster")
	key := strings.Join(diffProbe, " ")
	f.answer(t, "pay-k8s-qa-cluster", key,
		"W\tDeployment\tpayments\tpayments-api\t3\tRollingUpdate\tpayments\t{\"pool\":\"app\"}\t\n"+
			"C\tapi\treg/payments-api:1.4.2\t250m\t256Mi\t\t512Mi\tDB_HOST DB_PASSWORD \tpayments-config payments-secrets \t/ready\t8080\n"+
			"W\tDeployment\tother\tweb\t1\tRollingUpdate\t\t\t\n")
	f.answer(t, "pay2-k8s-qa-cluster", key,
		"W\tDeployment\tpayments\tpayments-api\t2\tRollingUpdate\tpayments\t{\"pool\":\"app\"}\t\n"+
			"C\tapi\treg/payments-api:1.3.9\t250m\t256Mi\t\t1Gi\tDB_HOST FEATURE_X \tpayments-config \t/ready\t8080\n")
	code, out, errb := run("--config", f.cfg, "diff", "payments-api", "--env", "qa")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{"payments-api in 2 place(s)", "≠", "replicas", "api: image", "reg/payments-api:1.4.2", "reg/payments-api:1.3.9",
		"api: memory limit", "+FEATURE_X −DB_PASSWORD", "−payments-secrets", "difference(s)", "never read, only their names"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	for _, same := range []string{"cpu request", "readiness probe", "service account"} {
		if strings.Contains(out, same) {
			t.Fatalf("%q is the same everywhere and should be hidden without --all:\n%s", same, out)
		}
	}
	if _, out, _ := run("--config", f.cfg, "diff", "payments-api", "--env", "qa", "--all"); !strings.Contains(out, "readiness probe") {
		t.Fatalf("--all: %s", out)
	}
	if code, _, errb := run("--config", f.cfg, "diff", "nope", "--env", "qa"); code != ExitFailure || !strings.Contains(errb, "not found") {
		t.Fatalf("missing app: code=%d err=%q", code, errb)
	}
}
