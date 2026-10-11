package app

import (
	"strings"
	"testing"
)

func TestAppAcrossEnvironments(t *testing.T) {
	f := newClusterFixture(t, "", "payments-k8s-qa-cluster", "acm-k8s-qa-cluster")
	q := strings.Join(appProbe, " ")
	f.answer(t, "payments-k8s-qa-cluster", q, "Deployment\tpayments\tpayments-api\t3\t2\treg.example/payments/api:1.4.2 reg.example/envoy:1.30\t2026-10-10T09:00:00Z\n"+
		"Deployment\tpayments\tpayments-worker\t1\t1\treg.example/payments/worker:1.4.2\t\n"+
		"StatefulSet\tpayments\tredis\t1\t1\tredis:7\t\n")
	f.answer(t, "acm-k8s-qa-cluster", q, "Deployment\tacm\tacm-web\t2\t2\treg.example/acm:2.0\t\n")
	// The dev bastion has the same fake clusters; one answers for dev too.
	code, out, errb := run("--config", f.cfg, "app", "payments-api", "--env", "qa")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "qa   payments-k8s-qa-cluster  payments   payments-api  2/3    1.4.2,1.30  2026-10-10T09:00:00") {
		t.Fatalf("table:\n%s", out)
	}
	if strings.Contains(out, "payments-worker") || strings.Contains(out, "acm-web") {
		t.Fatalf("only payments-api:\n%s", out)
	}
	code, out, _ = run("--config", f.cfg, "app", "payments", "--env", "qa", "-o", "json")
	if code != ExitOK || strings.Count(out, `"name": "payments-`) != 2 {
		t.Fatalf("contains: %s", out)
	}
	code, out, _ = run("--config", f.cfg, "app", "nothing-like-it", "--env", "qa")
	if code != ExitFailure || !strings.Contains(out, "not found on the 2 cluster(s) searched") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestAppDefaultsToEveryBastionAndSummarisesVersions(t *testing.T) {
	f := newClusterFixture(t, "", "payments-k8s-qa-cluster")
	f.answer(t, "payments-k8s-qa-cluster", strings.Join(appProbe, " "), "Deployment\tpayments\tpayments-api\t1\t1\treg/api:1.4.2\t\n")
	_, out, errb := run("--config", f.cfg, "app", "payments-api")
	// dev and qa bastions both answer (the fake serves the same clusters).
	if !strings.Contains(out, "dev  ") || !strings.Contains(out, "qa   ") || !strings.Contains(errb, "Reading 1 cluster(s) on 10.0.0.4") {
		t.Fatalf("out=%s err=%s", out, errb)
	}
}

func TestImageTag(t *testing.T) {
	for in, want := range map[string]string{"reg:5000/team/api:1.4.2": "1.4.2", "redis": "latest", "reg:5000/api": "latest",
		"reg/api@sha256:0123456789abcdef0123": "0123456789ab"} {
		if got := imageTag(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
