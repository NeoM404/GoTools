package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogsOfEveryPodOfADeployment(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.fail(t, c, "get pod payments-api -n payments -o name", `pods "payments-api" not found`)
	f.answer(t, c, "get deployment payments-api -n payments -o json", `{"kind":"Deployment","spec":{"selector":{"matchLabels":{"app":"payments-api"}}}}`)
	f.answer(t, c, "logs -n payments -l app=payments-api --max-log-requests=20 --prefix --since=10m --tail=200 --all-containers",
		"[pod/payments-api-1/api] started\n[pod/payments-api-2/api] ERROR db timeout\n[pod/payments-api-1/api] ok\n")
	code, out, errb := run("--config", f.cfg, "logs", "payments-api", "-n", "payments", "--since", "10m", "--cluster", c)
	if code != ExitOK || out != "[pod/payments-api-1/api] started\n[pod/payments-api-2/api] ERROR db timeout\n[pod/payments-api-1/api] ok\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	code, out, _ = run("--config", f.cfg, "logs", "deploy/payments-api", "-n", "payments", "--since", "10m", "--grep", "error", "--cluster", c)
	if code != ExitOK || out != "[pod/payments-api-2/api] ERROR db timeout\n" {
		t.Fatalf("grep: code=%d out=%q", code, out)
	}
	ev := readAudit(t, f.logPath)
	if len(ev) != 4 || ev[1].Action != "logs-read" || !strings.Contains(ev[1].Detail, "deployment/payments-api in payments (since 10m)") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestLogsOfOnePodAndContainer(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get pod api-1 -n default -o name", "pod/api-1")
	f.answer(t, c, "logs -n default api-1 --prefix --since=1h --tail=50 -c api", "[pod/api-1/api] hello\n")
	code, out, errb := run("--config", f.cfg, "logs", "api-1", "--tail", "50", "-c", "api", "--cluster", c)
	if code != ExitOK || out != "[pod/api-1/api] hello\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	for _, bad := range [][]string{{"logs"}, {"logs", "x", "--since", "1d"}, {"logs", "svc/x"}, {"logs", "x", "-c", "A;B"}} {
		if code, _, _ := run(append([]string{"--config", f.cfg}, bad...)...); code != ExitUsage {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestLogWriterColoursPerPodAcrossPartialWrites(t *testing.T) {
	var b bytes.Buffer
	w := &logWriter{out: &b, color: true}
	w.Write([]byte("[pod/a-1/api] hel"))
	w.Write([]byte("lo\n[pod/b-2/api] x\nno prefix"))
	w.flush()
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "a-1/api") || !strings.HasSuffix(lines[0], " hello") || strings.Contains(lines[0], "[pod/") || lines[2] != "no prefix" {
		t.Fatalf("%q", lines)
	}
	if !strings.Contains(lines[0], "\x1b[") {
		t.Fatal("no colour")
	}
}

func TestLogsHideSecretsAndPersonalData(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get pod api-1 -n default -o name", "pod/api-1")
	f.answer(t, c, "logs -n default api-1 --prefix --since=1h --tail=200 --all-containers",
		"[pod/api-1/api] login user=neo password=hunter22\n[pod/api-1/api] charged 4111 1111 1111 1111\n[pod/api-1/api] GET /health 200\n")
	code, out, errb := run("--config", f.cfg, "logs", "api-1", "--cluster", c)
	if code != ExitOK || strings.Contains(out, "hunter22") || strings.Contains(out, "4111 1111") ||
		!strings.Contains(out, "password=‹redacted›") || !strings.Contains(out, "‹card ****1111›") || !strings.Contains(out, "GET /health 200") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(errb, "2 line(s) had secrets or personal data hidden") || strings.Contains(errb, "--no-redact shows") {
		t.Fatalf("stderr: %q", errb)
	}
	// QA counts as production here: the raw values cannot be asked for.
	if code, out, errb := run("--config", f.cfg, "logs", "api-1", "--cluster", c, "--no-redact"); code != ExitUsage || strings.Contains(out, "hunter22") || !strings.Contains(errb, "not allowed") {
		t.Fatalf("--no-redact in production: code=%d out=%q err=%q", code, out, errb)
	}
}
