package app

import (
	"strings"
	"testing"
)

// Text from a cluster or a cloud must reach the screen as text: no escape
// sequence in a log line, an event message (even JSON-escaped) or a tag
// may act on the terminal.
const hostile = "\x1b]52;c;cm0gLXJmIH4=\x07\x1b]0;pwned\x07\x1b[2K"

func noControl(t *testing.T, what, s string) {
	t.Helper()
	if strings.ContainsAny(s, "\x1b\x07\x9b") || strings.Contains(s, "pwned") {
		t.Fatalf("%s carries terminal control:\n%q", what, s)
	}
}

func TestHostileLogLinesAreShownAsText(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get pod api-1 -n default -o name", "pod/api-1")
	f.answer(t, c, "logs -n default api-1 --prefix --since=1h --tail=200 --all-containers", "[pod/api-1/api] login ok"+hostile+" user=x\n")
	code, out, errb := run("--config", f.cfg, "logs", "api-1", "--cluster", c)
	if code != ExitOK || !strings.Contains(out, "login ok") || !strings.Contains(out, "user=x") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	noControl(t, "logs", out)
}

func TestHostileEventMessagesAreShownAsText(t *testing.T) {
	f := newClusterFixture(t, "", "acm-k8s-qa-cluster")
	c := "acm-k8s-qa-cluster"
	f.answer(t, c, "get deployment payments-api -n payments -o json", `{"kind":"Deployment","metadata":{"name":"payments-api"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"payments-api"}}},"status":{"readyReplicas":0}}`)
	f.answer(t, c, "get pods -n payments -l app=payments-api -o json", `{"items":[`+pullPod+`]}`)
	f.answer(t, c, "get events -n payments -o json", `{"items":[{"type":"Warning","reason":"Failed","message":"pull failed \u001b]52;c;cm0gLXJmIH4=\u0007\u001b]0;pwned\u0007 denied","involvedObject":{"kind":"Pod","name":"api-2"}}]}`)
	_, out, errb := run("--config", f.cfg, "explain", "deploy/payments-api", "-n", "payments", "--cluster", c)
	if !strings.Contains(out, "api-2") {
		t.Fatalf("out=%q err=%q", out, errb)
	}
	noControl(t, "explain", out+errb)
}

func TestHostileInstanceTagsAreShownAsText(t *testing.T) {
	w := newEC2World(t, "dev", "")
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-regions"*) echo '["af-south-1"]';;
"ec2 describe-instances"*) printf '%s' '{"Reservations":[{"Instances":[{"InstanceId":"i-0aaaaaaaaaaaaaaa1","State":{"Name":"running"},"Tags":[{"Key":"Name","Value":"web\u001b]0;pwned\u0007"}]},{"InstanceId":"i-0bbbbbbbbbbbbbbb2","State":{"Name":"running"},"Tags":[{"Key":"Name","Value":"db"}]}]}]}';;
esac`)
	answer(t, "q\n")
	_, _, errb := run("--config", w.cfg, "shell")
	if !strings.Contains(errb, "web") {
		t.Fatalf("picker: %q", errb)
	}
	noControl(t, "instance picker", strings.ReplaceAll(errb, "\x1b[", "")) // the picker's own colours are off here; any ESC is the tag's
}
