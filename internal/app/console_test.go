package app

import (
	"net/url"
	"strings"
	"testing"
)

func TestConsoleLink(t *testing.T) {
	link := consoleLink("https://d-1234567890.awsapps.com/start/", "222222222222", "Platform-Admin", "eks", "af-south-1")
	u, err := url.Parse(link)
	if err != nil || !strings.HasPrefix(link, "https://d-1234567890.awsapps.com/start/#/console?") {
		t.Fatalf("%s %v", link, err)
	}
	q, _ := url.ParseQuery(u.Fragment[strings.Index(u.Fragment, "?")+1:])
	if q.Get("account_id") != "222222222222" || q.Get("role_name") != "Platform-Admin" ||
		q.Get("destination") != "https://console.aws.amazon.com/eks/home?region=af-south-1#/clusters" {
		t.Fatalf("query: %v", q)
	}
	// The instance-ARN form of the start URL works the same way.
	if l := consoleLink("https://identitycenter.amazonaws.com/ssoins-0123456789abcdef", "1", "R", "", "eu-west-1"); !strings.HasPrefix(l, "https://identitycenter.amazonaws.com/ssoins-0123456789abcdef/#/console?") {
		t.Fatal(l)
	}
}

func TestConsoleOpensAsTheCurrentAccountAndRecordsIt(t *testing.T) {
	w := newEC2World(t, "dev", "")
	code, out, errb := run("--config", w.cfg, "console", "eks", "--print")
	if code != ExitOK || !strings.Contains(out, "account_id=222222222222") || !strings.Contains(out, "role_name=Platform-Admin") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	ev := readAudit(t, w.logPath)
	if last := ev[len(ev)-1]; last.Action != "aws-console" || last.Account != "222222222222" {
		t.Fatalf("audit: %+v", last)
	}
	// Opening a browser: the opener gets the link, nothing is printed.
	var opened []string
	old := openURL
	t.Cleanup(func() { openURL = old })
	openURL = func(name string, args ...string) error { opened = append([]string{name}, args...); return nil }
	fakeWSL(t, map[string]string{"WSL_DISTRO_NAME": "Ubuntu", "DISPLAY": ":0"})
	fakeCLI(t, "explorer.exe", "exit 0")
	fakeCLI(t, "xdg-open", "exit 0")
	code, out, errb = run("--config", w.cfg, "console")
	if code != ExitOK || out != "" || len(opened) < 2 || !strings.Contains(opened[len(opened)-1], "#/console?") || !strings.Contains(errb, "Opening the AWS console") {
		t.Fatalf("code=%d out=%q opened=%v err=%q", code, out, opened, errb)
	}
	if code, _, _ := run("--config", w.cfg, "console", "bad service!"); code != ExitUsage {
		t.Fatal("service names are validated")
	}
}
