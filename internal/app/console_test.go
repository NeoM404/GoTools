package app

import (
	"context"
	"net/url"
	"path/filepath"
	"time"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"os"
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
	// The portal: the awsapps.com start URL itself; for an instance signing
	// in through identitycenter.amazonaws.com, its app.aws portal (the
	// identitycenter.amazonaws.com address is not a web page); or portalUrl.
	for _, c := range []struct {
		a    config.AWS
		want string
	}{
		{config.AWS{StartURL: "https://d-1234567890.awsapps.com/start", SSORegion: "eu-west-1"}, "https://d-1234567890.awsapps.com/start"},
		{config.AWS{StartURL: "https://identitycenter.amazonaws.com/ssoins-68042455842cfa84", SSORegion: "eu-west-1"}, "https://ssoins-68042455842cfa84.portal.eu-west-1.app.aws"},
		{config.AWS{StartURL: "https://identitycenter.amazonaws.com/ssoins-68042455842cfa84", SSORegion: "eu-west-1", PortalURL: "https://bank.awsapps.com/start"}, "https://bank.awsapps.com/start"},
	} {
		if got := portalURL(c.a); got != c.want {
			t.Errorf("portalURL(%s) = %s, want %s", c.a.StartURL, got, c.want)
		}
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
	// No Windows programs on PATH (appendWindowsPath=false): the opener is
	// found at its fixed location on the Windows drive.
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "Windows", "System32"), 0o755)
	os.WriteFile(filepath.Join(root, "Windows", "System32", "rundll32.exe"), []byte("#!/bin/sh\n"), 0o755)
	oldRoot := windowsRoot
	t.Cleanup(func() { windowsRoot = oldRoot })
	windowsRoot = root
	t.Setenv("PATH", "/usr/bin:/bin")
	oldOS := goos
	t.Cleanup(func() { goos = oldOS })
	goos = "linux"
	code, out, errb = run("--config", w.cfg, "console")
	if code != ExitOK || out != "" || len(opened) < 3 || !strings.HasSuffix(opened[0], "/Windows/System32/rundll32.exe") ||
		opened[1] != "url.dll,FileProtocolHandler" || !strings.Contains(opened[2], "#/console?") || !strings.Contains(errb, "Opening the AWS console") {
		t.Fatalf("code=%d out=%q opened=%v err=%q", code, out, opened, errb)
	}
	// Nowhere to open it: say so, and print the link.
	os.Remove(filepath.Join(root, "Windows", "System32", "rundll32.exe"))
	code, out, errb = run("--config", w.cfg, "console")
	if code != ExitOK || !strings.Contains(out, "#/console?") || !strings.Contains(errb, "no browser could be opened") {
		t.Fatalf("fallback: code=%d out=%q err=%q", code, out, errb)
	}
	if code, _, _ := run("--config", w.cfg, "console", "bad service!"); code != ExitUsage {
		t.Fatal("service names are validated")
	}
}

func TestConfirmProduction(t *testing.T) {
	w := newEC2World(t, "prod", "")
	body, _ := os.ReadFile(w.cfg)
	os.WriteFile(w.cfg, []byte(strings.Replace(string(body), "{", `{"confirmProduction": true, `, 1)), 0o600)

	if code, _, errb := run("--config", w.cfg, "console", "--print"); code != ExitFailure || !strings.Contains(errb, "pass --yes") {
		t.Fatalf("no terminal: code=%d %q", code, errb)
	}
	if code, _, _ := run("--config", w.cfg, "console", "--print", "--yes"); code != ExitOK {
		t.Fatalf("--yes: code=%d", code)
	}
	answer(t, "nope\n")
	if code, _, errb := run("--config", w.cfg, "console", "--print"); code != ExitFailure || !strings.Contains(errb, "not confirmed") {
		t.Fatalf("wrong word: code=%d %q", code, errb)
	}
	answer(t, "PROD\n")
	if code, _, errb := run("--config", w.cfg, "console", "--print"); code != ExitOK || !strings.Contains(errb, "is PRODUCTION") {
		t.Fatalf("typed: code=%d %q", code, errb)
	}
	// Off by default; non-production never asks.
	dev := newEC2World(t, "dev", "")
	body, _ = os.ReadFile(dev.cfg)
	os.WriteFile(dev.cfg, []byte(strings.Replace(string(body), "{", `{"confirmProduction": true, `, 1)), 0o600)
	if code, _, _ := run("--config", dev.cfg, "console", "--print"); code != ExitOK {
		t.Fatal("dev must not ask")
	}
}

func TestOpenURLCommand(t *testing.T) {
	var opened []string
	old, oldOS := openURL, goos
	t.Cleanup(func() { openURL, goos = old, oldOS })
	openURL = func(name string, args ...string) error { opened = append([]string{name}, args...); return nil }
	goos = "darwin"
	fakeCLI(t, "open", "exit 0")
	if code, _, _ := run("__open-url", "https://device.sso.eu-west-1.amazonaws.com/?user_code=ABCD-EFGH"); code != ExitOK || len(opened) != 2 || opened[1] != "https://device.sso.eu-west-1.amazonaws.com/?user_code=ABCD-EFGH" {
		t.Fatalf("code=%d opened=%v", code, opened)
	}
	for _, bad := range []string{"http://x", "file:///etc/passwd", "https://a b"} {
		if code, _, _ := run("__open-url", bad); code != ExitUsage {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestSignInHandsTheBrowserToNedctlInWSL(t *testing.T) {
	w := newAWSWorld(t, "")
	cfg, _, _ := config.Load(w.cfg)
	seen := filepath.Join(w.home, "browser-env")
	cache := filepath.Join(w.home, ".aws", "sso", "cache")
	expires := time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339)
	fakeCLI(t, "aws", `printf '%s' "$BROWSER" > `+sq(seen)+`
mkdir -p `+sq(cache)+` && printf '%s' '{"accessToken":"t","expiresAt":"`+expires+`","region":"eu-west-1"}' > `+sq(awssso.TokenPath(cache, "nedctl")))
	fakeWSL(t, map[string]string{"WSL_DISTRO_NAME": "Ubuntu"})
	var errb strings.Builder
	if _, _, code := ensureSignIn(context.Background(), cfg, true, true, &errb); code != ExitOK {
		t.Fatalf("code=%d %s", code, errb.String())
	}
	got, _ := os.ReadFile(seen)
	if !strings.HasSuffix(string(got), "' __open-url %s") || !strings.Contains(errb.String(), "your browser opens") {
		t.Fatalf("BROWSER=%q\n%s", got, errb.String())
	}
}
