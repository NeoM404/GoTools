package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func fakeWSL(t *testing.T, env map[string]string) {
	t.Helper()
	old := lookupEnv
	t.Cleanup(func() { lookupEnv = old })
	lookupEnv = func(k string) string { return env[k] }
}

func TestWSLPath(t *testing.T) {
	fakeWSL(t, map[string]string{"WSL_DISTRO_NAME": "Ubuntu"})
	for in, want := range map[string]string{
		`C:\Program Files\SSM\AWS-EC2-SSMshell.exe`: "/mnt/c/Program Files/SSM/AWS-EC2-SSMshell.exe",
		`D:/tools/wt.exe`:   "/mnt/d/tools/wt.exe",
		"/usr/local/bin/sm": "/usr/local/bin/sm",
		"sm":                "sm",
	} {
		if got := wslPath(in); got != want {
			t.Errorf("wslPath(%q) = %q, want %q", in, got, want)
		}
	}
	fakeWSL(t, map[string]string{})
	if got := wslPath(`C:\x.exe`); got != `C:\x.exe` {
		t.Errorf("outside WSL a Windows path is left alone: %q", got)
	}
}

func TestFindWindowsTerminal(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no wt.exe on PATH
	root := t.TempDir()
	for _, u := range []string{"aaa", "neo"} {
		dir := filepath.Join(root, "Users", u, "WindowsApps")
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "wt.exe"), []byte("#!/bin/sh\n"), 0o755)
	}
	old := windowsAppsGlob
	t.Cleanup(func() { windowsAppsGlob = old })
	windowsAppsGlob = filepath.Join(root, "Users", "*", "WindowsApps", "wt.exe")

	fakeWSL(t, map[string]string{})
	if _, err := findWindowsTerminal(config.Config{}); err == nil || !strings.Contains(err.Error(), `"windowsTerminal"`) {
		t.Fatalf("outside WSL with nothing on PATH, the error must name the setting: %v", err)
	}
	fakeWSL(t, map[string]string{"WSL_DISTRO_NAME": "Ubuntu", "USER": "neo"})
	// Two Windows users have Windows Terminal: the one named like the Linux
	// user is preferred.
	if got, err := findWindowsTerminal(config.Config{}); err != nil || got != filepath.Join(root, "Users", "neo", "WindowsApps", "wt.exe") {
		t.Fatalf("WindowsApps fallback: %q %v", got, err)
	}
	set := filepath.Join(root, "Users", "aaa", "WindowsApps", "wt.exe")
	if got, err := findWindowsTerminal(config.Config{WindowsTerminal: set}); err != nil || got != set {
		t.Fatalf("the setting wins: %q %v", got, err)
	}
	if _, err := findWindowsTerminal(config.Config{WindowsTerminal: filepath.Join(root, "missing.exe")}); err == nil {
		t.Fatal("a windowsTerminal that does not exist must be reported")
	}
}

func TestLegacyWindowsToolGetsCredentialsThroughWSLENV(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "AWS-EC2-SSMshell.exe")
	w := newEC2World(t, "dev", `, "legacyTool": "`+tool+`"`)
	seen := filepath.Join(w.home, "seen")
	os.WriteFile(tool, []byte("#!/bin/sh\nprintf '%s|%s' \"$AWS_ACCESS_KEY_ID\" \"$WSLENV\" > "+sq(seen)+"\n"), 0o755)
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	t.Setenv("WSLENV", "WT_SESSION:WT_PROFILE_ID/u")
	code, _, errb := run("--config", w.cfg, "shell", "--via", "legacy")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	got, _ := os.ReadFile(seen)
	key, wslenv, _ := strings.Cut(string(got), "|")
	if key != "ASIAEXAMPLE" || !strings.HasPrefix(wslenv, "WT_SESSION:WT_PROFILE_ID/u:") ||
		!strings.Contains(wslenv, "AWS_ACCESS_KEY_ID") || !strings.Contains(wslenv, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("a Windows tool must get the keys via WSLENV, keeping what was there: %q", got)
	}
}

func TestLegacyToolMissingNamesTheSetting(t *testing.T) {
	w := newEC2World(t, "dev", "")
	t.Setenv("PATH", filepath.Dir(mustLook(t, "aws"))) // aws only, no sm
	code, _, errb := run("--config", w.cfg, "shell", "--via", "legacy")
	if code != ExitFailure || !strings.Contains(errb, "aws.legacyTool") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func mustLook(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
