package app

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
)

func setupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("NEDCTL_CONFIG", "")
	t.Setenv("SHELL", "/bin/bash")
	old := userBinDir
	t.Cleanup(func() { userBinDir = old })
	userBinDir = func() (string, error) { return filepath.Join(home, ".local", "bin"), nil }
	oldProbe := portalProbe
	t.Cleanup(func() { portalProbe = oldProbe })
	portalProbe = func(string) (*http.Client, string) { return &http.Client{Timeout: time.Second}, "https://127.0.0.1:1/" }
	return home
}

func TestSetupFromScratchIsIdempotent(t *testing.T) {
	home := setupHome(t)
	rc := filepath.Join(home, ".bashrc")
	os.WriteFile(rc, []byte("export MINE=1\neval \"$(/old/nedctl prompt init bash)\""), 0o600)
	args := []string{"setup", "--yes", "--start-url", "https://d-1234567890.awsapps.com/start", "--sso-region", "eu-west-1"}
	_, _, errb := run(args...)
	for _, want := range []string{"✔ config", "✔ install", "✔ shell", "line 2 of " + rc + " already runs `prompt init`", "nedctl aws login"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("setup output lacks %q:\n%s", want, errb)
		}
	}
	cfg, _, err := config.Load(filepath.Join(home, ".config", "nedctl", "config.json"))
	if err != nil || cfg.AWS.StartURL != "https://d-1234567890.awsapps.com/start" || cfg.AWS.SSORegion != "eu-west-1" {
		t.Fatalf("config: %+v %v", cfg.AWS, err)
	}
	if fi, err := os.Stat(filepath.Join(home, ".local", "bin", "nedctl")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary: %v %v", fi, err)
	}
	first, _ := os.ReadFile(rc)
	if !strings.HasPrefix(string(first), "export MINE=1\neval") || !strings.Contains(string(first), `export PATH="$HOME/.local/bin:$PATH"`) ||
		!strings.Contains(string(first), `eval "$(nedctl prompt init bash)"`) {
		t.Fatalf("~/.bashrc:\n%s", first)
	}
	if fi, _ := os.Stat(rc); fi.Mode().Perm() != 0o600 {
		t.Fatalf("~/.bashrc mode changed to %v", fi.Mode().Perm())
	}
	// Running again changes nothing: one block, config kept.
	run("setup", "--yes")
	second, _ := os.ReadFile(rc)
	if string(second) != string(first) || strings.Count(string(second), rcBegin) != 1 {
		t.Fatalf("second run changed ~/.bashrc:\n%s", second)
	}
}

func TestSetupNeedsATerminalOrYes(t *testing.T) {
	setupHome(t)
	if code, _, _ := run("setup"); code != ExitUsage {
		t.Fatalf("code=%d", code)
	}
	// Answering no leaves ~/.bashrc and ~/.local/bin alone.
	home := os.Getenv("HOME")
	answer(t, "\nn\nn\n") // start URL (blank: skip), install? no, shell? no
	_, _, errb := run("setup")
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); err == nil || !strings.Contains(errb, "– config") || !strings.Contains(errb, "– install") || !strings.Contains(errb, "– shell") {
		t.Fatalf("declined steps must change nothing:\n%s", errb)
	}
}

func TestBuiltInOrganisationDefaults(t *testing.T) {
	setupHome(t)
	old := config.OrgDefaults
	t.Cleanup(func() { config.OrgDefaults = old })
	config.OrgDefaults = base64.StdEncoding.EncodeToString([]byte(`{"aws": {"startUrl": "https://d-1234567890.awsapps.com/start", "ssoRegion": "eu-west-1"}, "environments": ["dev", "qa", "prod"], "prodEnvironments": ["qa", "prod"]}`))
	cfg, path, err := config.Load("")
	if err != nil || path != "" || !cfg.AWS.Configured() || len(cfg.Environments) != 3 {
		t.Fatalf("no file: built-in defaults apply: %+v %q %v", cfg.AWS, path, err)
	}
	_, _, errb := run("setup", "--yes", "--no-install", "--no-shell")
	if !strings.Contains(errb, "built-in settings for your organisation") {
		t.Fatalf("setup with built-in defaults:\n%s", errb)
	}
	// A user's file still applies on top.
	own := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(own, []byte(`{"aws": {"startUrl": "https://d-0000000000.awsapps.com/start", "ssoRegion": "af-south-1"}}`), 0o600)
	if cfg, _, err := config.Load(own); err != nil || cfg.AWS.SSORegion != "af-south-1" || len(cfg.Environments) != 3 {
		t.Fatalf("file over defaults: %+v %v", cfg, err)
	}
	// Broken built-in defaults are ignored and reported.
	config.OrgDefaults = "not base64!"
	if config.OrgDefaultsErr() == nil || config.Default().AWS.Configured() {
		t.Fatal("broken built-in defaults must be ignored and reported")
	}
}
