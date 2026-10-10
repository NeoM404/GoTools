package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/awssso"
)

func TestPromptShowsKubeAndAWSInEnvironmentColour(t *testing.T) {
	w := newEC2World(t, "dev", "")
	writeBastionKubeconfig(t, "payments-k8s-prod-cluster", aksContext("payments-k8s-prod-cluster", "rg-payments-prod"))
	cfgBody, _ := os.ReadFile(w.cfg)
	fleet, _ := filepath.Abs("../../configs/fleet.bastion.example.json")
	os.WriteFile(w.cfg, []byte(strings.Replace(string(cfgBody), `"audit"`, `"inventoryPath": `+quote(fleet)+`, "audit"`, 1)), 0o600)

	code, out, _ := run("--config", w.cfg, "prompt")
	if code != ExitOK || out != "k8s:payments-k8s-prod-cluster[PROD] aws:payments▲[dev]" {
		t.Fatalf("plain: code=%d out=%q", code, out)
	}
	_, out, _ = run("--config", w.cfg, "prompt", "--shell", "bash")
	if !strings.Contains(out, `\[`+"\x1b[1;38;2;239;68;68m"+`\]k8s:payments-k8s-prod-cluster[PROD]`) ||
		!strings.Contains(out, "\x1b[22;38;2;34;197;94m"+`\]aws:payments▲[dev]`) {
		t.Fatalf("bash: %q", out)
	}
	_, out, _ = run("--config", w.cfg, "prompt", "--shell", "zsh", "--no-aws")
	if !strings.HasPrefix(out, "%{\x1b[1;38;2;239;68;68m%}k8s:") || strings.Contains(out, "aws:") {
		t.Fatalf("zsh: %q", out)
	}
}

func TestPromptNeverFails(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	bad := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(bad, []byte(`{not json`), 0o600)
	for _, args := range [][]string{{"prompt"}, {"--config", bad, "prompt"}, {"prompt", "--bogus"}} {
		if code, out, errb := run(args...); code != ExitOK || out != "" || errb != "" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errb)
		}
	}
}

func writeSignIn(t *testing.T, home string, expires time.Time) {
	t.Helper()
	dir := filepath.Join(home, ".aws", "sso", "cache")
	os.MkdirAll(dir, 0o700)
	body := `{"accessToken":"tok-secret","expiresAt":"` + expires.UTC().Format(time.RFC3339) + `"}`
	if err := os.WriteFile(awssso.TokenPath(dir, "nedctl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPromptAndCommandsShowSignInExpiry(t *testing.T) {
	w := newEC2World(t, "dev", "")
	writeSignIn(t, w.home, time.Now().Add(30*time.Minute))
	_, out, _ := run("--config", w.cfg, "prompt", "--no-kube")
	if !strings.Contains(out, "(29m)") && !strings.Contains(out, "(30m)") {
		t.Fatalf("prompt must show time left under an hour: %q", out)
	}
	writeSignIn(t, w.home, time.Now().Add(5*time.Hour))
	if _, out, _ = run("--config", w.cfg, "prompt", "--no-kube"); strings.Contains(out, "(") {
		t.Fatalf("plenty of time left: no suffix expected: %q", out)
	}
	writeSignIn(t, w.home, time.Now().Add(-time.Minute))
	if _, out, _ = run("--config", w.cfg, "prompt", "--no-kube"); !strings.Contains(out, "(expired)") {
		t.Fatalf("expired: %q", out)
	}
	_, _, errb := run("--config", w.cfg, "shell", "devops")
	if !strings.Contains(errb, "sign-in has expired — run `nedctl aws login`") {
		t.Fatalf("shell must warn: %q", errb)
	}
	writeSignIn(t, w.home, time.Now().Add(10*time.Minute))
	_, _, errb = run("--config", w.cfg, "shell", "devops")
	if !strings.Contains(errb, "sign-in expires in 10m") && !strings.Contains(errb, "sign-in expires in 9m") {
		t.Fatalf("shell must warn before expiry: %q", errb)
	}
}

func TestNearestXterm256(t *testing.T) {
	for hex, want := range map[string]int{"#ef4444": 203, "#22c55e": 41, "#ffffff": 231, "#000000": 16, "#808080": 244} {
		if got, ok := nearestXterm256(hex); !ok || got != want {
			t.Errorf("%s: got %d, want %d", hex, got, want)
		}
	}
	if _, ok := nearestXterm256("red"); ok {
		t.Error("an invalid colour has no palette entry")
	}
}

func TestPromptColoursTheWindowsTerminalTab(t *testing.T) {
	w := newEC2World(t, "dev", "")
	writeBastionKubeconfig(t, "payments-k8s-prod-cluster", aksContext("payments-k8s-prod-cluster", "rg-payments-prod"))
	t.Setenv("WT_SESSION", "")
	if _, out, _ := run("--config", w.cfg, "prompt", "--shell", "bash", "--tab"); strings.Contains(out, ",|") {
		t.Fatalf("outside Windows Terminal the tab is left alone: %q", out)
	}
	t.Setenv("WT_SESSION", "x")
	// The AWS profile's environment (dev, green) sets the tab colour, marked
	// as taking no columns.
	if _, out, _ := run("--config", w.cfg, "prompt", "--shell", "bash", "--tab"); !strings.HasSuffix(out, `\[`+"\x1b[2;15;41,|"+`\]`) {
		t.Fatalf("bash --tab: %q", out)
	}
	if _, out, _ := run("--config", w.cfg, "prompt", "--shell", "zsh", "--tab", "--no-aws"); !strings.HasSuffix(out, "%{\x1b[2;15;203,|%}") {
		t.Fatalf("zsh --tab, kube only (prod, red): %q", out)
	}
	if _, out, _ := run("--config", w.cfg, "prompt", "--tab"); strings.Contains(out, "\x1b") {
		t.Fatalf("plain never carries escapes: %q", out)
	}
}

func TestPromptInit(t *testing.T) {
	code, out, _ := run("prompt", "init", "bash")
	self, _ := os.Executable()
	if code != ExitOK || !strings.Contains(out, "PROMPT_COMMAND=\"__nedctl_prompt") || !strings.Contains(out, shellQuote(self)+" prompt --shell bash --tab") {
		t.Fatalf("bash: code=%d\n%s", code, out)
	}
	if !strings.Contains(out, "nedctl() {") || !strings.Contains(out, "NEDCTL_SHELL_HOOK=1 "+shellQuote(self)) || strings.Contains(out, "eval") {
		t.Fatalf("bash: the login shell function is missing or uses eval:\n%s", out)
	}
	if code, out, _ := run("prompt", "init", "zsh"); code != ExitOK || !strings.Contains(out, "add-zsh-hook precmd __nedctl_prompt") || !strings.Contains(out, "nedctl() {") {
		t.Fatalf("zsh: code=%d\n%s", code, out)
	}
	if code, _, _ := run("prompt", "init", "fish"); code != ExitUsage {
		t.Fatalf("unsupported shell: code=%d", code)
	}
}

func TestPromptInsideKubeShellIsShort(t *testing.T) {
	w := newEC2World(t, "dev", "")
	writeBastionKubeconfig(t, "payments-k8s-prod-cluster", aksContext("payments-k8s-prod-cluster", "rg-payments-prod"))
	t.Setenv("NEDCTL_KUBECONFIG", os.Getenv("KUBECONFIG"))
	t.Setenv("WT_SESSION", "x")
	// The kube shell's ⎈ prefix names cluster and environment; the prompt
	// adds only the elevated-role marker — and still colours the tab.
	_, out, _ := run("--config", w.cfg, "prompt", "--shell", "bash", "--tab")
	if !strings.HasPrefix(out, "▲") || strings.Contains(out, "k8s:") || strings.Contains(out, "aws:") || !strings.Contains(out, ",|") {
		t.Fatalf("inside nedctl kube: %q", out)
	}
	// Outside it (KUBECONFIG changed), the full segments return.
	t.Setenv("NEDCTL_KUBECONFIG", "/elsewhere")
	if _, out, _ := run("--config", w.cfg, "prompt"); !strings.Contains(out, "k8s:") || !strings.Contains(out, "aws:") {
		t.Fatalf("outside: %q", out)
	}
}
