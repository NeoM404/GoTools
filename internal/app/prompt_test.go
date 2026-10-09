package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
