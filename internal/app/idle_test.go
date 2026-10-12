package app

import (
	"os"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func TestProductionShellsCloseWhenIdle(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	cfg := config.Config{}
	_, args, _, cleanup := kubeShell(cfg, profileContext{Environment: "prod", Production: true}, "payments-eks-prod")
	defer cleanup()
	rc, _ := os.ReadFile(args[1])
	if !strings.Contains(string(rc), "TMOUT=1800\nreadonly TMOUT") || strings.Index(string(rc), "TMOUT") < strings.Index(string(rc), ".bashrc") {
		t.Fatalf("production rc must set a read-only TMOUT after the user's files:\n%s", rc)
	}
	_, args, _, cleanup2 := kubeShell(cfg, profileContext{Environment: "dev"}, "lms-dev")
	defer cleanup2()
	if rc, _ := os.ReadFile(args[1]); strings.Contains(string(rc), "TMOUT") {
		t.Fatalf("non-production shells have no idle timeout:\n%s", rc)
	}
	if s := idleScript(config.Config{ProductionIdleTimeout: "45m"}, true); !strings.HasPrefix(s, "NEDCTL_TMOUT=2700\n") {
		t.Fatalf("azure: %q", s[:40])
	}
	if s := idleScript(config.Config{ProductionIdleTimeout: "0"}, true); s != sessionScript {
		t.Fatal("0 turns it off")
	}
}
