package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/config"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Exec(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpAndVersion(t *testing.T) {
	if code, out, _ := run(); code != 0 || !strings.Contains(out, "nedctl") {
		t.Fatalf("bare invocation: code=%d out=%q", code, out)
	}
	if code, out, _ := run("version"); code != 0 || !strings.Contains(out, "nedctl") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, errb := run("frobnicate"); code != 2 || !strings.Contains(errb, "unknown command") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestClustersListWithExampleFleet(t *testing.T) {
	// Uses the checked-in example inventory via an explicit config.
	code, out, errb := run("--config", "../../configs/nedctl.example.json", "clusters", "list", "--cloud", "aws")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "eks-payments-prod-euw1") {
		t.Fatalf("expected aws cluster in output: %q", out)
	}
	if strings.Contains(out, "aks-core-prod-weu") {
		t.Fatalf("azure cluster should be filtered out: %q", out)
	}
}

func TestFleetVersionsFailOnStale(t *testing.T) {
	// The example fleet has dev at 1.27 vs target 1.30 => STALE => exit 1.
	code, out, _ := run("--config", "../../configs/nedctl.example.json", "fleet", "versions", "--fail-on-stale")
	if code != 1 {
		t.Fatalf("expected exit 1 for stale fleet, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "STALE") {
		t.Fatalf("expected STALE in report: %q", out)
	}
}

func TestKubeconfigDryRunFlagAfterArg(t *testing.T) {
	// Flag AFTER the positional (how people actually type it) must work.
	code, out, errb := run("--config", "../../configs/nedctl.example.json",
		"kubeconfig", "aks-core-prod-weu", "--dry-run")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "az aks get-credentials") || !strings.Contains(out, "aks-core-prod-weu") {
		t.Fatalf("unexpected dry-run output: %q", out)
	}
}

func TestKubeconfigDryRunFlagBeforeArg(t *testing.T) {
	code, out, _ := run("--config", "../../configs/nedctl.example.json",
		"kubeconfig", "--dry-run", "eks-payments-prod-euw1")
	if code != 0 || !strings.Contains(out, "aws eks update-kubeconfig") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestClustersListJSON(t *testing.T) {
	code, out, errb := run("--config", "../../configs/nedctl.example.json",
		"clusters", "list", "--cloud", "azure", "-o", "json")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 azure clusters, got %d", len(got))
	}
}

func TestClustersGetJSON(t *testing.T) {
	code, out, _ := run("--config", "../../configs/nedctl.example.json",
		"clusters", "get", "eks-payments-prod-euw1", "-o", "json")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	var c map[string]any
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if c["name"] != "eks-payments-prod-euw1" {
		t.Fatalf("got name=%v", c["name"])
	}
}

func TestInvalidOutputFormat(t *testing.T) {
	code, _, errb := run("--config", "../../configs/nedctl.example.json",
		"clusters", "list", "-o", "yaml")
	if code != 2 || !strings.Contains(errb, "invalid output format") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestInitWritesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	code, out, errb := run("init", "--path", path)
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, path) {
		t.Fatalf("expected path in output: %q", out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("written config is not valid JSON: %v", err)
	}
	// The starter config must also pass nedctl's own validation.
	if _, _, err := config.Load(path); err != nil {
		t.Fatalf("starter config rejected by config.Load: %v", err)
	}
	// Second run without --force must refuse.
	if code, _, _ := run("init", "--path", path); code != 1 {
		t.Fatalf("expected refuse-overwrite exit 1, got %d", code)
	}
	// With --force it overwrites.
	if code, _, _ := run("init", "--path", path, "--force"); code != 0 {
		t.Fatalf("expected --force to succeed, got %d", code)
	}
}

func TestExtractConfig(t *testing.T) {
	cfg, rest := extractConfig([]string{"--config", "x.json", "clusters", "list"})
	if cfg != "x.json" || len(rest) != 2 || rest[0] != "clusters" {
		t.Fatalf("got cfg=%q rest=%v", cfg, rest)
	}
	cfg, rest = extractConfig([]string{"--config=y.json", "guard"})
	if cfg != "y.json" || rest[0] != "guard" {
		t.Fatalf("got cfg=%q rest=%v", cfg, rest)
	}
	cfg, rest = extractConfig([]string{"doctor"})
	if cfg != "" || rest[0] != "doctor" {
		t.Fatalf("got cfg=%q rest=%v", cfg, rest)
	}
}
