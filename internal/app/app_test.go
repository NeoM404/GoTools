package app

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Exec(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpAndVersion(t *testing.T) {
	if code, out, _ := run(); code != 0 || !strings.Contains(out, "bankctl") {
		t.Fatalf("bare invocation: code=%d out=%q", code, out)
	}
	if code, out, _ := run("version"); code != 0 || !strings.Contains(out, "bankctl") {
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
	code, out, errb := run("--config", "../../configs/bankctl.example.json", "clusters", "list", "--cloud", "aws")
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
	// The example fleet has sandbox at 1.27 vs target 1.30 => STALE => exit 1.
	code, out, _ := run("--config", "../../configs/bankctl.example.json", "fleet", "versions", "--fail-on-stale")
	if code != 1 {
		t.Fatalf("expected exit 1 for stale fleet, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "STALE") {
		t.Fatalf("expected STALE in report: %q", out)
	}
}

func TestKubeconfigDryRunFlagAfterArg(t *testing.T) {
	// Flag AFTER the positional (how people actually type it) must work.
	code, out, errb := run("--config", "../../configs/bankctl.example.json",
		"kubeconfig", "aks-core-prod-weu", "--dry-run")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(out, "az aks get-credentials") || !strings.Contains(out, "aks-core-prod-weu") {
		t.Fatalf("unexpected dry-run output: %q", out)
	}
}

func TestKubeconfigDryRunFlagBeforeArg(t *testing.T) {
	code, out, _ := run("--config", "../../configs/bankctl.example.json",
		"kubeconfig", "--dry-run", "eks-payments-prod-euw1")
	if code != 0 || !strings.Contains(out, "aws eks update-kubeconfig") {
		t.Fatalf("code=%d out=%q", code, out)
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
