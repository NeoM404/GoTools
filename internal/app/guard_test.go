package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// liveProdConfig: the example fleet plus a prod cluster whose name does not
// contain "prod" — the case name patterns alone miss.
func liveProdConfig(t *testing.T, extra string) string {
	t.Helper()
	raw, err := os.ReadFile("../../configs/fleet.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var fleet map[string][]map[string]string
	if err := json.Unmarshal(raw, &fleet); err != nil {
		t.Fatal(err)
	}
	fleet["clusters"] = append(fleet["clusters"], map[string]string{
		"name": "eks-core-live-euw1", "cloud": "aws", "environment": "prod", "region": "eu-west-1",
		"version": "1.30", "account": "555555555555",
	})
	dir := t.TempDir()
	b, _ := json.Marshal(fleet)
	if err := os.WriteFile(filepath.Join(dir, "fleet.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "cfg.json")
	body := `{"inventoryPath":"fleet.json","prodPatterns":["(?i)prod"],"environments":["dev","sit","uat","prod"]` + extra + `}`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const liveARN = "arn:aws:eks:eu-west-1:555555555555:cluster/eks-core-live-euw1"

func TestGuardBlocksProdClusterWithoutProdInName(t *testing.T) {
	kubeconfigWithContext(t, liveARN)
	cfg := liveProdConfig(t, "")
	code, out, _ := run("--config", cfg, "guard", "--block")
	if code != ExitProdContext || !strings.Contains(out, "inventory: eks-core-live-euw1 is in environment prod") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, out, _ = run("--config", cfg, "guard", "-o", "json")
	var st contextStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatal(err)
	}
	if code != ExitOK || !st.Production || st.Cluster != "eks-core-live-euw1" || st.Environment != "prod" || len(st.Reasons) != 1 {
		t.Fatalf("code=%d status=%+v", code, st)
	}
}

func TestGuardFallsBackToPatternsWhenInventoryBroken(t *testing.T) {
	kubeconfigWithContext(t, "eks-payments-prod-euw1")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"inventoryPath":"missing.json","prodPatterns":["(?i)prod"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := run("--config", cfg, "guard", "--block")
	if code != ExitProdContext || !strings.Contains(out, "name matches prod pattern") {
		t.Fatalf("guard must still work on patterns: code=%d out=%q", code, out)
	}
	if !strings.Contains(errb, "inventory unavailable, classifying by name patterns only") {
		t.Fatalf("degradation must be announced: %q", errb)
	}
}

func TestCurrentShowsResolvedCluster(t *testing.T) {
	kubeconfigWithContext(t, "222222222222.eks-payments-uat-euw1")
	code, out, _ := run("--config", liveProdConfig(t, ""), "current")
	if code != ExitOK || !strings.Contains(out, "status:  non-prod") || !strings.Contains(out, "cluster: eks-payments-uat-euw1 (uat)") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestLoginWarnsForCustomProdEnvironment(t *testing.T) {
	fakeAWS(t, "222222222222", "exit 0")
	fakeCLI(t, "kubectl", "exit 1") // drift probe: best-effort, ignored
	cfg := liveProdConfig(t, `, "prodEnvironments": ["prod", "uat"]`)
	code, out, errb := run("--config", cfg, "login", "eks-payments-uat-euw1")
	if code != ExitOK || !strings.Contains(out, "is a PRODUCTION cluster") {
		t.Fatalf("uat configured as prod must warn: code=%d out=%q err=%q", code, out, errb)
	}
}
