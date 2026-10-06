package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTimeoutDefaultAndOverride(t *testing.T) {
	if got := Default().Timeout(); got != DefaultCommandTimeout {
		t.Fatalf("default: %s", got)
	}
	cfg, _, err := Load(writeCfg(t, `{"commandTimeout": "90s"}`))
	if err != nil || cfg.Timeout() != 90*time.Second {
		t.Fatalf("override: %s err=%v", cfg.Timeout(), err)
	}
}

func TestInvalidTimeoutRejected(t *testing.T) {
	for _, v := range []string{`"soon"`, `"-5s"`, `"0s"`} {
		if _, _, err := Load(writeCfg(t, `{"commandTimeout": `+v+`}`)); err == nil || !strings.Contains(err.Error(), "commandTimeout") {
			t.Fatalf("%s: want commandTimeout error, got %v", v, err)
		}
	}
}

func TestRelativeInventoryResolvedAgainstConfigDir(t *testing.T) {
	p := writeCfg(t, `{"inventoryPath": "fleet.json"}`)
	cfg, _, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(filepath.Dir(p), "fleet.json"); cfg.InventoryPath != want {
		t.Fatalf("got %q want %q", cfg.InventoryPath, want)
	}
}

func TestMissingExplicitConfigFallsBackToDefaults(t *testing.T) {
	cfg, used, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || used != "" || len(cfg.ProdPatterns) == 0 {
		t.Fatalf("cfg=%+v used=%q err=%v", cfg, used, err)
	}
}

func TestProdEnvironments(t *testing.T) {
	if !Default().IsProdEnvironment("PROD") || Default().IsProdEnvironment("uat") {
		t.Fatal("default prod environment is prod, case-insensitive")
	}
	cfg, _, err := Load(writeCfg(t, `{"environments":["dev","uat","prod","dr"],"prodEnvironments":["prod","dr"]}`))
	if err != nil || !cfg.IsProdEnvironment("dr") {
		t.Fatalf("custom: err=%v", err)
	}
	// "production" can never match a cluster when the allow-list says "prod".
	_, _, err = Load(writeCfg(t, `{"environments":["dev","prod"],"prodEnvironments":["production"]}`))
	if err == nil || !strings.Contains(err.Error(), "no cluster could ever match") {
		t.Fatalf("want unreachable prodEnvironments error, got %v", err)
	}
}

func TestCacheTTL(t *testing.T) {
	if Default().CacheTTL() != DefaultInventoryCacheTTL {
		t.Fatal("default TTL")
	}
	if _, _, err := Load(writeCfg(t, `{"inventoryCacheTTL":"never"}`)); err == nil || !strings.Contains(err.Error(), "inventoryCacheTTL") {
		t.Fatalf("want TTL error, got %v", err)
	}
}

func TestModeAndNamePatternValidated(t *testing.T) {
	for body, want := range map[string]string{
		`{"mode": "jumpbox"}`: `mode "jumpbox"`,
		`{"discovery": {"nameEnvironmentPattern": "^(.+)-k8s-([a-z]+)-cluster$"}}`: "needs a named group",
		`{"discovery": {"nameEnvironmentPattern": "("}}`:                           "nameEnvironmentPattern",
	} {
		if _, _, err := Load(writeCfg(t, body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want error containing %q, got %v", body, want, err)
		}
	}
	cfg, _, err := Load(writeCfg(t, `{"mode": "Bastion", "discovery": {"nameEnvironmentPattern": "(?i)^.+-k8s-(?P<env>[a-z]+)-cluster$"}}`))
	if err != nil || !cfg.Bastion() {
		t.Fatalf("err=%v bastion=%v", err, cfg.Bastion())
	}
	for name, want := range map[string]string{
		"payments-k8s-QA-cluster": "qa", "payments-k8s-prod-cluster": "prod", "aks-core-prod-weu": "",
	} {
		if got := cfg.Discovery.EnvFromName(name); got != want {
			t.Fatalf("EnvFromName(%q) = %q, want %q", name, got, want)
		}
	}
}
