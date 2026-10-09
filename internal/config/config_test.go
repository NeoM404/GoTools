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

// The bank's real account names, classified with no configuration at all.
func TestClassifyInfersSquadAndEnvironmentFromBankNames(t *testing.T) {
	var a AWS
	envs := []string{"dev", "ete", "qa", "prod"}
	for name, want := range map[string][2]string{
		"[NONPROD] aws-mov-lms-dev": {"mov-lms", "dev"},
		"[NONPROD] aws-gt-elp-ete":  {"gt-elp", "ete"},
		"[PROD] aws-gt-elp-qa":      {"gt-elp", "qa"},
		"aws-cib-bancs-prod":        {"cib-bancs", "prod"},
		"aws-mov-Lms-qa":            {"mov-lms", "qa"},
		"aws-gt-nvanatest-dev":      {"gt-nvanatest", "dev"},
		"shared-services":           {"", ""},
		"aws-rsss-actimize-qa":      {"rsss-actimize", "qa"},
		"payments_prod":             {"payments", "prod"},
		"aws-ret-clm-dev-sandbox-x": {"ret-clm", "dev"},
	} {
		squad, env := a.Classify("000000000000", name, envs)
		if squad != want[0] || env != want[1] {
			t.Errorf("%q: got squad=%q env=%q, want %q %q", name, squad, env, want[0], want[1])
		}
	}
	// Explicit metadata and a matching pattern still win; a pattern that
	// does not match falls back to the name.
	a = AWS{Accounts: []AWSAccount{{ID: "111111111111", Squad: "pay", Environment: "PROD"}},
		AccountNamePattern: `^team-(?P<squad>\w+)-(?P<env>\w+)$`}
	if s, e := a.Classify("111111111111", "anything", envs); s != "pay" || e != "prod" {
		t.Fatalf("explicit: %q %q", s, e)
	}
	if s, e := a.Classify("2", "team-x-uat", envs); s != "x" || e != "uat" {
		t.Fatalf("pattern: %q %q", s, e)
	}
	if s, e := a.Classify("2", "aws-mov-lms-dev", envs); s != "mov-lms" || e != "dev" {
		t.Fatalf("fallback: %q %q", s, e)
	}
}

// The first real configuration error: startUrl and ssoRegion placed inside
// discovery.aws, which used to surface as "account must be a 12 digit ID".
func TestMisplacedSettingIsExplained(t *testing.T) {
	_, _, err := Load(writeCfg(t, `{"discovery": {"aws": [{"startUrl": "https://d-1.awsapps.com/start", "ssoRegion": "eu-west-1"}]}}`))
	if err == nil || !strings.Contains(err.Error(), `unknown setting "startUrl" here — it belongs in the "aws" block`) {
		t.Fatalf("got %v", err)
	}
	_, _, err = Load(writeCfg(t, `{"aws": {"startUrl": "https://d-1.awsapps.com/start", "ssoRegion": "eu-west-1", "regoin": "x"}}`))
	if err == nil || !strings.Contains(err.Error(), `unknown setting "regoin" — check its spelling`) {
		t.Fatalf("got %v", err)
	}
}

func TestShippedConfigsAreStrictlyValid(t *testing.T) {
	for _, p := range []string{"../../configs/nedctl.example.json", "../../configs/nedctl.bastion.example.json",
		"../../configs/nedctl.aws.example.json", "../../inventory/nedctl.json"} {
		if _, _, err := Load(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
