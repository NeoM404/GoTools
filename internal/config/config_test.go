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
