package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"v1.3.0", "v1.2.9", true},
		{"v1.2.10", "v1.2.9", true},
		{"v1.2.9", "v1.2.9", false},
		{"v1.2.9", "v1.2.9-4-gabc123", false},
		{"v2.0.0", "v1.99.99", true},
		{"v1.0.0", "dev", false},
		{"v1.0.0", "c9eb9fa-dirty", false},
	} {
		if got := newer(c.latest, c.current); got != c.want {
			t.Errorf("newer(%q, %q) = %v", c.latest, c.current, got)
		}
	}
}

func TestVersionCheck(t *testing.T) {
	latest := `{"version": "v1.4.0", "download": "https://releases.example/nedctl/v1.4.0/", "notes": "tab completion"}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, latest) }))
	defer srv.Close()
	old := releaseClient
	t.Cleanup(func() { releaseClient = old })
	releaseClient = srv.Client
	cfg := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(cfg, []byte(`{"releaseUrl": "`+srv.URL+`/latest.json"}`), 0o600)

	oldV := Version
	t.Cleanup(func() { Version = oldV })
	Version = "v1.3.2"
	code, out, _ := run("--config", cfg, "version", "--check")
	if code != ExitOK || !strings.Contains(out, "nedctl v1.4.0 is available — tab completion") || !strings.Contains(out, "download: https://releases.example/nedctl/v1.4.0/") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	Version = "v1.4.0"
	if _, out, _ := run("--config", cfg, "version", "--check"); !strings.Contains(out, "up to date") {
		t.Fatalf("current: %q", out)
	}
	latest = `{"version": "latest"}`
	if code, _, errb := run("--config", cfg, "version", "--check"); code != ExitFailure || !strings.Contains(errb, "not vX.Y.Z") {
		t.Fatalf("bad latest.json: code=%d err=%q", code, errb)
	}
	// Plain `version` never touches the network.
	if code, out, _ := run("--config", cfg, "version"); code != ExitOK || out != "nedctl v1.4.0\n" {
		t.Fatalf("version: %q", out)
	}
	os.WriteFile(cfg, []byte(`{"releaseUrl": "http://insecure.example/latest.json"}`), 0o600)
	if code, _, _ := run("--config", cfg, "version", "--check"); code != ExitFailure {
		t.Fatal("releaseUrl must be https")
	}
}
