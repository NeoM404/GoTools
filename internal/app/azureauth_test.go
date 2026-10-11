package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bastionKubeconfigView = `{"kind":"Config","apiVersion":"v1",
 "users":[
  {"name":"clusterUser_rg_acm","user":{"client-certificate-data":"DATA+OMITTED","client-key-data":"DATA+OMITTED","token":"REDACTED"}},
  {"name":"entra","user":{"exec":{"command":"/usr/local/bin/kubelogin","args":["get-token"]}}}],
 "contexts":[
  {"name":"acm-k8s-qa-cluster","context":{"cluster":"acm","user":"clusterUser_rg_acm"}},
  {"name":"pay-k8s-qa-cluster","context":{"cluster":"pay","user":"entra"}}]}`

func TestAzureAuthShowsLocalAccountsAndEntra(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"bastions":{"qa":"aks-qa"}}`)
	view := filepath.Join(t.TempDir(), "view.json")
	os.WriteFile(view, []byte(bastionKubeconfigView), 0o600)
	fakeCLI(t, "kubectl", `case "$*" in "config view -o json") cat `+sq(view)+`;; *) exit 1;; esac`)
	code, out, errb := run("--config", w.cfg, "azure", "auth")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range [][]string{{"qa", "acm-k8s-qa-cluster", "local-account", "clusterUser_rg_acm"}, {"qa", "pay-k8s-qa-cluster", "entra-id", "entra"}} {
		if !regexpLine(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "2 of 4 cluster(s) are reached with a shared local account") || !strings.Contains(out, "--disable-local-accounts") {
		t.Fatalf("summary:\n%s", out)
	}
	if code, _, _ := run("--config", w.cfg, "azure", "auth", "--fail-on-local"); code != ExitFailure {
		t.Fatal("--fail-on-local did not fail")
	}
	_, out, _ = run("--config", w.cfg, "azure", "auth", "-o", "json")
	if !strings.Contains(out, `"auth": "local-account"`) || strings.Contains(out, "OMITTED") {
		t.Fatalf("json: %s", out)
	}
}
