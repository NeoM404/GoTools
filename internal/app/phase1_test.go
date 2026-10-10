package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const exampleConfig = "../../configs/nedctl.example.json"

// fakeCLI puts an executable script named name first on PATH for this test.
func fakeCLI(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeAWS installs an aws whose credentials resolve to account; any other
// subcommand runs script.
func fakeAWS(t *testing.T, account, script string) {
	t.Helper()
	fakeCLI(t, "aws", `case "$*" in
*"sts get-caller-identity"*) echo '{"Account":"`+account+`","Arn":"arn:aws:sts::`+account+`:assumed-role/platform/neo"}';;
*) `+script+`;;
esac`)
}

// writeConfig writes a config pointing at the example fleet with extra JSON fields.
func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	fleet, err := filepath.Abs("../../configs/fleet.example.json")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"inventoryPath": ` + quote(fleet) + `, "targetKubeVersion": "1.30"` + extra + `}`
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

// kubeconfigWithContext points KUBECONFIG at a file whose current context is name.
func kubeconfigWithContext(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	kc := `apiVersion: v1
kind: Config
current-context: ` + name + `
contexts:
- name: ` + name + `
  context: {cluster: c, user: u}
clusters:
- name: c
  cluster: {server: "https://127.0.0.1:1"}
users:
- name: u
  user: {}
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
}

func TestKubeconfigTimesOutHungCLI(t *testing.T) {
	fakeCLI(t, "aws", "sleep 30")
	cfg := writeConfig(t, `, "commandTimeout": "200ms"`)
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitFailure || !strings.Contains(errb, "did not finish within 200ms") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestKubeconfigSurfacesCLIError(t *testing.T) {
	fakeCLI(t, "aws", `echo "An error occurred (ResourceNotFoundException): No cluster found" >&2; exit 254`)
	cfg := writeConfig(t, "")
	code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1")
	if code != ExitFailure || !strings.Contains(errb, "No cluster found") {
		t.Fatalf("CLI stderr not surfaced: code=%d err=%q", code, errb)
	}
	if !strings.Contains(errb, "nedctl doctor") {
		t.Fatalf("expected doctor hint for a CLI failure: %q", errb)
	}
}

func TestInvalidCommandTimeoutRejected(t *testing.T) {
	cfg := writeConfig(t, `, "commandTimeout": "soon"`)
	code, _, errb := run("--config", cfg, "clusters", "list")
	if code != ExitFailure || !strings.Contains(errb, "commandTimeout") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestInterruptedYields130(t *testing.T) {
	fakeCLI(t, "kubectl", "sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errb strings.Builder
	code := ExecContext(ctx, []string{"current"}, &out, &errb)
	if code != ExitInterrupted || !strings.Contains(errb.String(), "interrupted") {
		t.Fatalf("code=%d err=%q", code, errb.String())
	}
}

func TestGuardAndCurrentJSON(t *testing.T) {
	kubeconfigWithContext(t, "eks-payments-prod-euw1")
	for _, cmd := range [][]string{{"guard", "-o", "json"}, {"current", "-o", "json"}} {
		code, out, errb := run(append([]string{"--config", exampleConfig}, cmd...)...)
		if code != ExitOK {
			t.Fatalf("%v: code=%d err=%q", cmd, code, errb)
		}
		var st contextStatus
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			t.Fatalf("%v: invalid JSON %v\n%s", cmd, err, out)
		}
		if st.Context != "eks-payments-prod-euw1" || !st.Production {
			t.Fatalf("%v: got %+v", cmd, st)
		}
	}
}

func TestGuardBlockExitCodes(t *testing.T) {
	kubeconfigWithContext(t, "eks-payments-prod-euw1")
	if code, _, _ := run("--config", exampleConfig, "guard", "--block"); code != ExitProdContext {
		t.Fatalf("prod + --block: want %d got %d", ExitProdContext, code)
	}
	// JSON output must not weaken the block.
	if code, _, _ := run("--config", exampleConfig, "guard", "--block", "-o", "json"); code != ExitProdContext {
		t.Fatalf("prod + --block -o json: want %d got %d", ExitProdContext, code)
	}
	kubeconfigWithContext(t, "aks-core-dev-weu")
	if code, out, _ := run("--config", exampleConfig, "guard", "--block"); code != ExitOK || !strings.HasPrefix(out, "ok") {
		t.Fatalf("non-prod: code=%d out=%q", code, out)
	}
}

func TestContextErrorIsDiagnosable(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	empty := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(empty, []byte("apiVersion: v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", empty)
	code, _, errb := run("current")
	if code != ExitFailure || !strings.Contains(errb, "current-context is not set") {
		t.Fatalf("want kubectl's reason, got code=%d err=%q", code, errb)
	}
}

func TestDoctorJSON(t *testing.T) {
	code, out, _ := run("doctor", "-o", "json")
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rep.Tools) == 0 {
		t.Fatal("no tools reported")
	}
	if rep.Healthy != (code == ExitOK) {
		t.Fatalf("healthy=%v disagrees with exit code %d", rep.Healthy, code)
	}
	for _, tl := range rep.Tools {
		switch tl.Status {
		case "ok", "missing", "outdated":
		default:
			t.Fatalf("unexpected status %q for %s", tl.Status, tl.Name)
		}
	}
}

func TestBadOutputFormatIsUsageError(t *testing.T) {
	for _, cmd := range []string{"guard", "current", "doctor"} {
		if code, _, errb := run(cmd, "-o", "yaml"); code != ExitUsage || !strings.Contains(errb, "invalid output format") {
			t.Fatalf("%s: code=%d err=%q", cmd, code, errb)
		}
	}
}

// Cloud CLIs depend on inherited environment (AWS_PROFILE, AZURE_CONFIG_DIR,
// proxies). Losing it would silently break every SSO profile.
func TestCloudCLIInheritsEnvironment(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "env")
	fakeAWS(t, "111111111111", `printf %s "$AWS_PROFILE" > `+seen)
	t.Setenv("AWS_PROFILE", "bank-sso-readonly")
	cfg := writeConfig(t, "")
	if code, _, errb := run("--config", cfg, "kubeconfig", "eks-payments-prod-euw1"); code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	got, err := os.ReadFile(seen)
	if err != nil || string(got) != "bank-sso-readonly" {
		t.Fatalf("AWS_PROFILE not inherited: %q err=%v", got, err)
	}
}

func TestDoctorEnvironmentChecks(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(broken, []byte(`{"aws": {"startUrl": "https://x" "ssoRegion": "eu-west-1"}}`), 0o600)
	code, out, _ := run("--config", broken, "doctor", "--offline", "-o", "json")
	var rep doctorReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if code != ExitFailure || len(rep.Checks) == 0 || rep.Checks[0].Name != "config" || rep.Checks[0].Status != "fail" {
		t.Fatalf("a broken config must fail doctor: code=%d %+v", code, rep.Checks)
	}

	w := newAWSWorld(t, "")
	old := portalProbe
	t.Cleanup(func() { portalProbe = old })
	// A listener that never answers: the TLS handshake times out, as behind
	// a proxy that is not configured.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	portalProbe = func(string) (*http.Client, string) {
		return &http.Client{Timeout: 300 * time.Millisecond}, "https://" + ln.Addr().String() + "/"
	}
	code, out, _ = run("--config", w.cfg, "doctor", "-o", "json")
	rep = doctorReport{}
	json.Unmarshal([]byte(out), &rep)
	var portal doctorCheck
	plugin := false
	for _, c := range rep.Checks {
		if c.Name == "identity center portal" {
			portal = c
		}
	}
	for _, tl := range rep.Tools {
		if tl.Name == "session-manager-plugin" {
			plugin = tl.Required
		}
	}
	if code != ExitFailure || portal.Status != "fail" || !strings.Contains(portal.Detail, "HTTPS_PROXY") {
		t.Fatalf("unreachable portal: code=%d %+v", code, portal)
	}
	if !plugin {
		t.Fatal("with AWS configured, the Session Manager plugin is required")
	}
}
