package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/awssso"
	"nedctl/internal/config"
)

// awsWorld is a simulated engineer's machine and Identity Center: an
// isolated HOME and AWS config, a fake portal, and a fake aws CLI whose
// `sso login` writes the token cache like the real one and whose
// `sts get-caller-identity --profile P` answers with the account P names in
// the AWS config — so a wrong profile really acts in the wrong account.
type awsWorld struct {
	home, awsConfig, logPath, cfg string
	assignments                   map[string][]string // account id -> roles
	names                         map[string]string   // account id -> name
	loginMarker                   string
}

func newAWSWorld(t *testing.T, extra string) *awsWorld {
	t.Helper()
	w := &awsWorld{home: t.TempDir()}
	w.awsConfig = filepath.Join(w.home, ".aws", "config")
	w.logPath = filepath.Join(w.home, "audit.jsonl")
	w.loginMarker = filepath.Join(w.home, "logged-in")
	t.Setenv("HOME", w.home)
	t.Setenv("USERPROFILE", w.home)
	t.Setenv("AWS_CONFIG_FILE", w.awsConfig)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("XDG_STATE_HOME", filepath.Join(w.home, "state"))
	w.names = map[string]string{"111111111111": "payments-prod", "222222222222": "payments-dev", "333333333333": "lending-ete"}
	w.assignments = map[string][]string{
		"111111111111": {"Platform-ReadOnly", "BreakGlass-Admin"},
		"222222222222": {"Platform-Admin", "BreakGlass-Admin"},
		"333333333333": {"Platform-Admin"},
	}

	cache := filepath.Join(w.home, ".aws", "sso", "cache")
	tokenFile := awssso.TokenPath(cache, "nedctl")
	expires := time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339)
	fakeCLI(t, "aws", `case "$*" in
"sso login --sso-session nedctl"*)
  mkdir -p `+sq(cache)+` && printf '%s' '{"accessToken":"tok-secret","expiresAt":"`+expires+`","region":"af-south-1"}' > `+sq(tokenFile)+`
  echo "$*" > `+sq(w.loginMarker)+`;;
*"sts get-caller-identity"*)
  p=$(echo "$*" | sed -n 's/.*--profile \([^ ]*\).*/\1/p')
  acct=$(awk -v h="[profile $p]" '$0==h{f=1;next} /^\[/{f=0} f&&$1=="sso_account_id"{print $3}' "$AWS_CONFIG_FILE")
  [ -n "$acct" ] || { echo "The config profile ($p) could not be found" >&2; exit 255; }
  echo "{\"Account\":\"$acct\",\"Arn\":\"arn:aws:sts::$acct:assumed-role/AWSReservedSSO_role_abc/neo@bank.example\"}";;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-amz-sso_bearer_token") != "tok-secret" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/assignment/accounts":
			var parts []string
			for _, id := range []string{"111111111111", "222222222222", "333333333333"} {
				parts = append(parts, fmt.Sprintf(`{"accountId":%q,"accountName":%q}`, id, w.names[id]))
			}
			fmt.Fprintf(rw, `{"accountList":[%s]}`, strings.Join(parts, ","))
		case "/assignment/roles":
			var parts []string
			for _, role := range w.assignments[r.URL.Query().Get("account_id")] {
				parts = append(parts, fmt.Sprintf(`{"roleName":%q}`, role))
			}
			fmt.Fprintf(rw, `{"roleList":[%s]}`, strings.Join(parts, ","))
		}
	}))
	t.Cleanup(srv.Close)
	old := newPortal
	newPortal = func(config.AWS) awssso.Portal { return awssso.Portal{BaseURL: srv.URL, Client: srv.Client()} }
	t.Cleanup(func() { newPortal = old })

	w.cfg = filepath.Join(w.home, "nedctl.json")
	body := `{"environments": ["dev","ete","qa","prod"], "prodEnvironments": ["qa","prod"],
	  "audit": {"logPath": ` + quote(w.logPath) + `},
	  "aws": {"startUrl": "https://d-1234567890.awsapps.com/start", "ssoRegion": "af-south-1",
	          "accountNamePattern": "^(?P<squad>[a-z]+)-(?P<env>dev|ete|qa|prod)$",
	          "breakGlassRoles": ["BreakGlass-Admin"]` + extra + `}}`
	if err := os.WriteFile(w.cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

// answer feeds the picker as if typed at a terminal.
func answer(t *testing.T, input string) {
	t.Helper()
	oldIn, oldTTY := stdin, stdinIsTerminal
	stdin, stdinIsTerminal = strings.NewReader(input), func() bool { return true }
	t.Cleanup(func() { stdin, stdinIsTerminal = oldIn, oldTTY })
}

func TestAWSLoginWithFlagsWritesOneVerifiedProfile(t *testing.T) {
	w := newAWSWorld(t, "")
	code, out, errb := run("--config", w.cfg, "aws", "login", "--account", "payments-prod", "--role", "Platform-ReadOnly", "--format", "sh")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	const profile = "nedctl.payments-prod.Platform-ReadOnly"
	if out != "export AWS_PROFILE='"+profile+"'\n" {
		t.Fatalf("stdout must be only the export line (for eval): %q", out)
	}
	if _, err := os.Stat(w.loginMarker); err != nil {
		t.Fatal("no cached sign-in, so `aws sso login` must have run")
	}
	cfgText, _ := os.ReadFile(w.awsConfig)
	if strings.Count(string(cfgText), "[profile ") != 1 || !strings.Contains(string(cfgText), "sso_account_id = 111111111111") ||
		!strings.Contains(string(cfgText), "# environment = prod") {
		t.Fatalf("exactly the chosen profile must be written:\n%s", cfgText)
	}
	if strings.Contains(string(cfgText), "tok-secret") || strings.Contains(errb, "tok-secret") {
		t.Fatal("the Identity Center token leaked")
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "aws-login" || ev[1].Outcome != audit.OutcomeSuccess || ev[1].Account != "111111111111" ||
		!ev[1].Production || ev[1].Environment != "prod" || !strings.Contains(ev[1].Principal, "AWSReservedSSO") {
		t.Fatalf("audit: %+v", ev)
	}
	if !strings.Contains(errb, "Signed in: payments · PROD · Platform-ReadOnly") {
		t.Fatalf("stderr: %q", errb)
	}
	if got := resolveProfile(mustLoad(t, w.cfg), ""); got != profile {
		t.Fatalf("current profile not remembered: %q", got)
	}
}

func mustLoad(t *testing.T, path string) config.Config {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAWSLoginPickerFiltersAndColoursByEnvironment(t *testing.T) {
	w := newAWSWorld(t, "")
	answer(t, "dev platform\n1\n")
	code, out, errb := run("--config", w.cfg, "aws", "login", "--format", "powershell")
	if code != ExitOK || out != "$env:AWS_PROFILE = 'nedctl.payments-dev.Platform-Admin'\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	for _, want := range []string{"SQUAD", "lending", "ete", `filter: "dev platform" (1 of 5)`} {
		if !strings.Contains(errb, want) {
			t.Fatalf("picker output lacks %q:\n%s", want, errb)
		}
	}
}

func TestAWSLoginReusesCachedSignIn(t *testing.T) {
	w := newAWSWorld(t, "")
	if code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "222222222222", "--role", "Platform-Admin"); code != ExitOK {
		t.Fatalf("first: %q", errb)
	}
	os.Remove(w.loginMarker)
	if code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "lending-ete"); code != ExitOK {
		t.Fatalf("second: %q", errb)
	}
	if _, err := os.Stat(w.loginMarker); err == nil {
		t.Fatal("a valid cached sign-in must not trigger another browser approval")
	}
	cfgText, _ := os.ReadFile(w.awsConfig)
	if strings.Count(string(cfgText), "[profile ") != 2 {
		t.Fatalf("profiles accumulate inside the managed block:\n%s", cfgText)
	}
}

func TestAWSLoginNeverGuesses(t *testing.T) {
	w := newAWSWorld(t, "")
	old := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = old })
	// Two roles in payments-prod and no terminal: refuse rather than pick.
	code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "payments-prod")
	if code != ExitUsage || !strings.Contains(errb, "2 assignments match") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	code, _, errb = run("--config", w.cfg, "aws", "login", "--account", "nope")
	if code != ExitFailure || !strings.Contains(errb, "none of your 5 assignments matches") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	answer(t, "q\n")
	if code, _, _ := run("--config", w.cfg, "aws", "login"); code != ExitFailure {
		t.Fatalf("quitting the picker: code=%d", code)
	}
}

func TestAWSLoginRefusesProfileActingInAnotherAccount(t *testing.T) {
	w := newAWSWorld(t, "")
	// Someone hand-edits the managed block so the profile points elsewhere;
	// the next login rewrites it, so simulate the CLI resolving wrongly instead.
	fakeCLI(t, "aws", `case "$*" in
*"sts get-caller-identity"*) echo '{"Account":"999999999999","Arn":"arn:aws:sts::999999999999:assumed-role/x/y"}';;
"sso login"*) mkdir -p "$HOME/.aws/sso/cache"; printf '%s' '{"accessToken":"tok-secret","expiresAt":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}' > "$HOME/.aws/sso/cache/1ed1f11d95712761bde8be84597801e59ab9632a.json";;
esac`)
	code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "lending-ete")
	if code != ExitFailure || !strings.Contains(errb, `acts in account "999999999999", not 333333333333`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if ev := readAudit(t, w.logPath); ev[1].Outcome != audit.OutcomeRefused {
		t.Fatalf("refusal must be recorded: %+v", ev)
	}
}

func TestAWSLoginNeedsConfiguration(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(cfg, []byte(`{}`), 0o600)
	if code, _, errb := run("--config", cfg, "aws", "login"); code != ExitFailure || !strings.Contains(errb, "IAM Identity Center is not configured") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	os.WriteFile(cfg, []byte(`{"aws":{"startUrl":"http://x","ssoRegion":"nowhere"}}`), 0o600)
	if code, _, errb := run("--config", cfg, "aws", "login"); code != ExitFailure || !strings.Contains(errb, "must be https") || !strings.Contains(errb, "not an AWS region") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestAWSBreakGlassAllUsesOnlyBreakGlassRolesAndFlagsEach(t *testing.T) {
	w := newAWSWorld(t, "")
	reason := "P1 INC0012345 payments API down in prod"
	code, out, errb := run("--config", w.cfg, "aws", "login", "--all", "--break-glass", reason)
	if code != ExitOK || out != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	cfgText, _ := os.ReadFile(w.awsConfig)
	if strings.Count(string(cfgText), "[profile ") != 2 || strings.Contains(string(cfgText), "Platform-") {
		t.Fatalf("only the two BreakGlass-Admin assignments may be signed in to:\n%s", cfgText)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 4 {
		t.Fatalf("want a start+end per account: %+v", ev)
	}
	for _, e := range ev {
		if !e.BreakGlass || e.BreakGlassReason != reason {
			t.Fatalf("every event must be flagged break-glass: %+v", e)
		}
	}
	if !strings.Contains(errb, "BREAK-GLASS: signing in to 2 account(s)") {
		t.Fatalf("stderr: %q", errb)
	}
}

func TestAWSBreakGlassRefusedWithoutRoleIsRecorded(t *testing.T) {
	w := newAWSWorld(t, "")
	w.assignments["111111111111"] = []string{"Platform-ReadOnly"}
	w.assignments["222222222222"] = []string{"Platform-Admin"}
	code, _, errb := run("--config", w.cfg, "aws", "login", "--all", "--break-glass", "P1 INC0012345 payments API down")
	if code != ExitFailure || !strings.Contains(errb, "you hold no break-glass role") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Outcome != audit.OutcomeRefused || !ev[1].BreakGlass {
		t.Fatalf("a refused break-glass attempt must be on record: %+v", ev)
	}
}

func TestAWSBreakGlassFlagRules(t *testing.T) {
	w := newAWSWorld(t, "")
	for _, args := range [][]string{
		{"--all"},
		{"--break-glass", "P1 INC0012345 payments API down"},
		{"--all", "--break-glass", "too short"},
		{"--all", "--break-glass", "P1 INC0012345 payments API down", "--role", "BreakGlass-Admin"},
	} {
		if code, _, _ := run(append([]string{"--config", w.cfg, "aws", "login"}, args...)...); code != ExitUsage {
			t.Fatalf("%v: code=%d", args, code)
		}
	}
}

// withExport extends the fake aws CLI with `configure export-credentials`.
func withExport(t *testing.T, w *awsWorld, output string) {
	t.Helper()
	cache := filepath.Join(w.home, ".aws", "sso", "cache")
	tokenFile := awssso.TokenPath(cache, "nedctl")
	expires := time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339)
	fakeCLI(t, "aws", `case "$*" in
"configure export-credentials"*) printf '%s\n' `+sq(output)+`;;
"sso login"*) mkdir -p `+sq(cache)+` && printf '%s' '{"accessToken":"tok-secret","expiresAt":"`+expires+`"}' > `+sq(tokenFile)+`;;
*"sts get-caller-identity"*)
  p=$(echo "$*" | sed -n 's/.*--profile \([^ ]*\).*/\1/p')
  acct=$(awk -v h="[profile $p]" '$0==h{f=1;next} /^\[/{f=0} f&&$1=="sso_account_id"{print $3}' "$AWS_CONFIG_FILE")
  echo "{\"Account\":\"$acct\",\"Arn\":\"arn:aws:sts::$acct:assumed-role/AWSReservedSSO_r/neo\"}";;
esac`)
}

func TestAWSWhoamiAndEnv(t *testing.T) {
	w := newAWSWorld(t, "")
	withExport(t, w, "AWS_ACCESS_KEY_ID=ASIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=c2VjcmV0\nAWS_SESSION_TOKEN=dG9rZW4=\nAWS_CREDENTIAL_EXPIRATION=2026-10-06T17:00:00+00:00")
	if code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "payments-prod", "--role", "Platform-ReadOnly", "--format", "none"); code != ExitOK {
		t.Fatalf("login: %q", errb)
	}
	code, out, errb := run("--config", w.cfg, "aws", "whoami", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"environment": "prod"`) || !strings.Contains(out, `"production": true`) ||
		!strings.Contains(out, `"signInExpires"`) || !strings.Contains(out, `"role": "Platform-ReadOnly"`) {
		t.Fatalf("whoami: code=%d out=%s err=%q", code, out, errb)
	}
	code, out, errb = run("--config", w.cfg, "aws", "env", "--format", "sh")
	if code != ExitOK || !strings.Contains(out, "export AWS_ACCESS_KEY_ID='ASIAEXAMPLE'") || !strings.Contains(out, "export AWS_SESSION_TOKEN='dG9rZW4='") {
		t.Fatalf("env: code=%d out=%q err=%q", code, out, errb)
	}
	ev := readAudit(t, w.logPath)
	last := ev[len(ev)-1]
	if last.Action != "aws-export-credentials" || last.Outcome != audit.OutcomeSuccess {
		t.Fatalf("export must be recorded: %+v", last)
	}
	logText, _ := os.ReadFile(w.logPath)
	if strings.Contains(string(logText), "ASIAEXAMPLE") || strings.Contains(string(logText), "c2VjcmV0") {
		t.Fatal("credentials leaked into the audit log")
	}
}

func TestAWSEnvRefusesSuspiciousOutput(t *testing.T) {
	w := newAWSWorld(t, "")
	withExport(t, w, "AWS_ACCESS_KEY_ID=ASIA'; rm -rf ~; echo '\nAWS_SECRET_ACCESS_KEY=x")
	code, out, errb := run("--config", w.cfg, "aws", "env", "--profile", "anything")
	if code != ExitFailure || out != "" || !strings.Contains(errb, "unexpected output") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}

// A portal call that hangs (no proxy behind a corporate firewall) must end
// with an explanation, not just "Client.Timeout exceeded".
func TestAWSLoginTimeoutExplainsTheProxy(t *testing.T) {
	w := newAWSWorld(t, "")
	hang := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	t.Cleanup(hang.Close)
	newPortal = func(config.AWS) awssso.Portal {
		c := hang.Client()
		c.Timeout = 200 * time.Millisecond
		return awssso.Portal{BaseURL: hang.URL, Client: c}
	}
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	code, _, errb := run("--config", w.cfg, "aws", "login", "--account", "payments-dev")
	if code != ExitFailure || !strings.Contains(errb, "HTTPS_PROXY is not set") || !strings.Contains(errb, "NEDCTL_DEBUG=1") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
