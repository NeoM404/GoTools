package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"nedctl/internal/awssso"
	"nedctl/internal/evidence"
)

// TestE2EEngineerJourney is the regression test for the AWS access
// proposal: one engineer's day, in order, through nedctl's real command
// paths, against a simulated Identity Center, AWS account, private EKS API
// and the legacy sm tool. Each step depends on the state the previous ones
// left (AWS config, current profile, kubeconfig, audit chain), as in real
// use. Run alone with `make e2e`.
func TestE2EEngineerJourney(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("kubectl not installed")
	}
	w := newAWSWorld(t, `, "devopsInstance": "devops", "legacyTool": "sm"`)
	body, _ := os.ReadFile(w.cfg)
	os.WriteFile(w.cfg, []byte(strings.Replace(string(body), `"audit"`,
		`"prodPatterns": ["(?i)(^|[-_.])(prod|prd|qa)([-_.]|$)"], "changeControl": {"enabled": false, "requireFor": ["prod"]}, "audit"`, 1)), 0o600)

	calls := filepath.Join(w.home, "aws-calls")
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	ca := fakeEKSAPI(t, port)
	cache := filepath.Join(w.home, ".aws", "sso", "cache")
	tokenFile := awssso.TokenPath(cache, "nedctl")
	expires := time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339)
	desc := `{"cluster":{"name":"payments-eks-prod","arn":"arn:aws:eks:af-south-1:111111111111:cluster/payments-eks-prod","endpoint":"https://` + eksHost +
		`","version":"1.30","accessConfig":{"authenticationMode":"CONFIG_MAP"},"resourcesVpcConfig":{"endpointPrivateAccess":true},"certificateAuthority":{"data":"` + ca + `"}}}`
	fakeCLI(t, "aws", `echo "$*" >> `+sq(calls)+`
case "$*" in
"sso login --sso-session nedctl"*) mkdir -p `+sq(cache)+` && printf '%s' '{"accessToken":"tok-secret","expiresAt":"`+expires+`"}' > `+sq(tokenFile)+`;;
*"sts get-caller-identity"*)
  p=$(echo "$*" | sed -n 's/.*--profile \([^ ]*\).*/\1/p')
  acct=$(awk -v h="[profile $p]" '$0==h{f=1;next} /^\[/{f=0} f&&$1=="sso_account_id"{print $3}' "$AWS_CONFIG_FILE")
  echo "{\"Account\":\"$acct\",\"Arn\":\"arn:aws:sts::$acct:assumed-role/AWSReservedSSO_r_1/neo@bank.example\"}";;
"ec2 describe-instances"*"--region af-south-1"*) printf '%s' `+sq(instancesJSON)+`;;
"ec2 describe-instances"*) echo '{"Reservations":[]}';;
"ssm start-session"*) echo "Starting session with SessionId: neo@bank.example-0123abcd";;
"eks describe-cluster"*"--region af-south-1"*) printf '%s' `+sq(desc)+`;;
"eks list-clusters"*"--region af-south-1"*) echo '{"clusters":["payments-eks-prod"]}';;
"eks list-clusters"*) echo '{"clusters":[]}';;
"ec2 describe-regions"*) echo '["af-south-1","eu-west-1"]';;
"eks get-token"*) echo '{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","status":{"token":"k8s-aws-v1.fake","expirationTimestamp":"2099-01-01T00:00:00Z"}}';;
"configure export-credentials"*) printf 'AWS_ACCESS_KEY_ID=ASIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=c2VjcmV0\nAWS_SESSION_TOKEN=dG9rZW4=\n';;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)
	smSaw := filepath.Join(w.home, "sm-saw")
	fakeCLI(t, "sm", `printf '%s' "$AWS_ACCESS_KEY_ID" > `+sq(smSaw))

	step := func(name string, wantCode int, args ...string) (string, string) {
		t.Helper()
		code, out, errb := run(append([]string{"--config", w.cfg}, args...)...)
		if code != wantCode {
			t.Fatalf("step %q: code=%d want %d\nstdout: %s\nstderr: %s", name, code, wantCode, out, errb)
		}
		return out, errb
	}

	// 1. Morning: one browser approval, pick payments prod read-only.
	answer(t, "payments prod readonly\n1\n")
	out, _ := step("sign in and pick", ExitOK, "aws", "login", "--format", "sh")
	if out != "export AWS_PROFILE='nedctl.payments-prod.Platform-ReadOnly'\n" {
		t.Fatalf("login stdout: %q", out)
	}
	// 2. Confirm who I am.
	out, _ = step("whoami", ExitOK, "aws", "whoami", "-o", "json")
	if !strings.Contains(out, `"production": true`) {
		t.Fatalf("whoami: %s", out)
	}
	// 3. Shell on the devops box (change control is off for now).
	_, errb := step("shell on the devops box", ExitOK, "shell", "devops")
	if !strings.Contains(errb, "PRODUCTION — this session is recorded") || !strings.Contains(errb, "change control is switched off") {
		t.Fatalf("shell: %s", errb)
	}
	// 4. Straight to the private cluster from the laptop, then real kubectl.
	step("connect", ExitOK, "connect", "payments-eks-prod", "--port", strconv.Itoa(port))
	kc := filepath.Join(w.home, ".kube", "nedctl", "payments-eks-prod.json")
	if raw, err := exec.Command("kubectl", "--kubeconfig", kc, "get", "--raw", "/version").CombinedOutput(); err != nil || !strings.Contains(string(raw), "eks") {
		t.Fatalf("kubectl: %v %s", err, raw)
	}
	// 5. The guard and the prompt both know this is production.
	t.Setenv("KUBECONFIG", kc)
	step("guard blocks prod", ExitProdContext, "guard", "--block")
	out, _ = step("prompt", ExitOK, "prompt")
	if !strings.Contains(out, "k8s:payments-eks-prod[PROD]") || !strings.Contains(out, "aws:payments[PROD]") {
		t.Fatalf("prompt: %q", out)
	}
	// 6. Evidence for the access-entries decision.
	out, _ = step("eks auth report", ExitOK, "eks", "auth", "-o", "json")
	if !strings.Contains(out, `"configMapOnly": 1`) {
		t.Fatalf("eks auth: %s", out)
	}
	// 7. A colleague prefers sm: launch it signed in, no paste.
	step("sm handover", ExitOK, "shell", "--via", "legacy")
	if got, _ := os.ReadFile(smSaw); string(got) != "ASIAEXAMPLE" {
		t.Fatalf("sm did not receive credentials: %q", got)
	}
	// 8. Incident: break-glass to every account (named admins only).
	step("break-glass", ExitOK, "aws", "login", "--all", "--break-glass", "P1 INC0012345 payments API down in prod")

	// 9. Quarter end: the evidence pack and the audit chain.
	out, _ = step("evidence pack", ExitOK, "evidence", "--from", "2000-01-01", "--to", "2099-12-31", "-o", "json")
	var rep evidence.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, a := range rep.Accesses {
		actions[a.Action]++
	}
	for _, want := range []string{"aws-login", "ssm-session", "eks-connect", "legacy-ssm-tool"} {
		if actions[want] == 0 {
			t.Fatalf("evidence lacks %s: %v", want, actions)
		}
	}
	if !rep.Complete || rep.Summary.BreakGlass != 2 || len(rep.Exceptions) == 0 {
		t.Fatalf("evidence: complete=%v summary=%+v exceptions=%d", rep.Complete, rep.Summary, len(rep.Exceptions))
	}
	reasons := ""
	for _, e := range rep.Exceptions {
		reasons += e.Reason + "\n"
	}
	if !strings.Contains(reasons, "break-glass access") || !strings.Contains(reasons, "production access without a change record") {
		t.Fatalf("exceptions:\n%s", reasons)
	}
	step("audit chain intact", ExitOK, "audit", "verify")
	logText, _ := os.ReadFile(w.logPath)
	for _, secret := range []string{"tok-secret", "ASIAEXAMPLE", "c2VjcmV0", "k8s-aws-v1.fake"} {
		if strings.Contains(string(logText), secret) {
			t.Fatalf("secret %q leaked into the audit log", secret)
		}
	}
	// Tampering with any recorded access is detected.
	lines := strings.Split(string(logText), "\n")
	lines[3] = strings.Replace(lines[3], `"production":true`, `"production":false`, 1)
	os.WriteFile(w.logPath, []byte(strings.Join(lines, "\n")), 0o600)
	step("tampering detected", ExitFailure, "audit", "verify")
}
