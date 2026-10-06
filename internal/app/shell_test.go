package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NeoM404/GoTools/internal/audit"
	"github.com/NeoM404/GoTools/internal/awssso"
)

// ec2World is an awsWorld signed in to one profile, with a fake account of
// three instances. The fake aws records what it was asked to do.
type ec2World struct {
	*awsWorld
	calls string // file the fake aws appends its arguments to
}

const instancesJSON = `{"Reservations":[{"Instances":[
 {"InstanceId":"i-0aaaaaaaaaaaaaaa1","InstanceType":"t3.large","PrivateIpAddress":"10.0.1.10","State":{"Name":"running"},"Placement":{"AvailabilityZone":"af-south-1a"},"Tags":[{"Key":"Name","Value":"payments-devops"},{"Key":"AccessLevel","Value":"3"}]},
 {"InstanceId":"i-0bbbbbbbbbbbbbbb2","InstanceType":"t3.small","PrivateIpAddress":"10.0.1.11","State":{"Name":"stopped"},"Placement":{"AvailabilityZone":"af-south-1b"},"Tags":[{"Key":"Name","Value":"payments-batch"},{"Key":"AccessLevel","Value":"1"}]},
 {"InstanceId":"i-0ccccccccccccccc3","InstanceType":"t3.small","PrivateIpAddress":"10.0.1.12","State":{"Name":"running"},"Placement":{"AvailabilityZone":"af-south-1a"},"Tags":[{"Key":"Name","Value":"payments-tools"}]}]}]}`

func newEC2World(t *testing.T, env, extra string) *ec2World {
	t.Helper()
	w := &ec2World{awsWorld: newAWSWorld(t, extra)}
	w.calls = filepath.Join(w.home, "aws-calls")
	acct := map[string]string{"prod": "111111111111", "dev": "222222222222"}[env]
	profile := "bankctl.payments-" + env + ".Platform-Admin"
	err := awssso.SaveManaged(w.awsConfig, awssso.Managed{
		Session:  awssso.Session{Name: "bankctl", StartURL: "https://d-1234567890.awsapps.com/start", Region: "af-south-1"},
		Profiles: map[string]awssso.Profile{profile: {Name: profile, AccountID: acct, Role: "Platform-Admin", Squad: "payments", Environment: env}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_PROFILE", profile)
	fakeCLI(t, "aws", `echo "$*" >> `+sq(w.calls)+`
case "$*" in
"ec2 describe-instances"*) printf '%s' `+sq(instancesJSON)+`;;
"ssm start-session"*) echo "Starting session with SessionId: neo@bank.example-0123abcd";;
"ec2 start-instances"*|"ec2 stop-instances"*) echo '{}';;
"configure export-credentials"*) printf 'AWS_ACCESS_KEY_ID=ASIAEXAMPLE\nAWS_SECRET_ACCESS_KEY=c2VjcmV0\nAWS_SESSION_TOKEN=dG9rZW4=\n';;
*) echo "fake aws: unexpected: $*" >&2; exit 254;;
esac`)
	return w
}

func (w *ec2World) awsCalls(t *testing.T) string {
	t.Helper()
	data, _ := os.ReadFile(w.calls)
	return string(data)
}

func TestShellFilterToOneInstanceStartsAuditedSession(t *testing.T) {
	w := newEC2World(t, "dev", "")
	code, _, errb := run("--config", w.cfg, "shell", "devops")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if !strings.Contains(w.awsCalls(t), "ssm start-session --target i-0aaaaaaaaaaaaaaa1 --profile bankctl.payments-dev.Platform-Admin") {
		t.Fatalf("calls:\n%s", w.awsCalls(t))
	}
	if !strings.Contains(errb, "▶ payments · DEV · payments-devops") {
		t.Fatalf("banner: %q", errb)
	}
	ev := readAudit(t, w.logPath)
	if len(ev) != 2 || ev[1].Action != "ssm-session" || ev[1].Outcome != audit.OutcomeSuccess || ev[1].Account != "222222222222" ||
		!strings.Contains(ev[1].Detail, "i-0aaaaaaaaaaaaaaa1 (payments-devops), level 3") {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestShellPickerShowsInstancesLikeSSMshell(t *testing.T) {
	w := newEC2World(t, "dev", "")
	answer(t, "tools\n1\n")
	if code, _, errb := run("--config", w.cfg, "shell"); code != ExitOK {
		t.Fatalf("err=%q", errb)
	}
	if !strings.Contains(w.awsCalls(t), "--target i-0ccccccccccccccc3") {
		t.Fatalf("calls:\n%s", w.awsCalls(t))
	}
}

func TestShellPickerColumns(t *testing.T) {
	w := newEC2World(t, "dev", "")
	answer(t, "q\n")
	_, _, errb := run("--config", w.cfg, "shell")
	for _, want := range []string{"NAME", "INSTANCE", "PRIVATE IP", "STATE", "TYPE", "ZONE", "LEVEL", "10.0.1.11", "stopped", "af-south-1b"} {
		if !strings.Contains(errb, want) {
			t.Fatalf("picker lacks %q:\n%s", want, errb)
		}
	}
}

func TestShellRefusesStoppedAndAmbiguous(t *testing.T) {
	w := newEC2World(t, "dev", "")
	code, _, errb := run("--config", w.cfg, "shell", "--instance", "payments-batch")
	if code != ExitFailure || !strings.Contains(errb, "is stopped — start it with `bankctl ec2 start i-0bbbbbbbbbbbbbbb2`") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	code, _, errb = run("--config", w.cfg, "shell", "payments")
	if code != ExitUsage || !strings.Contains(errb, "3 instances match") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if strings.Contains(w.awsCalls(t), "start-session") {
		t.Fatal("no session may start")
	}
}

func TestShellProdNeedsChangeRecordWhenControlRequiresIt(t *testing.T) {
	w := newEC2World(t, "prod", "")
	cfgBody, _ := os.ReadFile(w.cfg)
	os.WriteFile(w.cfg, []byte(strings.Replace(string(cfgBody), `"audit"`, `"changeControl": {"requireFor": ["prod"]}, "audit"`, 1)), 0o600)
	code, _, errb := run("--config", w.cfg, "shell", "devops")
	if code != ExitFailure || !strings.Contains(errb, "a change record is required for prod") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if code, _, errb = run("--config", w.cfg, "shell", "devops", "--change-record", "CHG0012345"); code != ExitOK {
		t.Fatalf("with a record: code=%d err=%q", code, errb)
	}
	if !strings.Contains(errb, "PRODUCTION — this session is recorded") {
		t.Fatalf("prod warning missing: %q", errb)
	}
}

func TestShellViaLegacyLaunchesSmSignedIn(t *testing.T) {
	w := newEC2World(t, "dev", "")
	seen := filepath.Join(w.home, "sm-env")
	fakeCLI(t, "sm", `printf '%s|%s' "$AWS_ACCESS_KEY_ID" "${AWS_PROFILE:-}" > `+sq(seen))
	code, _, errb := run("--config", w.cfg, "shell", "--via", "legacy")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	got, _ := os.ReadFile(seen)
	if !strings.HasPrefix(string(got), "ASIAEXAMPLE|") {
		t.Fatalf("sm must start with the credentials in its environment: %q", got)
	}
	if ev := readAudit(t, w.logPath); ev[1].Action != "legacy-ssm-tool" || ev[1].Outcome != audit.OutcomeSuccess {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestShellTabOpensColouredWindowsTerminalTab(t *testing.T) {
	w := newEC2World(t, "prod", "")
	args := filepath.Join(w.home, "wt-args")
	fakeCLI(t, "wt.exe", `printf '%s\n' "$@" > `+sq(args))
	t.Setenv("WT_SESSION", "x")
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	code, _, errb := run("--config", w.cfg, "shell", "devops", "--tab")
	if code != ExitOK {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	var got []byte
	for i := 0; i < 50 && len(got) == 0; i++ {
		got, _ = os.ReadFile(args)
		if len(got) == 0 {
			sleepBriefly()
		}
	}
	for _, want := range []string{"--tabColor\n#ef4444", "--title\npayments · PROD · payments-devops", "wsl.exe\n-d\nUbuntu\n--", "shell\n--profile\nbankctl.payments-prod.Platform-Admin\n--instance\ni-0aaaaaaaaaaaaaaa1"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("wt.exe args lack %q:\n%s", want, got)
		}
	}
	t.Setenv("WT_SESSION", "")
	if code, _, _ := run("--config", w.cfg, "shell", "devops", "--tab"); code != ExitUsage {
		t.Fatalf("--tab outside Windows Terminal: code=%d", code)
	}
}

func TestEC2StartStop(t *testing.T) {
	w := newEC2World(t, "prod", "")
	code, _, errb := run("--config", w.cfg, "ec2", "start", "payments-batch")
	if code != ExitUsage || !strings.Contains(errb, "pass --yes") {
		t.Fatalf("prod without a terminal must need --yes: code=%d err=%q", code, errb)
	}
	answer(t, "i-wrong\n")
	if code, _, _ := run("--config", w.cfg, "ec2", "start", "payments-batch"); code != ExitFailure {
		t.Fatalf("wrong confirmation: code=%d", code)
	}
	answer(t, "i-0bbbbbbbbbbbbbbb2\n")
	code, out, errb := run("--config", w.cfg, "ec2", "start", "payments-batch")
	if code != ExitOK || !strings.Contains(out, "start requested for payments-batch") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	if !strings.Contains(w.awsCalls(t), "ec2 start-instances --instance-ids i-0bbbbbbbbbbbbbbb2") {
		t.Fatalf("calls:\n%s", w.awsCalls(t))
	}
	if ev := readAudit(t, w.logPath); ev[len(ev)-1].Action != "ec2-start" || !ev[len(ev)-1].Production {
		t.Fatalf("audit: %+v", ev)
	}
}

func sleepBriefly() { time.Sleep(20 * time.Millisecond) }
