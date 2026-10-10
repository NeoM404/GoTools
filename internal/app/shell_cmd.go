package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
	"nedctl/internal/picker"
)

// ec2Instance is one row of the instance picker.
type ec2Instance struct {
	ID, Name, PrivateIP, State, Type, Zone, AccessLevel string
	Region                                              string
}

func (e ec2Instance) regionOf() string { return e.Region }

var instanceIDRe = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)

// profileContext is what nedctl knows about the profile a command acts with.
type profileContext struct {
	Name               string
	AccountID, Role    string
	Squad, Environment string
	Production         bool
}

func loadProfileContext(ctx context.Context, cfg config.Config, flagValue string, stderr io.Writer) (profileContext, bool) {
	name := resolveProfile(cfg, flagValue)
	if name == "" {
		// Not signed in yet: in a terminal, sign in now and carry on, so
		// `nedctl kube` can be the first command of the day.
		if !cfg.AWS.Configured() || !stdinIsTerminal() {
			fmt.Fprintln(stderr, "not signed in — run `nedctl aws login`, or pass --profile")
			return profileContext{}, false
		}
		fmt.Fprintln(stderr, "Not signed in yet — pick an account and role:")
		profile, code := interactiveLogin(ctx, cfg, nil, stderr)
		if code != ExitOK {
			return profileContext{}, false
		}
		name = profile
	}
	pc := profileContext{Name: name}
	if path, err := awssso.ConfigPath(); err == nil {
		if m, err := awssso.LoadManaged(path); err == nil {
			if p, ok := m.Profiles[name]; ok {
				pc.AccountID, pc.Role, pc.Squad, pc.Environment = p.AccountID, p.Role, p.Squad, p.Environment
				renewOrWarnSignIn(ctx, cfg, m.Session.Name, stderr)
			}
		}
	}
	pc.Production = cfg.IsProdEnvironment(pc.Environment)
	return pc, true
}

// renewOrWarnSignIn renews an expired (or about to expire) sign-in in a
// terminal, keeping the same account and role, so a task is not broken by
// "Token has expired" from the AWS CLI. Without a terminal it warns.
func renewOrWarnSignIn(ctx context.Context, cfg config.Config, session string, stderr io.Writer) {
	left, ok := signInLeft(session)
	if ok && left <= tokenMargin && cfg.AWS.Configured() && stdinIsTerminal() {
		fmt.Fprintln(stderr, "Your IAM Identity Center sign-in has expired — renewing it (same account and role).")
		if _, _, code := ensureSignIn(ctx, cfg, noLocalBrowser(), true, stderr); code == ExitOK {
			fmt.Fprintln(stderr, "Signed in again.")
			return
		}
	}
	warnSignIn(session, stderr)
}

// signInWarnWithin is how close to expiry a command starts warning.
const signInWarnWithin = 15 * time.Minute

// signInLeft is how long the cached Identity Center sign-in for session
// has left; ok is false when there is none to read.
func signInLeft(session string) (time.Duration, bool) {
	dir, err := awssso.CacheDir()
	if err != nil {
		return 0, false
	}
	tok, err := awssso.ReadToken(dir, session, now(), -100*365*24*time.Hour) // read even when expired
	if err != nil {
		return 0, false
	}
	return tok.ExpiresAt.Sub(now()), true
}

// warnSignIn tells the engineer before their sign-in runs out mid-task.
func warnSignIn(session string, stderr io.Writer) {
	left, ok := signInLeft(session)
	switch {
	case !ok:
	case left <= 0:
		fmt.Fprintln(stderr, "warning: your IAM Identity Center sign-in has expired — run `nedctl aws login` to renew it")
	case left <= signInWarnWithin:
		fmt.Fprintf(stderr, "warning: your IAM Identity Center sign-in expires in %s — run `nedctl aws login` to renew it\n", left.Round(time.Minute))
	}
}

func (pc profileContext) label() string {
	return strings.Trim(firstNonBlank(pc.Squad, pc.Name)+" · "+strings.ToUpper(pc.Environment), " ·")
}

// listInstances returns the account's instances that are not terminated,
// across the regions the search covers.
func listInstances(ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, stderr io.Writer) ([]ec2Instance, []string, error) {
	list, searched, err := searchRegions(ctx, cfg, pc, rs, "ec2", stderr, func(region string) ([]ec2Instance, error) {
		return instancesIn(ctx, cfg, pc.Name, region)
	})
	sort.Slice(list, func(i, j int) bool {
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
	return list, searched, err
}

func instancesIn(ctx context.Context, cfg config.Config, profile, region string) ([]ec2Instance, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "ec2", "describe-instances", "--profile", profile, "--region", region, "--output", "json",
		"--filters", "Name=instance-state-name,Values=pending,running,stopping,stopped")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Reservations []struct {
			Instances []struct {
				InstanceID       string `json:"InstanceId"`
				InstanceType     string `json:"InstanceType"`
				PrivateIPAddress string `json:"PrivateIpAddress"`
				State            struct{ Name string }
				Placement        struct{ AvailabilityZone string }
				Tags             []struct{ Key, Value string }
			}
		}
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parsing ec2 describe-instances: %w", err)
	}
	levelTag := cfg.AWS.LevelTag()
	var list []ec2Instance
	for _, r := range resp.Reservations {
		for _, in := range r.Instances {
			if !instanceIDRe.MatchString(in.InstanceID) {
				return nil, fmt.Errorf("ec2 returned an invalid instance ID %q", in.InstanceID)
			}
			e := ec2Instance{ID: in.InstanceID, PrivateIP: in.PrivateIPAddress, State: in.State.Name,
				Type: in.InstanceType, Zone: in.Placement.AvailabilityZone, Region: region}
			for _, tg := range in.Tags {
				switch {
				case tg.Key == "Name":
					e.Name = tg.Value
				case strings.EqualFold(tg.Key, levelTag):
					e.AccessLevel = tg.Value
				}
			}
			list = append(list, e)
		}
	}
	return list, nil
}

// noInstances explains an empty search instead of an empty picker.
func noInstances(pc profileContext, searched []string, stderr io.Writer) {
	fmt.Fprintf(stderr, "no instances in %s, searched %s — wrong account? Try --all-regions, or --region R\n",
		pc.label(), strings.Join(searched, ", "))
}

// chooseInstance resolves --instance or the filter terms to one instance,
// using the picker when several remain. It never guesses without a terminal.
func chooseInstance(cfg config.Config, pc profileContext, list []ec2Instance, instance string, terms []string, stderr io.Writer) (ec2Instance, int) {
	if instance != "" {
		for _, in := range list {
			if in.ID == instance || in.Name == instance {
				return in, ExitOK
			}
		}
		fmt.Fprintf(stderr, "no instance %q in this account (profile %s)\n", instance, pc.Name)
		return ec2Instance{}, ExitFailure
	}
	var cands []ec2Instance
	for _, in := range list {
		hay := strings.ToLower(strings.Join([]string{in.Name, in.ID, in.PrivateIP, in.State, in.Type, in.Zone, in.AccessLevel}, " "))
		ok := true
		for _, t := range terms {
			if !strings.Contains(hay, strings.ToLower(t)) {
				ok = false
			}
		}
		if ok {
			cands = append(cands, in)
		}
	}
	switch {
	case len(cands) == 0:
		fmt.Fprintf(stderr, "no instance matches %q in %s\n", strings.Join(terms, " "), pc.label())
		return ec2Instance{}, ExitFailure
	case len(cands) == 1:
		return cands[0], ExitOK
	case !stdinIsTerminal():
		fmt.Fprintf(stderr, "%d instances match — narrow the filter or pass --instance\n", len(cands))
		return ec2Instance{}, ExitUsage
	}
	color := cfg.ColorFor(pc.Environment)
	rows := make([]picker.Row, len(cands))
	for i, in := range cands {
		rows[i] = picker.Row{Cells: []string{in.Name, in.ID, in.PrivateIP, in.State, in.Type, in.Zone, in.AccessLevel}, Color: color}
	}
	idx, err := picker.Picker{Title: "Instances in " + pc.label(), Header: []string{"NAME", "INSTANCE", "PRIVATE IP", "STATE", "TYPE", "ZONE", "LEVEL"},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ec2Instance{}, ExitFailure
	}
	return cands[idx], ExitOK
}

func cmdShell(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to act with (default: $AWS_PROFILE, then the last `nedctl aws login`)")
	instance := fs.String("instance", "", "instance ID or Name tag (skips the picker)")
	via := fs.String("via", "aws", "aws (Session Manager directly) or legacy (launch sm/SSMshell already signed in)")
	tab := fs.Bool("tab", false, "open the session in a new Windows Terminal tab coloured by environment")
	crFlag := fs.String("change-record", "", "change record for this session, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	var rs regionSearch
	addRegionFlags(fs, &rs)
	terms, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if *via != "aws" && *via != "legacy" {
		fmt.Fprintf(stderr, "--via %q: want aws or legacy\n", *via)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	pc, ok := loadProfileContext(ctx, cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	if *via == "legacy" {
		return launchLegacy(ctx, cfg, pc, stderr)
	}

	list, searched, err := listInstances(ctx, cfg, pc, rs, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "listing instances with %s: %v\n", pc.Name, err)
		return ExitFailure
	}
	if len(list) == 0 {
		noInstances(pc, searched, stderr)
		return ExitFailure
	}
	in, code := chooseInstance(cfg, pc, list, *instance, terms, stderr)
	if code != ExitOK {
		return code
	}
	if in.State != "running" {
		fmt.Fprintf(stderr, "%s (%s) is %s — start it with `nedctl ec2 start %s`\n", firstNonBlank(in.Name, in.ID), in.ID, in.State, in.ID)
		return ExitFailure
	}
	if *tab {
		return openTab(cfg, pc, in, *crFlag, *glassFlag, stderr)
	}

	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	base := audit.Event{Action: "ssm-session", Cloud: "aws", Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("instance %s (%s) in %s, level %s, profile %s", in.ID, firstNonBlank(in.Name, "unnamed"), in.Region, firstNonBlank(in.AccessLevel, "untagged"), pc.Name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to start the session: every session must be recorded\n", err)
		return ExitFailure
	}
	target := inventory.Cluster{Name: firstNonBlank(in.Name, in.ID), Environment: pc.Environment}
	if code := applyChangeControl(ctx, cfg, target, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	banner(cfg, pc, firstNonBlank(in.Name, in.ID), stderr)
	err = execx.Interactive(ctx, execx.Spec{Name: "aws", Args: []string{"ssm", "start-session", "--target", in.ID, "--region", in.Region, "--profile", pc.Name},
		Timeout: cfg.AWS.Timeout()})
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "session failed: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	return ExitOK
}

// banner names the target in the terminal title and in the environment's
// colour, so prod is visible before the first keystroke.
func banner(cfg config.Config, pc profileContext, target string, stderr io.Writer) {
	title := pc.label() + " · " + target
	if colorOn(stderr) {
		fmt.Fprintf(stderr, "\x1b]0;%s\x07", title)
		title = picker.Paint(cfg.ColorFor(pc.Environment), title)
	}
	fmt.Fprintf(stderr, "▶ %s\n", title)
	if cfg.AWS.Elevated(pc.Role) {
		note := "▲ elevated role " + pc.Role + " — it can change and delete resources"
		if colorOn(stderr) {
			note = picker.Paint(elevatedColor, note)
		}
		fmt.Fprintln(stderr, note)
	}
	if pc.Production {
		fmt.Fprintln(stderr, "⚠️ PRODUCTION — this session is recorded.")
	}
}

// launchLegacy starts the existing SSM tool (sm, SSMshell) with the
// profile's short-term credentials in its environment, so nobody pastes
// keys into it. The credentials go to that one child process only.
func launchLegacy(ctx context.Context, cfg config.Config, pc profileContext, stderr io.Writer) int {
	tool := wslPath(cfg.AWS.Legacy())
	base := audit.Event{Action: "legacy-ssm-tool", Cloud: "aws", Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, Detail: fmt.Sprintf("%s with profile %s", tool, pc.Name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to launch %s: every session must be recorded\n", err, tool)
		return ExitFailure
	}
	env, err := exportCredentials(ctx, cfg, pc.Name)
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "getting credentials for %s: %v\n", pc.Name, err)
		return ExitFailure
	}
	if inWSL() && strings.HasSuffix(strings.ToLower(tool), ".exe") {
		env = shareWithWindows(env)
	}
	banner(cfg, pc, tool, stderr)
	err = execx.Interactive(ctx, execx.Spec{Name: tool, Env: env, Timeout: cfg.AWS.Timeout()})
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "%s: %v\n", tool, err)
		var nf *execx.NotFoundError
		if errors.As(err, &nf) {
			fmt.Fprintln(stderr, `→ set aws.legacyTool in config to the tool's path, e.g. "C:\\Tools\\AWS-EC2-SSMshell.exe" (from WSL, /mnt/c/... works too)`)
		}
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	return ExitOK
}

// openTab hands the session to a new Windows Terminal tab.
func openTab(cfg config.Config, pc profileContext, in ec2Instance, cr, glass string, stderr io.Writer) int {
	title := pc.label() + " · " + firstNonBlank(in.Name, in.ID)
	args := []string{"shell", "--profile", pc.Name, "--region", in.Region, "--instance", in.ID}
	if cr != "" {
		args = append(args, "--change-record", cr)
	}
	if glass != "" {
		args = append(args, "--break-glass", glass)
	}
	code := openWTTab(cfg, pc.Environment, title, "run without --tab to use this terminal", args, stderr)
	if code == ExitOK {
		fmt.Fprintf(stderr, "opened a tab: %s\n", title)
	}
	return code
}

func cmdEC2(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "start" && args[0] != "stop") {
		fmt.Fprintln(stderr, "usage: nedctl ec2 <start|stop> <instance-id|name> [--profile P] [--yes]")
		return ExitUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("ec2 "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to act with")
	yes := fs.Bool("yes", false, "do not ask for confirmation (required without a terminal in production)")
	var rs regionSearch
	addRegionFlags(fs, &rs)
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: nedctl ec2 <start|stop> <instance-id|name> [--profile P] [--yes]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	pc, ok := loadProfileContext(ctx, cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	list, _, err := listInstances(ctx, cfg, pc, rs, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "listing instances with %s: %v\n", pc.Name, err)
		return ExitFailure
	}
	in, code := chooseInstance(cfg, pc, list, pos[0], nil, stderr)
	if code != ExitOK {
		return code
	}
	if pc.Production && !*yes {
		if !stdinIsTerminal() {
			fmt.Fprintln(stderr, "production: pass --yes to "+action+" without a terminal")
			return ExitUsage
		}
		fmt.Fprintf(stderr, "⚠  %s %s (%s) in PRODUCTION? Type the instance ID to confirm: ", action, firstNonBlank(in.Name, in.ID), in.ID)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.TrimSpace(line) != in.ID {
			fmt.Fprintln(stderr, "not confirmed — nothing changed")
			return ExitFailure
		}
	}
	base := audit.Event{Action: "ec2-" + action, Cloud: "aws", Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, Detail: fmt.Sprintf("instance %s (%s) in %s, profile %s", in.ID, firstNonBlank(in.Name, "unnamed"), in.Region, pc.Name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to %s: every change must be recorded\n", err, action)
		return ExitFailure
	}
	if _, err := execx.Output(ctx, cfg.Timeout(), "aws", "ec2", action+"-instances", "--instance-ids", in.ID, "--region", in.Region, "--profile", pc.Name, "--output", "json"); err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "%s failed: %v\n", action, err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	fmt.Fprintf(stdout, "%s requested for %s (%s)\n", action, firstNonBlank(in.Name, in.ID), in.ID)
	return ExitOK
}
