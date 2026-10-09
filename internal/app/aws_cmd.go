package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/picker"
)

// Seams for tests: the operator's terminal and the Identity Center portal.
var (
	stdin           io.Reader = os.Stdin
	stdinIsTerminal           = func() bool { return isTerminal(os.Stdin) }
	newPortal                 = func(a config.AWS) awssso.Portal { return awssso.Portal{Region: a.SSORegion} }
)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorOn reports whether w should get ANSI colour: a terminal, and NO_COLOR
// (https://no-color.org) unset.
func colorOn(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isTerminal(f) && os.Getenv("NO_COLOR") == ""
}

// tokenMargin: a cached sign-in expiring sooner than this counts as expired,
// so a command never starts on a token about to lapse.
const tokenMargin = 5 * time.Minute

func cmdAWS(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl aws <login|whoami|env> ...")
		return ExitUsage
	}
	switch args[0] {
	case "login":
		return awsLogin(ctx, cfgPath, args[1:], stdout, stderr)
	case "whoami":
		return awsWhoami(ctx, cfgPath, args[1:], stdout, stderr)
	case "env":
		return awsEnv(ctx, cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown aws subcommand %q\n", args[0])
		return ExitUsage
	}
}

// awsChoice is one assignment with the metadata nedctl derives for it.
type awsChoice struct {
	awssso.Assignment
	Squad, Environment string
}

func loadAWSConfig(cfgPath string, stderr io.Writer) (config.Config, bool) {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return cfg, false
	}
	if !cfg.AWS.Configured() {
		fmt.Fprintln(stderr, `IAM Identity Center is not configured — set "aws": {"startUrl": "https://<id>.awsapps.com/start", "ssoRegion": "<region>"} in your config (see docs/aws.md)`)
		return cfg, false
	}
	return cfg, true
}

func awsLogin(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aws login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	account := fs.String("account", "", "account ID or name (skips the picker when it and --role match one assignment)")
	role := fs.String("role", "", "role (permission set) name")
	deviceCode := fs.Bool("device-code", false, "sign in with a device code — for a host with no browser, such as a devops box")
	force := fs.Bool("force", false, "sign in again even if a valid sign-in is cached")
	refresh := fs.Bool("refresh", false, "fetch your accounts and roles again instead of reusing the list from this sign-in")
	format := fs.String("format", defaultEnvFormat(), "what to print on stdout: sh (export AWS_PROFILE=…), powershell, or none")
	all := fs.Bool("all", false, "break-glass: sign in to every account where you hold a break-glass role (needs --break-glass)")
	glass := fs.String("break-glass", "", "the incident or reason for signing in to every account; recorded and flagged for review")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	switch {
	case *all != (*glass != ""):
		fmt.Fprintln(stderr, "--all and --break-glass go together: signing in to every account is break-glass only")
		return ExitUsage
	case *all && (*account != "" || *role != ""):
		fmt.Fprintln(stderr, "--all signs in to every break-glass assignment; it does not take --account or --role")
		return ExitUsage
	case *all && len(strings.TrimSpace(*glass)) < config.MinBreakGlassReason:
		fmt.Fprintf(stderr, "--break-glass needs a real reason (at least %d characters): it is recorded and reviewed\n", config.MinBreakGlassReason)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: nedctl aws login [--account ID|NAME] [--role ROLE] [--device-code] [--force] [--format sh|powershell|none]")
		return ExitUsage
	}
	if *format != "sh" && *format != "powershell" && *format != "none" {
		fmt.Fprintf(stderr, "--format %q: want sh, powershell or none\n", *format)
		return ExitUsage
	}
	cfg, ok := loadAWSConfig(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}

	choices, managed, code := listChoices(ctx, cfg, *deviceCode, *force, *refresh, stderr)
	if code != ExitOK {
		return code
	}
	if *all {
		return breakGlassAll(ctx, cfg, managed, choices, strings.TrimSpace(*glass), stderr)
	}
	chosen, code := chooseAssignment(cfg, choices, *account, *role, stderr)
	if code != ExitOK {
		return code
	}
	profile, code := signInTo(ctx, cfg, managed, chosen, audit.Event{}, stderr)
	if code != ExitOK {
		return code
	}
	warnElevated(cfg, chosen, choices, stderr)
	if err := saveCurrentProfile(cfg, profile); err != nil {
		fmt.Fprintf(stderr, "warning: could not remember %s as your current profile: %v\n", profile, err)
	}
	printProfileEnv(stdout, *format, profile)
	return ExitOK
}

// listChoices signs in when needed and lists the caller's assignments with
// the squad and environment nedctl derives for each.
func listChoices(ctx context.Context, cfg config.Config, deviceCode, force, refresh bool, stderr io.Writer) ([]awsChoice, awssso.Managed, int) {
	a := cfg.AWS
	tok, managed, code := ensureSignIn(ctx, cfg, deviceCode, force, stderr)
	if code != ExitOK {
		return nil, managed, code
	}
	if !refresh {
		if cached, ok := loadAssignments(cfg, tok); ok {
			return classifyAll(cfg, cached), managed, ExitOK
		}
	}
	assignments, err := newPortal(a).Assignments(ctx, tok)
	if errors.Is(err, awssso.ErrUnauthorized) && !force {
		// Revoked server-side although the cache looked valid: sign in once more.
		if tok, managed, code = ensureSignIn(ctx, cfg, deviceCode, true, stderr); code != ExitOK {
			return nil, managed, code
		}
		assignments, err = newPortal(a).Assignments(ctx, tok)
	}
	if err != nil {
		fmt.Fprintf(stderr, "listing your Identity Center assignments: %v\n", err)
		fmt.Fprint(stderr, networkHint(err))
		return nil, managed, ExitFailure
	}
	saveAssignments(cfg, tok, assignments)
	return classifyAll(cfg, assignments), managed, ExitOK
}

func classifyAll(cfg config.Config, assignments []awssso.Assignment) []awsChoice {
	choices := make([]awsChoice, len(assignments))
	for i, as := range assignments {
		squad, env := cfg.AWS.Classify(as.AccountID, as.AccountName, cfg.Environments)
		choices[i] = awsChoice{as, squad, env}
	}
	return choices
}

// The account list is fetched once per sign-in: one call per account
// through the proxy adds up. It is reused while the sign-in that produced
// it is current (same token expiry) and holds no secret, only account
// names, IDs and role names; the token itself is never stored by nedctl.
type assignmentCache struct {
	StartURL      string              `json:"startUrl"`
	SignInExpires time.Time           `json:"signInExpires"`
	Assignments   []awssso.Assignment `json:"assignments"`
}

func assignmentCachePath(cfg config.Config) (string, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(log), "assignments-"+cfg.AWS.Session()+".json"), nil
}

func loadAssignments(cfg config.Config, tok awssso.Token) ([]awssso.Assignment, bool) {
	p, err := assignmentCachePath(cfg)
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var c assignmentCache
	if json.Unmarshal(data, &c) != nil || c.StartURL != cfg.AWS.StartURL || !c.SignInExpires.Equal(tok.ExpiresAt) || len(c.Assignments) == 0 {
		return nil, false
	}
	return c.Assignments, true
}

func saveAssignments(cfg config.Config, tok awssso.Token, as []awssso.Assignment) {
	p, err := assignmentCachePath(cfg)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(assignmentCache{StartURL: cfg.AWS.StartURL, SignInExpires: tok.ExpiresAt, Assignments: as}); err == nil {
		_ = writeFileAtomic(p, data, 0o600) // best effort: a cache must never fail a sign-in
	}
}

// breakGlassAll signs in to every account where the caller holds one of the
// configured break-glass roles. Identity Center decides who holds those
// roles; nedctl refuses to use any other role this way, records every
// sign-in as break-glass, and records a refused attempt too.
func breakGlassAll(ctx context.Context, cfg config.Config, m awssso.Managed, choices []awsChoice, reason string, stderr io.Writer) int {
	base := audit.Event{BreakGlass: true, BreakGlassReason: reason}
	var targets []awsChoice
	for _, c := range choices {
		if cfg.AWS.IsBreakGlassRole(c.Role) {
			targets = append(targets, c)
		}
	}
	if len(targets) == 0 {
		msg := "you hold no break-glass role in Identity Center"
		if len(cfg.AWS.BreakGlassRoles) == 0 {
			msg = "no break-glass roles are configured (aws.breakGlassRoles)"
		}
		ev := base
		ev.Action, ev.Cloud, ev.Detail = "aws-login", "aws", "break-glass sign-in to all accounts"
		if tr, err := beginAuditEvent(ctx, cfg, ev, stderr); err == nil {
			tr.end(ctx, audit.OutcomeRefused, "", msg, stderr)
		}
		fmt.Fprintln(stderr, "break-glass refused: "+msg)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "\n⚠  BREAK-GLASS: signing in to %d account(s) with %s.\n   Reason: %s\n   Every sign-in is recorded and flagged for review.\n\n",
		len(targets), strings.Join(cfg.AWS.BreakGlassRoles, ", "), reason)
	failed := 0
	for _, c := range targets {
		if _, code := signInTo(ctx, cfg, m, c, base, stderr); code != ExitOK {
			failed++
		}
		// signInTo saved the profile; reload so the next save keeps it.
		if path, err := awssso.ConfigPath(); err == nil {
			if fresh, err := awssso.LoadManaged(path); err == nil {
				m = fresh
			}
		}
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "%d of %d break-glass sign-ins failed — see above\n", failed, len(targets))
		return ExitFailure
	}
	fmt.Fprintf(stderr, "break-glass: signed in to %d account(s); use a profile with --profile or AWS_PROFILE\n", len(targets))
	return ExitOK
}

func defaultEnvFormat() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "sh"
}

func printProfileEnv(w io.Writer, format, profile string) {
	switch format {
	case "sh":
		fmt.Fprintf(w, "export AWS_PROFILE='%s'\n", profile)
	case "powershell":
		fmt.Fprintf(w, "$env:AWS_PROFILE = '%s'\n", profile)
	}
}

// ensureSignIn makes sure the managed sso-session exists and a valid
// Identity Center sign-in is cached, running `aws sso login` when needed.
func ensureSignIn(ctx context.Context, cfg config.Config, deviceCode, force bool, stderr io.Writer) (awssso.Token, awssso.Managed, int) {
	a := cfg.AWS
	path, err := awssso.ConfigPath()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return awssso.Token{}, awssso.Managed{}, ExitFailure
	}
	m, err := awssso.LoadManaged(path)
	if err != nil {
		fmt.Fprintf(stderr, "reading %s: %v\n", path, err)
		return awssso.Token{}, m, ExitFailure
	}
	want := awssso.Session{Name: a.Session(), StartURL: a.StartURL, Region: a.SSORegion}
	if m.Session != want {
		m.Session = want
		if err := awssso.SaveManaged(path, m); err != nil {
			fmt.Fprintf(stderr, "writing %s: %v\n", path, err)
			return awssso.Token{}, m, ExitFailure
		}
	}
	dir, err := awssso.CacheDir()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return awssso.Token{}, m, ExitFailure
	}
	if !force {
		if tok, err := awssso.ReadToken(dir, a.Session(), now(), tokenMargin); err == nil {
			return tok, m, ExitOK
		}
	}
	args := []string{"sso", "login", "--sso-session", a.Session()}
	if deviceCode {
		args = append(args, "--use-device-code")
	}
	fmt.Fprintln(stderr, "Signing in to IAM Identity Center — approve the request in your browser.")
	// stdout stays clean for `eval "$(nedctl aws login)"`; the CLI's
	// instructions go to the terminal on stderr.
	if err := execx.Interactive(ctx, execx.Spec{Name: "aws", Args: args, Stdout: stderr, Stderr: stderr, Timeout: 15 * time.Minute}); err != nil {
		fmt.Fprintf(stderr, "sign-in failed: %v\n", err)
		return awssso.Token{}, m, ExitFailure
	}
	tok, err := awssso.ReadToken(dir, a.Session(), now(), tokenMargin)
	if err != nil {
		fmt.Fprintf(stderr, "sign-in did not leave a valid token in %s: %v\n", dir, err)
		return awssso.Token{}, m, ExitFailure
	}
	return tok, m, ExitOK
}

// chooseAssignment narrows by --account/--role, then asks with the picker
// when more than one remains. It never guesses.
func chooseAssignment(cfg config.Config, all []awsChoice, account, role string, stderr io.Writer) (awsChoice, int) {
	var cands []awsChoice
	for _, c := range all {
		if account != "" && c.AccountID != account && !strings.EqualFold(c.AccountName, account) &&
			!strings.EqualFold(config.StripAccountTag(c.AccountName), account) {
			continue
		}
		if role != "" && !strings.EqualFold(c.Role, role) {
			continue
		}
		cands = append(cands, c)
	}
	switch {
	case len(all) == 0:
		fmt.Fprintln(stderr, "Identity Center assigns you no accounts")
		return awsChoice{}, ExitFailure
	case len(cands) == 0:
		fmt.Fprintf(stderr, "none of your %d assignments matches --account %q --role %q\n", len(all), account, role)
		return awsChoice{}, ExitFailure
	case len(cands) == 1:
		return cands[0], ExitOK
	case !stdinIsTerminal():
		fmt.Fprintf(stderr, "%d assignments match — pass --account and --role to choose one without a terminal\n", len(cands))
		return awsChoice{}, ExitUsage
	}
	sortChoices(cfg, cands)
	rows := make([]picker.Row, len(cands))
	for i, c := range cands {
		role := c.Role
		var cellColor map[int]string
		if cfg.AWS.Elevated(c.Role) {
			role += " ▲"
			cellColor = map[int]string{4: elevatedColor}
		}
		rows[i] = picker.Row{Cells: []string{firstNonBlank(c.Environment, "?"), c.Squad, config.StripAccountTag(c.AccountName), c.AccountID, role},
			Color: cfg.ColorFor(c.Environment), ColorCol: 0, CellColor: cellColor}
	}
	color := colorOn(stderr)
	idx, err := picker.Picker{Title: fmt.Sprintf("Pick an account and role · %d available", len(cands)),
		Header: []string{"ENV", "SQUAD", "ACCOUNT", "ID", "ROLE"}, Rows: rows, In: stdin, Out: stderr,
		Color: color, Badge: true, Legend: envLegend(cfg, color)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return awsChoice{}, ExitFailure
	}
	return cands[idx], ExitOK
}

// signInTo writes the profile for one assignment, verifies the AWS CLI acts
// in that account, and records the sign-in. base carries extra audit fields
// (break-glass). It returns the profile name.
func signInTo(ctx context.Context, cfg config.Config, m awssso.Managed, c awsChoice, base audit.Event, stderr io.Writer) (string, int) {
	a := cfg.AWS
	name := awssso.ProfileName(a.Prefix(), c.Assignment)
	m.Profiles[name] = awssso.Profile{Name: name, AccountID: c.AccountID, Role: c.Role, Region: a.ProfileRegion(),
		Squad: c.Squad, Environment: c.Environment}
	path, err := awssso.ConfigPath()
	if err == nil {
		err = awssso.SaveManaged(path, m)
	}
	if err != nil {
		fmt.Fprintf(stderr, "writing the AWS profile: %v\n", err)
		return "", ExitFailure
	}

	base.Action, base.Cloud, base.Account, base.Environment = "aws-login", "aws", c.AccountID, c.Environment
	base.Production = cfg.IsProdEnvironment(c.Environment)
	base.Detail = fmt.Sprintf("account %s, role %s, profile %s", c.AccountName, c.Role, name)
	if a.Elevated(c.Role) {
		base.Detail += ", elevated role"
	}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to sign in: every sign-in must be recorded\n", err)
		return "", ExitFailure
	}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "sts", "get-caller-identity", "--profile", name, "--output", "json")
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
		fmt.Fprintf(stderr, "verifying the sign-in to %s: %v\n", c.AccountName, err)
		return "", ExitFailure
	}
	var id struct{ Account, Arn string }
	if err := json.Unmarshal(out, &id); err != nil || id.Account != c.AccountID {
		msg := fmt.Sprintf("profile %s acts in account %q, not %s — refusing it", name, id.Account, c.AccountID)
		tr.end(ctx, audit.OutcomeRefused, id.Arn, msg, stderr)
		fmt.Fprintln(stderr, msg)
		return "", ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, id.Arn, base.Detail, stderr)

	label := fmt.Sprintf("%s · %s · %s", firstNonBlank(c.Squad, config.StripAccountTag(c.AccountName)), strings.ToUpper(firstNonBlank(c.Environment, "unknown env")), c.Role)
	if colorOn(stderr) {
		label = picker.Paint(cfg.ColorFor(c.Environment), label)
	}
	fmt.Fprintf(stderr, "Signed in: %s (profile %s)\n", label, name)
	return name, ExitOK
}

// elevatedColor marks roles that can change resources.
const elevatedColor = "#f08a24"

// envOrder ranks environments for sorting: the configured order, else
// dev, ete, qa, prod; unknown last.
func envOrder(cfg config.Config, env string) int {
	order := cfg.Environments
	if len(order) == 0 {
		order = config.DefaultEnvironmentWords
	}
	for i, e := range order {
		if strings.EqualFold(e, env) {
			return i
		}
	}
	return len(order)
}

func sortChoices(cfg config.Config, cs []awsChoice) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if oa, ob := envOrder(cfg, a.Environment), envOrder(cfg, b.Environment); oa != ob {
			return oa < ob
		}
		if a.Squad != b.Squad {
			return a.Squad < b.Squad
		}
		if a.AccountName != b.AccountName {
			return a.AccountName < b.AccountName
		}
		return a.Role < b.Role
	})
}

// envLegend explains the badges and the elevated mark.
func envLegend(cfg config.Config, color bool) string {
	order := cfg.Environments
	if len(order) == 0 {
		order = []string{"dev", "ete", "qa", "prod"}
	}
	var parts []string
	for _, e := range order {
		tag := " " + strings.ToUpper(e) + " "
		if color {
			tag = picker.Badge(cfg.ColorFor(e), tag)
		}
		if cfg.IsProdEnvironment(e) {
			tag += " production"
		}
		parts = append(parts, tag)
	}
	mark := "▲ elevated: can change and delete resources"
	if color {
		mark = picker.Paint(elevatedColor, mark)
	}
	return strings.Join(parts, "  ") + "    " + mark
}

// warnElevated tells the engineer they hold an elevated role and whether a
// read-only alternative is assigned to them in the same account.
func warnElevated(cfg config.Config, c awsChoice, all []awsChoice, stderr io.Writer) {
	if !cfg.AWS.Elevated(c.Role) {
		return
	}
	head := fmt.Sprintf("▲ %s has ELEVATED access: it can change and delete resources in %s.", c.Role, firstNonBlank(c.Squad, config.StripAccountTag(c.AccountName)))
	if colorOn(stderr) {
		head = picker.Paint(elevatedColor, head)
	}
	fmt.Fprintln(stderr, head)
	var alts []string
	for _, o := range all {
		if o.AccountID == c.AccountID && o.Role != c.Role && !cfg.AWS.Elevated(o.Role) {
			alts = append(alts, o.Role)
		}
	}
	if len(alts) > 0 {
		fmt.Fprintf(stderr, "  For looking around, prefer: %s  (nedctl aws login --account %s --role %s)\n", strings.Join(alts, ", "), c.AccountID, alts[0])
	} else {
		fmt.Fprintln(stderr, "  No read-only role is assigned to you in this account; use this one for changes only.")
	}
	if cfg.IsProdEnvironment(c.Environment) {
		fmt.Fprintln(stderr, "  This is a PRODUCTION account.")
	}
}

func firstNonBlank(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// currentProfilePath remembers the last profile signed in to, so a new
// terminal tab (or `nedctl shell`) can use it without exporting anything.
func currentProfilePath(cfg config.Config) (string, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(log), "aws-profile"), nil
}

func saveCurrentProfile(cfg config.Config, profile string) error {
	p, err := currentProfilePath(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p, []byte(profile+"\n"), 0o600)
}

// resolveProfile picks the profile a command acts with: --profile, then
// $AWS_PROFILE, then the last `nedctl aws login`.
func resolveProfile(cfg config.Config, flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return p
	}
	if p, err := currentProfilePath(cfg); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// awsIdentity is `aws whoami`'s answer.
type awsIdentity struct {
	Profile     string `json:"profile"`
	Account     string `json:"account"`
	AccountName string `json:"accountName,omitempty"`
	Squad       string `json:"squad,omitempty"`
	Environment string `json:"environment,omitempty"`
	Production  bool   `json:"production"`
	Role        string `json:"role,omitempty"`
	Elevated    bool   `json:"elevated"`
	Arn         string `json:"arn"`
	// SignInExpires is when the Identity Center sign-in lapses (managed
	// profiles only).
	SignInExpires string `json:"signInExpires,omitempty"`
}

func awsWhoami(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aws whoami", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to check (default: $AWS_PROFILE, then the last `nedctl aws login`)")
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	profile := resolveProfile(cfg, *profileFlag)
	if profile == "" {
		fmt.Fprintln(stderr, "no profile selected — run `nedctl aws login`, or pass --profile")
		return ExitFailure
	}
	id := awsIdentity{Profile: profile}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "sts", "get-caller-identity", "--profile", profile, "--output", "json")
	if err != nil {
		fmt.Fprintf(stderr, "%s is not usable: %v\n→ sign in again with `nedctl aws login`\n", profile, err)
		return ExitFailure
	}
	var sts struct{ Account, Arn string }
	if err := json.Unmarshal(out, &sts); err != nil {
		fmt.Fprintf(stderr, "parsing aws sts get-caller-identity: %v\n", err)
		return ExitFailure
	}
	id.Account, id.Arn = sts.Account, sts.Arn
	if path, err := awssso.ConfigPath(); err == nil {
		if m, err := awssso.LoadManaged(path); err == nil {
			if p, ok := m.Profiles[profile]; ok {
				id.Role, id.Squad, id.Environment = p.Role, p.Squad, p.Environment
				id.Elevated = cfg.AWS.Elevated(p.Role)
				id.Production = cfg.IsProdEnvironment(p.Environment)
				if dir, err := awssso.CacheDir(); err == nil {
					if tok, err := awssso.ReadToken(dir, m.Session.Name, now(), 0); err == nil {
						id.SignInExpires = tok.ExpiresAt.UTC().Format(time.RFC3339)
					}
				}
			}
		}
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, id)
	}
	env := id.Environment
	if env != "" && colorOn(stdout) {
		env = picker.Paint(cfg.ColorFor(id.Environment), strings.ToUpper(env))
	}
	fmt.Fprintf(stdout, "profile:    %s\naccount:    %s", id.Profile, id.Account)
	if id.Squad != "" || env != "" {
		fmt.Fprintf(stdout, " (%s)", strings.Trim(id.Squad+" · "+env, " ·"))
	}
	fmt.Fprintln(stdout)
	if id.Role != "" {
		role := id.Role
		if id.Elevated {
			role += "  ▲ ELEVATED — can change and delete resources"
			if colorOn(stdout) {
				role = id.Role + "  " + picker.Paint(elevatedColor, "▲ ELEVATED — can change and delete resources")
			}
		}
		fmt.Fprintf(stdout, "role:       %s\n", role)
	}
	fmt.Fprintf(stdout, "acting as:  %s\n", id.Arn)
	if id.SignInExpires != "" {
		exp, _ := time.Parse(time.RFC3339, id.SignInExpires)
		left := exp.Sub(now()).Round(time.Minute)
		if left > 0 {
			fmt.Fprintf(stdout, "sign-in:    valid for %s (until %s UTC)\n", left, exp.Format("15:04"))
		} else {
			fmt.Fprintln(stdout, "sign-in:    EXPIRED — run `nedctl aws login`")
		}
	}
	return ExitOK
}

// credentialKeys are the only variables `aws env` passes on.
var credentialKeys = map[string]bool{
	"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_CREDENTIAL_EXPIRATION": true,
}

// exportCredentials asks the AWS CLI for a profile's current short-term
// credentials, as KEY=VALUE entries, for tools that cannot use a profile
// (sm, SSMshell). The values are secrets: callers hand them to a child
// process or print them on request, and never log them.
func exportCredentials(ctx context.Context, cfg config.Config, profile string) ([]string, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "configure", "export-credentials", "--profile", profile, "--format", "env-no-export")
	if err != nil {
		return nil, err
	}
	var env []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || !credentialKeys[k] || strings.ContainsAny(v, "'\"\\ \t\r\n;$`") {
			return nil, fmt.Errorf("unexpected output from aws configure export-credentials")
		}
		env = append(env, k+"="+v)
	}
	if len(env) < 2 {
		return nil, fmt.Errorf("aws configure export-credentials returned no credentials")
	}
	return env, nil
}

func awsEnv(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aws env", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to export (default: $AWS_PROFILE, then the last `nedctl aws login`)")
	format := fs.String("format", defaultEnvFormat(), "sh or powershell")
	show := fs.Bool("show", false, "print the keys even when stdout is a terminal (they would be visible on screen)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *format != "sh" && *format != "powershell" {
		fmt.Fprintf(stderr, "--format %q: want sh or powershell\n", *format)
		return ExitUsage
	}
	if f, ok := stdout.(*os.File); ok && isTerminal(f) && !*show {
		fmt.Fprintln(stderr, "refusing to print credentials on the screen — use it as  eval \"$(nedctl aws env)\"  (or pass --show)")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	profile := resolveProfile(cfg, *profileFlag)
	if profile == "" {
		fmt.Fprintln(stderr, "no profile selected — run `nedctl aws login`, or pass --profile")
		return ExitFailure
	}
	tr, err := beginAuditEvent(ctx, cfg, audit.Event{Action: "aws-export-credentials", Cloud: "aws", Detail: "profile " + profile}, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to export credentials: every export must be recorded\n", err)
		return ExitFailure
	}
	env, err := exportCredentials(ctx, cfg, profile)
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
		fmt.Fprintf(stderr, "exporting credentials for %s: %v\n", profile, err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, "", "profile "+profile, stderr)
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if *format == "powershell" {
			fmt.Fprintf(stdout, "$env:%s = '%s'\n", k, v)
		} else {
			fmt.Fprintf(stdout, "export %s='%s'\n", k, v)
		}
	}
	return ExitOK
}

// networkHint explains the two failures a corporate network usually causes —
// a call that hangs because it is not going through the proxy, and a TLS
// error because a proxy re-signs traffic with a corporate CA — and what to
// set. It returns "" for any other error.
func networkHint(err error) string {
	msg := err.Error()
	proxy := firstNonBlank(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy"))
	switch {
	case strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "deadline exceeded") || strings.Contains(msg, "i/o timeout"):
		if proxy == "" {
			return "→ the call timed out and HTTPS_PROXY is not set: if the AWS CLI works here through a proxy, export the same HTTPS_PROXY (and NO_PROXY) for nedctl\n" +
				"→ run with NEDCTL_DEBUG=1 to see each request and the route it takes\n"
		}
		return "→ the call timed out going through HTTPS_PROXY; check the proxy allows the Identity Center portal (portal.sso.<region>.amazonaws.com)\n" +
			"→ run with NEDCTL_DEBUG=1 to see each request and the route it takes\n"
	case strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate"):
		return "→ TLS could not be verified: behind a TLS-inspecting proxy, trust the corporate root CA — export SSL_CERT_FILE=<the bundle AWS_CA_BUNDLE points at>, or add it to the system store (update-ca-certificates)\n"
	}
	return ""
}
