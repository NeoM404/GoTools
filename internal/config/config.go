// Package config loads nedctl configuration and locates the fleet inventory.
//
// Config is JSON (stdlib only). Resolution order for the config file:
//  1. --config flag
//  2. $NEDCTL_CONFIG
//  3. $XDG_CONFIG_HOME/nedctl/config.json  (or ~/.config/nedctl/config.json)
//  4. ./nedctl.json
//
// If no config is found, sensible zero-value defaults are used so `nedctl
// doctor` and `--help` still work out of the box.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"nedctl/internal/support"

	"nedctl/internal/rx"
)

// DefaultCommandTimeout bounds a cloud CLI call when the config sets none.
// Credential fetches are normally seconds; two minutes absorbs a slow SSO
// token refresh without letting a hung CLI stall a shell or CI job forever.
const DefaultCommandTimeout = 2 * time.Minute

// Config controls where the fleet inventory comes from and which contexts are
// treated as production (for the safety guard).
type Config struct {
	// Mode is where nedctl runs: "workstation" (default) fetches credentials
	// through the aws/az CLIs; "bastion" runs on a jump host whose kubeconfig
	// the platform already provisions, so nedctl only selects contexts and
	// never needs a cloud CLI. See ModeBastion.
	Mode string `json:"mode"`

	// InventoryPath is a local JSON file produced by the IaC pipeline
	// (e.g. `terraform output -json fleet`). Used when InventoryURL is empty.
	InventoryPath string `json:"inventoryPath"`

	// InventoryURL is an HTTPS endpoint returning the same JSON. Preferred in
	// production so every engineer sees the same live fleet. TLS is required.
	InventoryURL string `json:"inventoryUrl"`

	// ProdPatterns are regular expressions; a cluster or kube-context whose
	// name matches any of them is treated as production by `nedctl guard`,
	// in addition to any cluster whose inventory Environment == "prod".
	ProdPatterns []string `json:"prodPatterns"`

	// KubeconfigDir is where per-cluster kubeconfigs are written. Empty means
	// the standard KUBECONFIG / ~/.kube/config behaviour of the cloud CLIs.
	KubeconfigDir string `json:"kubeconfigDir"`

	// TargetKubeVersion is the fleet's desired minor version (e.g. "1.30").
	// `nedctl fleet versions` flags anything more than one minor behind.
	TargetKubeVersion string `json:"targetKubeVersion"`

	// MinVersions overrides the built-in `doctor` version floors by tool name,
	// e.g. {"kubectl": "1.29", "aws": "2.15"}. Lets the team raise the bar
	// centrally without a nedctl release.
	MinVersions map[string]string `json:"minVersions"`

	// CommandTimeout bounds each cloud CLI call (aws/az), as a Go duration
	// string such as "90s" or "3m". Empty means DefaultCommandTimeout.
	CommandTimeout string `json:"commandTimeout"`

	// Environments, when set, is the allow-list every inventory cluster's
	// environment must be on (e.g. ["dev","ete","qa","prod"]), so a typo
	// such as "prd" is caught at load time instead of dodging prod checks.
	Environments []string `json:"environments"`

	// ProdEnvironments are the inventory environments treated as production
	// by guard, current and login (default ["prod"]). A kube-context that
	// resolves to a cluster in one of these is production whatever its name.
	ProdEnvironments []string `json:"prodEnvironments"`

	// InventoryCacheTTL is how long guard/current reuse a cached copy of an
	// inventoryUrl before refetching (Go duration, default "10m"), so a shell
	// prompt never waits on the network. Other commands always fetch live.
	InventoryCacheTTL string `json:"inventoryCacheTTL"`

	// Discovery is the cloud scope `inventory sync` and `inventory diff` scan.
	Discovery Discovery `json:"discovery"`

	// TargetKubeVersions sets the drift target per environment, e.g.
	// {"prod": "1.29", "uat": "1.30"}, because prod deliberately lags.
	// Environments not listed fall back to TargetKubeVersion.
	TargetKubeVersions map[string]string `json:"targetKubeVersions"`

	// SupportCalendar is each minor version's end of standard and extended
	// support, per cloud, for `fleet eol`. Generate the AWS part with
	// `nedctl fleet calendar aws`.
	SupportCalendar support.Calendar `json:"supportCalendar"`

	// CostRates are control-plane prices used to estimate the
	// extended-support premium. Optional; set them from your own pricing.
	CostRates support.Rates `json:"costRates"`

	// Audit controls the credential-access audit trail. It is always on;
	// this only chooses where it goes.
	Audit Audit `json:"audit"`

	// ChangeControl gates credential fetches on a change record.
	ChangeControl ChangeControl `json:"changeControl"`

	// AWS configures IAM Identity Center sign-in and the EC2/EKS access
	// commands (`nedctl aws`, `shell`, `connect`).
	AWS AWS `json:"aws"`

	// EnvironmentColors maps an environment to a #rrggbb colour for pickers,
	// terminal tabs and the prompt. Defaults: dev green, ete orange, qa blue,
	// prod red.
	EnvironmentColors map[string]string `json:"environmentColors"`

	// WindowsTerminal is the path to wt.exe for --tab, when it is not on
	// PATH (WSL without the Windows PATH). A C:\ path works from WSL.
	WindowsTerminal string `json:"windowsTerminal"`

	// ReleaseURL is the HTTPS address of latest.json, which the release
	// pipeline publishes next to the binaries; `nedctl version --check`
	// compares against it. Usually part of the built-in defaults.
	ReleaseURL string `json:"releaseUrl"`
}

// DefaultEnvironmentColors matches the colours engineers already know from
// the SSM tooling.
var DefaultEnvironmentColors = map[string]string{
	"dev": "#22c55e", "ete": "#f97316", "qa": "#3b82f6", "prod": "#ef4444",
}

// ColorFor returns the colour for an environment ("" when none).
func (c Config) ColorFor(env string) string {
	env = strings.ToLower(strings.TrimSpace(env))
	for k, v := range c.EnvironmentColors {
		if strings.EqualFold(k, env) {
			return v
		}
	}
	return DefaultEnvironmentColors[env]
}

// AWS is the IAM Identity Center and EC2/EKS access configuration.
type AWS struct {
	// StartURL is the Identity Center access portal, e.g.
	// https://d-xxxxxxxxxx.awsapps.com/start. Required for `nedctl aws`.
	StartURL string `json:"startUrl"`
	// SSORegion is the Identity Center region.
	SSORegion string `json:"ssoRegion"`
	// SSOSession names the [sso-session] nedctl writes (default "nedctl").
	SSOSession string `json:"ssoSession"`
	// Region is the default region of generated profiles (default SSORegion).
	// Commands that look for clusters or instances search regions themselves
	// (see Regions), so most users never set it.
	Region string `json:"region"`
	// Regions, when set, is the exact list of regions commands search.
	// Empty: each account's enabled regions, narrowed by what was found
	// before.
	Regions []string `json:"regions"`
	// ProfilePrefix starts every generated profile name (default "nedctl").
	ProfilePrefix string `json:"profilePrefix"`
	// AccountNamePattern derives squad and environment from an account's
	// name: a regex with named groups (?P<env>…) and optionally (?P<squad>…).
	AccountNamePattern string `json:"accountNamePattern"`
	// Accounts gives squad/environment explicitly, overriding the pattern.
	Accounts []AWSAccount `json:"accounts"`
	// BreakGlassRoles are the Identity Center roles (permission sets) that
	// `aws login --all` may use. Identity Center decides who holds them;
	// nedctl only refuses to sign in to every account with anything else.
	BreakGlassRoles []string `json:"breakGlassRoles"`
	// SessionTimeout bounds an interactive sign-in or shell (default "12h").
	SessionTimeout string `json:"sessionTimeout"`
	// AccessLevelTag is the EC2 tag holding an instance's access level
	// (default "AccessLevel"), shown in the instance picker.
	AccessLevelTag string `json:"accessLevelTag"`
	// LegacyTool is the existing SSM tool `shell --via legacy` launches
	// already signed in (default "sm"; e.g. "AWS-EC2-SSMshell.exe").
	LegacyTool string `json:"legacyTool"`
	// ElevatedRolePattern marks roles (permission sets) that can change
	// resources, so engineers see when they hold one. Default:
	// DefaultElevatedRolePattern.
	ElevatedRolePattern string `json:"elevatedRolePattern"`
	// DevopsInstance is matched against instance names to find the hop for
	// `nedctl connect` (default "devops").
	DevopsInstance string `json:"devopsInstance"`
}

// DevopsName returns the devops-instance name match.
func (a AWS) DevopsName() string {
	if a.DevopsInstance == "" {
		return "devops"
	}
	return a.DevopsInstance
}

// LevelTag returns the access-level tag key.
func (a AWS) LevelTag() string {
	if a.AccessLevelTag == "" {
		return "AccessLevel"
	}
	return a.AccessLevelTag
}

// Legacy returns the existing SSM tool's command.
func (a AWS) Legacy() string {
	if a.LegacyTool == "" {
		return "sm"
	}
	return a.LegacyTool
}

// AWSAccount is explicit metadata for one account.
type AWSAccount struct {
	ID          string `json:"id"`
	Squad       string `json:"squad"`
	Environment string `json:"environment"`
}

// DefaultAWSSessionTimeout bounds interactive AWS commands.
const DefaultAWSSessionTimeout = 12 * time.Hour

// Configured reports whether Identity Center sign-in is set up.
func (a AWS) Configured() bool { return a.StartURL != "" }

// Session returns the sso-session name.
func (a AWS) Session() string {
	if a.SSOSession == "" {
		return "nedctl"
	}
	return a.SSOSession
}

// Prefix returns the generated-profile prefix.
func (a AWS) Prefix() string {
	if a.ProfilePrefix == "" {
		return "nedctl"
	}
	return a.ProfilePrefix
}

// ProfileRegion returns the region for generated profiles.
func (a AWS) ProfileRegion() string {
	if a.Region == "" {
		return a.SSORegion
	}
	return a.Region
}

// Timeout returns the interactive-session bound.
func (a AWS) Timeout() time.Duration {
	d, err := parsePositive("aws.sessionTimeout", a.SessionTimeout, DefaultAWSSessionTimeout)
	if err != nil {
		return DefaultAWSSessionTimeout
	}
	return d
}

// Classify returns the squad and environment of an account: explicit
// metadata first, then the account-name pattern.
//
// Without either, it reads the name itself: an optional leading "[TAG]" is
// dropped, the name is split on - _ . and spaces, the environment is the
// last part that is one of envs (the configured environments, or dev, ete,
// qa, prod, sit, uat), and the squad is what comes before it, less a
// leading "aws". So "[NONPROD] aws-mov-lms-dev" is squad mov-lms, env dev,
// with no configuration at all.
func (a AWS) Classify(id, name string, envs []string) (squad, env string) {
	for _, acct := range a.Accounts {
		if acct.ID == id {
			return acct.Squad, strings.ToLower(acct.Environment)
		}
	}
	if a.AccountNamePattern != "" {
		if re, err := rx.Compile(a.AccountNamePattern); err == nil {
			if m := re.FindStringSubmatch(name); m != nil {
				if i := re.SubexpIndex("squad"); i >= 0 {
					squad = m[i]
				}
				return squad, strings.ToLower(m[re.SubexpIndex("env")])
			}
		}
	}
	return inferFromName(name, envs)
}

// DefaultEnvironmentWords are recognised in account names when no
// environments are configured.
var DefaultEnvironmentWords = []string{"dev", "ete", "qa", "prod", "sit", "uat"}

var (
	accountTagRe   = regexp.MustCompile(`^\s*\[[^\]]*\]\s*`)
	nameSeparators = regexp.MustCompile(`[-_.\s]+`)
)

// StripAccountTag removes a leading "[TAG]" such as "[NONPROD] " from an
// account name.
func StripAccountTag(name string) string { return accountTagRe.ReplaceAllString(name, "") }

func inferFromName(name string, envs []string) (squad, env string) {
	if len(envs) == 0 {
		envs = DefaultEnvironmentWords
	}
	known := map[string]bool{}
	for _, e := range envs {
		known[strings.ToLower(e)] = true
	}
	parts := nameSeparators.Split(strings.TrimSpace(StripAccountTag(name)), -1)
	for i := len(parts) - 1; i >= 0; i-- {
		if !known[strings.ToLower(parts[i])] {
			continue
		}
		rest := parts[:i]
		if len(rest) > 0 && strings.EqualFold(rest[0], "aws") {
			rest = rest[1:]
		}
		return strings.ToLower(strings.Join(rest, "-")), strings.ToLower(parts[i])
	}
	return "", ""
}

// DefaultElevatedRolePattern matches role names that grant change rights.
const DefaultElevatedRolePattern = `(?i)(devops|admin|poweruser|power-user|break-?glass|fullaccess|full-access|owner|deploy)`

// Elevated reports whether a role can change resources, by its name.
func (a AWS) Elevated(role string) bool {
	p := a.ElevatedRolePattern
	if p == "" {
		p = DefaultElevatedRolePattern
	}
	re, err := rx.Compile(p)
	return err == nil && re.MatchString(role)
}

// IsBreakGlassRole reports whether role may be used by `aws login --all`.
func (a AWS) IsBreakGlassRole(role string) bool {
	for _, r := range a.BreakGlassRoles {
		if r == role {
			return true
		}
	}
	return false
}

var (
	sessionNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	iamRoleRe     = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	hexColorRe    = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
)

func (c Config) validateAWS() error {
	a := c.AWS
	var errs []error
	if a.StartURL != "" && !strings.HasPrefix(a.StartURL, "https://") {
		errs = append(errs, fmt.Errorf("aws.startUrl must be https"))
	}
	if a.StartURL != "" && !regionRe.MatchString(a.SSORegion) {
		errs = append(errs, fmt.Errorf("aws.ssoRegion %q is not an AWS region such as af-south-1", a.SSORegion))
	}
	if a.Region != "" && !regionRe.MatchString(a.Region) {
		errs = append(errs, fmt.Errorf("aws.region %q is not an AWS region", a.Region))
	}
	for _, r := range a.Regions {
		if !regionRe.MatchString(r) {
			errs = append(errs, fmt.Errorf("aws.regions: %q is not an AWS region such as af-south-1", r))
		}
	}
	if !sessionNameRe.MatchString(a.Session()) || !sessionNameRe.MatchString(a.Prefix()) {
		errs = append(errs, fmt.Errorf("aws.ssoSession and aws.profilePrefix may hold only letters, digits, - and _"))
	}
	if p := a.AccountNamePattern; p != "" {
		re, err := rx.Compile(p)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("aws.accountNamePattern: %w", err))
		case re.SubexpIndex("env") < 0:
			errs = append(errs, fmt.Errorf("aws.accountNamePattern %q needs a named group (?P<env>...)", p))
		}
	}
	allowed := map[string]bool{}
	for _, e := range c.Environments {
		allowed[strings.ToLower(e)] = true
	}
	for i, acct := range a.Accounts {
		if !accountRe.MatchString(acct.ID) {
			errs = append(errs, fmt.Errorf("aws.accounts[%d]: id %q must be a 12-digit AWS account ID", i, acct.ID))
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(acct.Environment)] {
			errs = append(errs, fmt.Errorf("aws.accounts[%d]: environment %q is not in environments %v", i, acct.Environment, c.Environments))
		}
	}
	if a.ElevatedRolePattern != "" {
		if _, err := regexp.Compile(a.ElevatedRolePattern); err != nil {
			errs = append(errs, fmt.Errorf("aws.elevatedRolePattern: %w", err))
		}
	}
	for _, r := range a.BreakGlassRoles {
		if !iamRoleRe.MatchString(r) {
			errs = append(errs, fmt.Errorf("aws.breakGlassRoles: %q is not an IAM role name", r))
		}
	}
	if c.ReleaseURL != "" && !strings.HasPrefix(c.ReleaseURL, "https://") {
		errs = append(errs, fmt.Errorf("releaseUrl must be https://"))
	}
	if strings.ContainsAny(c.WindowsTerminal, "\r\n") || strings.HasPrefix(c.WindowsTerminal, "-") {
		errs = append(errs, fmt.Errorf("windowsTerminal: invalid value"))
	}
	if strings.ContainsAny(a.AccessLevelTag+a.LegacyTool, "\r\n") || strings.HasPrefix(a.LegacyTool, "-") {
		errs = append(errs, fmt.Errorf("aws.accessLevelTag / aws.legacyTool: invalid value"))
	}
	if _, err := parsePositive("aws.sessionTimeout", a.SessionTimeout, DefaultAWSSessionTimeout); err != nil {
		errs = append(errs, err)
	}
	for env, col := range c.EnvironmentColors {
		if !hexColorRe.MatchString(col) {
			errs = append(errs, fmt.Errorf("environmentColors[%q] %q: want #rrggbb", env, col))
		}
	}
	return errors.Join(errs...)
}

// Run modes.
const (
	ModeWorkstation = "workstation"
	// ModeBastion: credentials are provisioned on the host (kubeconfig with
	// contexts already present); there may be no az/aws CLI and no internet.
	// `login` selects the cluster's existing context instead of fetching
	// credentials, and cloud discovery is left to the IaC pipeline.
	ModeBastion = "bastion"
)

// Bastion reports whether nedctl runs on a bastion host.
func (c Config) Bastion() bool { return strings.EqualFold(c.Mode, ModeBastion) }

func (c Config) validateMode() error {
	switch strings.ToLower(c.Mode) {
	case "", ModeWorkstation, ModeBastion:
		return nil
	}
	return fmt.Errorf("mode %q: want %q or %q", c.Mode, ModeWorkstation, ModeBastion)
}

// ChangeControl configures change-record checks for `kubeconfig`/`login`.
type ChangeControl struct {
	// Enabled switches change control off without removing its settings:
	// false means no change record is ever required and none is verified
	// against ServiceNow (one given is still format-checked and recorded).
	// Absent means on.
	Enabled *bool `json:"enabled"`
	// RequireFor lists environments whose clusters need --change-record
	// (or --break-glass). Empty: never required, still verified if given.
	RequireFor []string `json:"requireFor"`
	// Pattern is the change-number format (default ServiceNow ^CHG\d{7}$).
	Pattern string `json:"pattern"`
	// ServiceNow, when InstanceURL is set, verifies each change record.
	ServiceNow ServiceNowConfig `json:"serviceNow"`
}

// ServiceNowConfig locates the ServiceNow Table API.
type ServiceNowConfig struct {
	InstanceURL string `json:"instanceUrl"`
	// TokenEnv names the environment variable holding the API token; the
	// token is never stored in config.
	TokenEnv      string   `json:"tokenEnv"`
	Scheme        string   `json:"scheme"`        // default "Bearer"
	AllowedStates []string `json:"allowedStates"` // default Scheduled, Implement
	Timeout       string   `json:"timeout"`       // default "10s"
}

// DefaultServiceNowTimeout bounds one change-record lookup.
const DefaultServiceNowTimeout = 10 * time.Second

// MinBreakGlassReason is the shortest acceptable break-glass justification.
const MinBreakGlassReason = 20

// Requires reports whether env needs a change record.
func (c ChangeControl) Requires(env string) bool {
	return c.On() && c.Listed(env)
}

// On reports whether change control is enabled.
func (c ChangeControl) On() bool { return c.Enabled == nil || *c.Enabled }

// Listed reports whether env is in RequireFor, whether or not change
// control is on.
func (c ChangeControl) Listed(env string) bool {
	for _, e := range c.RequireFor {
		if strings.EqualFold(e, strings.TrimSpace(env)) {
			return true
		}
	}
	return false
}

// SNOWTimeout returns the effective ServiceNow timeout.
func (s ServiceNowConfig) SNOWTimeout() time.Duration {
	d, err := parsePositive("changeControl.serviceNow.timeout", s.Timeout, DefaultServiceNowTimeout)
	if err != nil {
		return DefaultServiceNowTimeout
	}
	return d
}

func (c Config) validateChangeControl() error {
	cc := c.ChangeControl
	var errs []error
	if cc.Pattern != "" {
		if _, err := regexp.Compile(cc.Pattern); err != nil {
			errs = append(errs, fmt.Errorf("changeControl.pattern: %w", err))
		}
	}
	allowed := map[string]bool{}
	for _, e := range c.Environments {
		allowed[strings.ToLower(e)] = true
	}
	for _, e := range cc.RequireFor {
		if len(allowed) > 0 && !allowed[strings.ToLower(e)] {
			errs = append(errs, fmt.Errorf("changeControl.requireFor has %q, which is not in environments %v — no cluster could ever require a change record", e, c.Environments))
		}
	}
	if s := cc.ServiceNow; s.InstanceURL != "" {
		if !strings.HasPrefix(s.InstanceURL, "https://") {
			errs = append(errs, fmt.Errorf("changeControl.serviceNow.instanceUrl must be https"))
		}
		if s.TokenEnv == "" {
			errs = append(errs, fmt.Errorf("changeControl.serviceNow.tokenEnv is required: name the environment variable holding the API token (never put the token in config)"))
		}
		if _, err := parsePositive("changeControl.serviceNow.timeout", s.Timeout, DefaultServiceNowTimeout); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Audit configures the audit trail.
type Audit struct {
	// LogPath is the local hash-chained log. Default:
	// $XDG_STATE_HOME/nedctl/audit.jsonl (~/.local/state/nedctl/audit.jsonl).
	LogPath string `json:"logPath"`
	// Forward, when URL is set, sends each event to a SIEM collector.
	Forward AuditForward `json:"forward"`
}

// AuditForward is an HTTPS event collector (e.g. Splunk HEC).
type AuditForward struct {
	URL string `json:"url"`
	// TokenEnv names the environment variable holding the collector token.
	// The token itself is never stored in config.
	TokenEnv string `json:"tokenEnv"`
	Scheme   string `json:"scheme"`  // Authorization scheme; default "Bearer" ("Splunk" for HEC)
	Format   string `json:"format"`  // "json" (default) or "splunk-hec"
	Timeout  string `json:"timeout"` // default "5s"
}

// DefaultAuditForwardTimeout bounds one delivery to the collector.
const DefaultAuditForwardTimeout = 5 * time.Second

// AuditLogPath returns the effective local audit log path.
func (c Config) AuditLogPath() (string, error) {
	if c.Audit.LogPath != "" {
		return c.Audit.LogPath, nil
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home directory for the audit log: %w", err)
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "nedctl", "audit.jsonl"), nil
}

// ForwardTimeout returns the effective collector timeout.
func (a AuditForward) ForwardTimeout() time.Duration {
	d, err := parsePositive("audit.forward.timeout", a.Timeout, DefaultAuditForwardTimeout)
	if err != nil {
		return DefaultAuditForwardTimeout
	}
	return d
}

func (a Audit) validate() error {
	f := a.Forward
	if f.URL == "" {
		return nil
	}
	var errs []error
	if !strings.HasPrefix(f.URL, "https://") {
		errs = append(errs, fmt.Errorf("audit.forward.url must be https"))
	}
	if f.TokenEnv == "" {
		errs = append(errs, fmt.Errorf("audit.forward.tokenEnv is required: name the environment variable holding the collector token (never put the token in config)"))
	}
	switch f.Format {
	case "", "json", "splunk-hec":
	default:
		errs = append(errs, fmt.Errorf("audit.forward.format %q: want json or splunk-hec", f.Format))
	}
	if _, err := parsePositive("audit.forward.timeout", f.Timeout, DefaultAuditForwardTimeout); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// TargetFor returns the drift target for an environment ("" if none).
func (c Config) TargetFor(env string) string {
	for k, v := range c.TargetKubeVersions {
		if strings.EqualFold(k, strings.TrimSpace(env)) {
			return v
		}
	}
	return c.TargetKubeVersion
}

// HasTargets reports whether any drift target is configured.
func (c Config) HasTargets() bool { return c.TargetKubeVersion != "" || len(c.TargetKubeVersions) > 0 }

// DefaultInventoryCacheTTL is used when inventoryCacheTTL is unset.
const DefaultInventoryCacheTTL = 10 * time.Minute

// ProdEnvs returns the production environments, defaulting to ["prod"].
func (c Config) ProdEnvs() []string {
	if len(c.ProdEnvironments) == 0 {
		return []string{"prod"}
	}
	return c.ProdEnvironments
}

// IsProdEnvironment reports whether env is a production environment.
func (c Config) IsProdEnvironment(env string) bool {
	for _, p := range c.ProdEnvs() {
		if strings.EqualFold(strings.TrimSpace(env), p) {
			return true
		}
	}
	return false
}

// CacheTTL returns the effective inventory cache TTL.
func (c Config) CacheTTL() time.Duration {
	d, err := parsePositive("inventoryCacheTTL", c.InventoryCacheTTL, DefaultInventoryCacheTTL)
	if err != nil {
		return DefaultInventoryCacheTTL
	}
	return d
}

// Discovery defines exactly which cloud scopes are scanned. It is explicit so
// it can be reviewed and audited: nedctl never guesses which accounts or
// subscriptions exist, and a completeness claim is only ever made for these.
type Discovery struct {
	AWS   []AWSTarget   `json:"aws"`
	Azure []AzureTarget `json:"azure"`
	// Concurrency caps how many cloud CLI processes run at once across the
	// whole scan. Default DefaultConcurrency; at most MaxConcurrency.
	Concurrency int `json:"concurrency"`
	// TagKeys names the cloud tags that carry inventory metadata.
	TagKeys TagKeys `json:"tagKeys"`
	// NameEnvironmentPattern derives a cluster's environment from its name
	// when it has no environment tag: a regex with a named group "env", e.g.
	// `^.+-k8s-(?P<env>[a-z]+)-cluster$`. The tag always wins when present.
	NameEnvironmentPattern string `json:"nameEnvironmentPattern"`
}

// EnvFromName returns the environment encoded in name by
// NameEnvironmentPattern, or "" if there is no pattern or no match. Load has
// already rejected an invalid pattern.
func (d Discovery) EnvFromName(name string) string {
	if d.NameEnvironmentPattern == "" {
		return ""
	}
	re, err := rx.Compile(d.NameEnvironmentPattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[re.SubexpIndex("env")])
}

// AWSTarget is one AWS account, scanned in each listed region.
type AWSTarget struct {
	// Profile is the AWS CLI profile to use; empty means the default
	// credential chain.
	Profile string `json:"profile"`
	// Account is the 12-digit account the profile must resolve to. It is
	// verified before scanning, so a misconfigured profile is refused rather
	// than silently scanning the wrong account.
	Account string   `json:"account"`
	Regions []string `json:"regions"`
}

// AzureTarget is one Azure subscription, by name or ID.
type AzureTarget struct {
	Subscription string `json:"subscription"`
}

// TagKeys maps inventory fields to the cloud tag keys that carry them.
type TagKeys struct {
	Environment string `json:"environment"`
	Owner       string `json:"owner"`
	CostCentre  string `json:"costCentre"`
}

// Discovery defaults and limits.
const (
	DefaultConcurrency = 8
	MaxConcurrency     = 64
)

// Configured reports whether any scan scope is defined.
func (d Discovery) Configured() bool { return len(d.AWS) > 0 || len(d.Azure) > 0 }

// Workers returns the effective concurrency.
func (d Discovery) Workers() int {
	if d.Concurrency <= 0 {
		return DefaultConcurrency
	}
	return d.Concurrency
}

// Keys returns the tag keys with defaults applied.
func (d Discovery) Keys() TagKeys {
	k := d.TagKeys
	if k.Environment == "" {
		k.Environment = "environment"
	}
	if k.Owner == "" {
		k.Owner = "owner"
	}
	if k.CostCentre == "" {
		k.CostCentre = "cost-centre"
	}
	return k
}

var (
	accountRe = regexp.MustCompile(`^\d{12}$`)
	regionRe  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
)

func (d Discovery) validate() error {
	var errs []error
	seen := map[string]bool{}
	for i, t := range d.AWS {
		at := fmt.Sprintf("discovery.aws[%d]", i)
		if !accountRe.MatchString(t.Account) {
			errs = append(errs, fmt.Errorf("%s: account %q must be a 12-digit AWS account ID", at, t.Account))
		}
		if strings.HasPrefix(t.Profile, "-") {
			errs = append(errs, fmt.Errorf("%s: profile %q must not start with '-'", at, t.Profile))
		}
		if len(t.Regions) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one region is required", at))
		}
		for _, r := range t.Regions {
			if !regionRe.MatchString(r) {
				errs = append(errs, fmt.Errorf("%s: %q is not an AWS region such as eu-west-1", at, r))
				continue
			}
			key := "aws/" + t.Account + "/" + r
			if seen[key] {
				errs = append(errs, fmt.Errorf("%s: account %s region %s is listed more than once", at, t.Account, r))
			}
			seen[key] = true
		}
	}
	for i, t := range d.Azure {
		at := fmt.Sprintf("discovery.azure[%d]", i)
		s := strings.TrimSpace(t.Subscription)
		switch {
		case s == "":
			errs = append(errs, fmt.Errorf("%s: subscription is required", at))
		case strings.HasPrefix(s, "-"):
			errs = append(errs, fmt.Errorf("%s: subscription %q must not start with '-'", at, s))
		case seen["azure/"+strings.ToLower(s)]:
			errs = append(errs, fmt.Errorf("%s: subscription %q is listed more than once", at, s))
		}
		seen["azure/"+strings.ToLower(s)] = true
	}
	if p := d.NameEnvironmentPattern; p != "" {
		re, err := rx.Compile(p)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("discovery.nameEnvironmentPattern: %w", err))
		case re.SubexpIndex("env") < 0:
			errs = append(errs, fmt.Errorf("discovery.nameEnvironmentPattern %q needs a named group (?P<env>...)", p))
		}
	}
	if d.Concurrency < 0 || d.Concurrency > MaxConcurrency {
		errs = append(errs, fmt.Errorf("discovery.concurrency %d must be between 1 and %d", d.Concurrency, MaxConcurrency))
	}
	return errors.Join(errs...)
}

// Timeout returns the effective cloud CLI timeout. Load has already rejected
// an invalid value, so the fallback only covers hand-built configs.
func (c Config) Timeout() time.Duration {
	d, err := c.parseTimeout()
	if err != nil {
		return DefaultCommandTimeout
	}
	return d
}

func (c Config) parseTimeout() (time.Duration, error) {
	return parsePositive("commandTimeout", c.CommandTimeout, DefaultCommandTimeout)
}

// parsePositive parses an optional positive Go duration setting.
func parsePositive(field, v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s %q: want a duration such as \"90s\" or \"3m\"", field, v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s %q must be positive", field, v)
	}
	return d, nil
}

// validate rejects settings that would otherwise misbehave silently later.
func (c Config) validate() error {
	_, errTimeout := c.parseTimeout()
	_, errTTL := parsePositive("inventoryCacheTTL", c.InventoryCacheTTL, DefaultInventoryCacheTTL)
	return errors.Join(c.validateMode(), errTimeout, errTTL, c.validateEnvironments(), c.validateTargets(),
		c.Discovery.validate(), c.SupportCalendar.Validate(), c.CostRates.Validate(), c.Audit.validate(), c.validateChangeControl(), c.validateAWS())
}

var minorRe = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?$`)

func (c Config) validateTargets() error {
	var errs []error
	if c.TargetKubeVersion != "" && !minorRe.MatchString(c.TargetKubeVersion) {
		errs = append(errs, fmt.Errorf("targetKubeVersion %q is not a version like 1.30", c.TargetKubeVersion))
	}
	allowed := map[string]bool{}
	for _, e := range c.Environments {
		allowed[strings.ToLower(e)] = true
	}
	for env, v := range c.TargetKubeVersions {
		if !minorRe.MatchString(v) {
			errs = append(errs, fmt.Errorf("targetKubeVersions[%q] %q is not a version like 1.30", env, v))
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(env)] {
			errs = append(errs, fmt.Errorf("targetKubeVersions has environment %q, which is not in environments %v", env, c.Environments))
		}
	}
	return errors.Join(errs...)
}

// validateEnvironments catches a prodEnvironments entry that no cluster can
// ever have — e.g. "production" when the allow-list says "prod" — which would
// silently disable inventory-based prod detection.
func (c Config) validateEnvironments() error {
	if len(c.Environments) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, e := range c.Environments {
		allowed[strings.ToLower(e)] = true
	}
	var errs []error
	for _, p := range c.ProdEnvs() {
		if !allowed[strings.ToLower(p)] {
			errs = append(errs, fmt.Errorf("prodEnvironments entry %q is not in environments %v, so no cluster could ever match it", p, c.Environments))
		}
	}
	return errors.Join(errs...)
}

// OrgDefaults is a config fragment built into release binaries, base64
// JSON set with -ldflags "-X nedctl/internal/config.OrgDefaults=…" (see the
// Makefile's ORG_DEFAULTS). It holds what every engineer in the organisation
// shares — the Identity Center start URL and region, environments, prod
// patterns — so nedctl works with no config file at all. A user's own config
// file is applied on top. Empty in source, so nothing organisation-specific
// lives in the repository.
var OrgDefaults string

// OrgDefaultsErr reports built-in defaults that do not decode; doctor shows
// it. Such defaults are ignored.
func OrgDefaultsErr() error {
	_, err := orgDefaults()
	return err
}

func orgDefaults() (Config, error) {
	cfg := genericDefaults()
	if OrgDefaults == "" {
		return cfg, nil
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(OrgDefaults))
	if err != nil {
		return cfg, fmt.Errorf("built-in defaults: not base64: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return genericDefaults(), fmt.Errorf("built-in defaults: %w", err)
	}
	if err := strictCheck(data); err != nil {
		return genericDefaults(), fmt.Errorf("built-in defaults: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return genericDefaults(), fmt.Errorf("built-in defaults: %w", err)
	}
	return cfg, nil
}

// HasOrgDefaults reports valid built-in defaults.
func HasOrgDefaults() bool { return OrgDefaults != "" && OrgDefaultsErr() == nil }

// Default returns config used when no file is present: the built-in
// organisation defaults, if any, else the generic ones.
func Default() Config {
	cfg, err := orgDefaults()
	if err != nil {
		return genericDefaults()
	}
	return cfg
}

func genericDefaults() Config {
	return Config{ProdPatterns: []string{`(?i)prod`, `(?i)-prd-`}}
}

// Load resolves and reads the config file. An empty explicitPath triggers the
// search order documented on the package. A missing file is NOT an error; the
// defaults are returned instead.
func Load(explicitPath string) (Config, string, error) {
	cfg := Default()
	path := resolvePath(explicitPath)
	if path == "" {
		return cfg, "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, "", nil
		}
		return cfg, path, fmt.Errorf("reading config %s: %w", path, err)
	}
	// Decode over the defaults so unspecified fields keep their default.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, path, fmt.Errorf("parsing config %s: %w", path, err)
	}
	// A setting nedctl does not know is a mistake, usually one in the wrong
	// block: silently ignoring it hides the real problem behind a confusing
	// error elsewhere (startUrl under discovery read as an empty account).
	if err := strictCheck(data); err != nil {
		return cfg, path, fmt.Errorf("config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, path, fmt.Errorf("config %s: %w", path, err)
	}
	// A relative inventoryPath is resolved against the config file's directory,
	// not the current working directory, so `nedctl` works from anywhere.
	if cfg.InventoryPath != "" && !filepath.IsAbs(cfg.InventoryPath) {
		cfg.InventoryPath = filepath.Join(filepath.Dir(path), cfg.InventoryPath)
	}
	return cfg, path, nil
}

// settingHome says where commonly misplaced settings belong.
var settingHome = map[string]string{
	"startUrl": "aws", "ssoRegion": "aws", "ssoSession": "aws", "region": "aws", "regions": "aws",
	"accountNamePattern": "aws", "accounts": "aws", "breakGlassRoles": "aws", "elevatedRolePattern": "aws",
	"accessLevelTag": "aws", "legacyTool": "aws", "devopsInstance": "aws", "profilePrefix": "aws", "sessionTimeout": "aws",
	"requireFor": "changeControl", "enabled": "changeControl", "instanceUrl": "changeControl.serviceNow",
	"tokenEnv": "changeControl.serviceNow or audit.forward", "logPath": "audit", "forward": "audit",
	"profile": "discovery.aws[]", "account": "discovery.aws[]", "subscription": "discovery.azure[]",
	"tagKeys": "discovery", "nameEnvironmentPattern": "discovery",
}

var unknownFieldRe = regexp.MustCompile(`unknown field "([^"]+)"`)

func strictCheck(data []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var probe Config
	err := dec.Decode(&probe)
	if err == nil {
		return nil
	}
	m := unknownFieldRe.FindStringSubmatch(err.Error())
	if m == nil {
		return err
	}
	if home, ok := settingHome[m[1]]; ok {
		return fmt.Errorf("unknown setting %q here — it belongs in the %q block; check where it sits in the file", m[1], home)
	}
	return fmt.Errorf("unknown setting %q — check its spelling and which block it is in (docs/nedctl.md, Configuration)", m[1])
}

func resolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("NEDCTL_CONFIG"); env != "" {
		return env
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		}
	}
	if base != "" {
		p := filepath.Join(base, "nedctl", "config.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat("nedctl.json"); err == nil {
		return "nedctl.json"
	}
	return ""
}
