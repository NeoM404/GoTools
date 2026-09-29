// Package config loads bankctl configuration and locates the fleet inventory.
//
// Config is JSON (stdlib only). Resolution order for the config file:
//  1. --config flag
//  2. $BANKCTL_CONFIG
//  3. $XDG_CONFIG_HOME/bankctl/config.json  (or ~/.config/bankctl/config.json)
//  4. ./bankctl.json
//
// If no config is found, sensible zero-value defaults are used so `bankctl
// doctor` and `--help` still work out of the box.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NeoM404/GoTools/internal/support"
)

// DefaultCommandTimeout bounds a cloud CLI call when the config sets none.
// Credential fetches are normally seconds; two minutes absorbs a slow SSO
// token refresh without letting a hung CLI stall a shell or CI job forever.
const DefaultCommandTimeout = 2 * time.Minute

// Config controls where the fleet inventory comes from and which contexts are
// treated as production (for the safety guard).
type Config struct {
	// InventoryPath is a local JSON file produced by the IaC pipeline
	// (e.g. `terraform output -json fleet`). Used when InventoryURL is empty.
	InventoryPath string `json:"inventoryPath"`

	// InventoryURL is an HTTPS endpoint returning the same JSON. Preferred in
	// production so every engineer sees the same live fleet. TLS is required.
	InventoryURL string `json:"inventoryUrl"`

	// ProdPatterns are regular expressions; a cluster or kube-context whose
	// name matches any of them is treated as production by `bankctl guard`,
	// in addition to any cluster whose inventory Environment == "prod".
	ProdPatterns []string `json:"prodPatterns"`

	// KubeconfigDir is where per-cluster kubeconfigs are written. Empty means
	// the standard KUBECONFIG / ~/.kube/config behaviour of the cloud CLIs.
	KubeconfigDir string `json:"kubeconfigDir"`

	// TargetKubeVersion is the fleet's desired minor version (e.g. "1.30").
	// `bankctl fleet versions` flags anything more than one minor behind.
	TargetKubeVersion string `json:"targetKubeVersion"`

	// MinVersions overrides the built-in `doctor` version floors by tool name,
	// e.g. {"kubectl": "1.29", "aws": "2.15"}. Lets the team raise the bar
	// centrally without a bankctl release.
	MinVersions map[string]string `json:"minVersions"`

	// CommandTimeout bounds each cloud CLI call (aws/az), as a Go duration
	// string such as "90s" or "3m". Empty means DefaultCommandTimeout.
	CommandTimeout string `json:"commandTimeout"`

	// Environments, when set, is the allow-list every inventory cluster's
	// environment must be on (e.g. ["dev","sit","uat","prod"]), so a typo
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
	// `bankctl fleet calendar aws`.
	SupportCalendar support.Calendar `json:"supportCalendar"`

	// CostRates are control-plane prices used to estimate the
	// extended-support premium. Optional; set them from your own pricing.
	CostRates support.Rates `json:"costRates"`

	// Audit controls the credential-access audit trail. It is always on;
	// this only chooses where it goes.
	Audit Audit `json:"audit"`
}

// Audit configures the audit trail.
type Audit struct {
	// LogPath is the local hash-chained log. Default:
	// $XDG_STATE_HOME/bankctl/audit.jsonl (~/.local/state/bankctl/audit.jsonl).
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
	return filepath.Join(base, "bankctl", "audit.jsonl"), nil
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
// it can be reviewed and audited: bankctl never guesses which accounts or
// subscriptions exist, and a completeness claim is only ever made for these.
type Discovery struct {
	AWS   []AWSTarget   `json:"aws"`
	Azure []AzureTarget `json:"azure"`
	// Concurrency caps how many cloud CLI processes run at once across the
	// whole scan. Default DefaultConcurrency; at most MaxConcurrency.
	Concurrency int `json:"concurrency"`
	// TagKeys names the cloud tags that carry inventory metadata.
	TagKeys TagKeys `json:"tagKeys"`
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
	return errors.Join(errTimeout, errTTL, c.validateEnvironments(), c.validateTargets(),
		c.Discovery.validate(), c.SupportCalendar.Validate(), c.CostRates.Validate(), c.Audit.validate())
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

// Default returns config used when no file is present.
func Default() Config {
	return Config{
		ProdPatterns: []string{`(?i)prod`, `(?i)-prd-`},
	}
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
	if err := cfg.validate(); err != nil {
		return cfg, path, fmt.Errorf("config %s: %w", path, err)
	}
	// A relative inventoryPath is resolved against the config file's directory,
	// not the current working directory, so `bankctl` works from anywhere.
	if cfg.InventoryPath != "" && !filepath.IsAbs(cfg.InventoryPath) {
		cfg.InventoryPath = filepath.Join(filepath.Dir(path), cfg.InventoryPath)
	}
	return cfg, path, nil
}

func resolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("BANKCTL_CONFIG"); env != "" {
		return env
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".config")
		}
	}
	if base != "" {
		p := filepath.Join(base, "bankctl", "config.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat("bankctl.json"); err == nil {
		return "bankctl.json"
	}
	return ""
}
