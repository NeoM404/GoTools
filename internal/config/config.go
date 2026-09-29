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

	// Discovery is the cloud scope `inventory sync` and `inventory diff` scan.
	Discovery Discovery `json:"discovery"`
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
	if c.CommandTimeout == "" {
		return DefaultCommandTimeout, nil
	}
	d, err := time.ParseDuration(c.CommandTimeout)
	if err != nil {
		return 0, fmt.Errorf("commandTimeout %q: want a duration such as \"90s\" or \"3m\"", c.CommandTimeout)
	}
	if d <= 0 {
		return 0, fmt.Errorf("commandTimeout %q must be positive", c.CommandTimeout)
	}
	return d, nil
}

// validate rejects settings that would otherwise misbehave silently later.
func (c Config) validate() error {
	_, err := c.parseTimeout()
	return errors.Join(err, c.Discovery.validate())
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
