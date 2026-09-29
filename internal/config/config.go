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
	"fmt"
	"os"
	"path/filepath"
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
	return err
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
