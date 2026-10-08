package app

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"nedctl/internal/config"
)

// starterConfig is written by `nedctl init`. It is valid JSON with sensible
// defaults so `nedctl` works after the user just fills in an inventory source.
//
// QA is a production copy, so it is guarded as production. The prod pattern
// matches prod/prd/qa only as a whole dash-, dot- or underscore-separated
// word, so "product-api-k8s-dev-cluster" is not flagged.
const starterConfig = `{
  "mode": "%s",
  "inventoryPath": "",
  "inventoryUrl": "",
  "prodPatterns": ["(?i)(^|[-_.])(prod|prd|qa)([-_.]|$)"],
  "kubeconfigDir": "",
  "targetKubeVersion": "1.30",
  "environments": ["dev", "ete", "qa", "prod"],
  "prodEnvironments": ["qa", "prod"],
  "commandTimeout": "2m",
  "discovery": {
    "aws": [],
    "azure": []
  }
}
`

// cmdInit scaffolds a config file at the default location (or --path), so a new
// user does not have to hand-write JSON. It never overwrites without --force.
func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pathFlag := fs.String("path", "", "where to write the config (default: ~/.config/nedctl/config.json)")
	force := fs.Bool("force", false, "overwrite an existing config")
	mode := fs.String("mode", config.ModeWorkstation, "where nedctl runs: workstation (fetches credentials via aws/az) or bastion (uses the host's kubeconfig)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *mode != config.ModeWorkstation && *mode != config.ModeBastion {
		fmt.Fprintf(stderr, "--mode %q: want %s or %s\n", *mode, config.ModeWorkstation, config.ModeBastion)
		return ExitUsage
	}

	path := *pathFlag
	if path == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(stderr, "cannot determine home directory: %v\n", err)
				return ExitFailure
			}
			base = filepath.Join(home, ".config")
		}
		path = filepath.Join(base, "nedctl", "config.json")
	}

	if _, err := os.Stat(path); err == nil && !*force {
		fmt.Fprintf(stderr, "%s already exists — use --force to overwrite\n", path)
		return ExitFailure
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(stderr, "creating config dir: %v\n", err)
		return ExitFailure
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf(starterConfig, *mode)), 0o644); err != nil {
		fmt.Fprintf(stderr, "writing config: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintf(stdout, "wrote starter config to %s\n", path)
	fmt.Fprintln(stdout, "next: set \"inventoryPath\" or \"inventoryUrl\", then run `nedctl clusters list`")
	return ExitOK
}
