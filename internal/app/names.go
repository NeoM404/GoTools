package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nedctl/internal/config"
)

// The names of an account's clusters and instances, kept each time nedctl
// lists them, so tab completion can offer them instantly and offline.

// named is implemented by results that have a name worth completing.
type named interface{ nameOf() string }

func (c clusterHit) nameOf() string  { return c.Name }
func (r eksAuthRow) nameOf() string  { return r.Cluster }
func (e ec2Instance) nameOf() string { return e.Name }

func namesPath(cfg config.Config, account, kind string) (string, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	key := strings.NewReplacer("/", "_", "\\", "_").Replace(account)
	return filepath.Join(filepath.Dir(log), "names", key+"-"+kind+".json"), nil
}

func loadNames(cfg config.Config, account, kind string) []string {
	p, err := namesPath(cfg, account, kind)
	if err != nil {
		return nil
	}
	var names []string
	if data, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(data, &names)
	}
	return names
}

// rememberNames stores the names found; a single-region search adds to
// what is known instead of replacing it. Best effort.
func rememberNames[T any](cfg config.Config, pc profileContext, kind string, items []T, partial bool) {
	account := firstNonBlank(pc.AccountID, pc.Name)
	if account == "" {
		return
	}
	set := map[string]bool{}
	if partial {
		for _, n := range loadNames(cfg, account, kind) {
			set[n] = true
		}
	}
	for _, it := range items {
		if n, ok := any(it).(named); ok && n.nameOf() != "" && !strings.ContainsAny(n.nameOf(), " \t\r\n") {
			set[n.nameOf()] = true
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	p, err := namesPath(cfg, account, kind)
	if err != nil || os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	if data, err := json.Marshal(names); err == nil {
		_ = writeFileAtomic(p, data, 0o600)
	}
}
