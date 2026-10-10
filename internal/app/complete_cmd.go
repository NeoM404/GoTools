package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
)

// Tab completion. The shell function from `nedctl prompt init` calls
// `nedctl __complete <words…>` with the words typed so far, the last being
// the one under the cursor (possibly empty), and offers what it prints, one
// per line. It reads only local state — config, ~/.aws/config, nedctl's
// caches — so it answers instantly and never touches the network. Flags
// come from each command's own flag set, so they cannot fall out of date.
// "__files__" asks the shell to complete file names.

var subcommands = map[string][]string{
	"aws":       {"login", "whoami", "env"},
	"eks":       {"auth", "access"},
	"ec2":       {"start", "stop"},
	"clusters":  {"list"},
	"fleet":     {"versions", "eol", "calendar"},
	"inventory": {"validate", "diff", "sync"},
	"audit":     {"verify"},
	"prompt":    {"init"},
}

var commandNames = []string{
	"setup", "aws", "shell", "kube", "connect", "eks", "ec2", "clusters", "kubeconfig", "login",
	"fleet", "inventory", "sweep", "audit", "evidence", "guard", "current", "prompt", "doctor", "init", "version", "help",
}

var fileFlags = map[string]bool{"config": true, "path": true, "log": true, "file": true, "out": true, "report": true, "kubeconfig": true}

func cmdComplete(ctx context.Context, cfgPath string, words []string, stdout io.Writer) int {
	if len(words) == 0 {
		words = []string{""}
	}
	cur, done := words[len(words)-1], words[:len(words)-1]
	for _, c := range completions(ctx, cfgPath, done, cur) {
		if strings.HasPrefix(strings.ToLower(c), strings.ToLower(cur)) || c == "__files__" {
			fmt.Fprintln(stdout, c)
		}
	}
	return ExitOK
}

func completions(ctx context.Context, cfgPath string, done []string, cur string) []string {
	// A leading --config PATH belongs to nedctl itself.
	if len(done) > 0 && (done[0] == "--config" || done[0] == "-config") {
		if len(done) == 1 {
			return []string{"__files__"}
		}
		cfgPath, done = done[1], done[2:]
	}
	if len(done) == 0 {
		if strings.HasPrefix(cur, "-") {
			return []string{"--config"}
		}
		return commandNames
	}
	cmd := done[0]
	path := []string{cmd}
	rest := done[1:]
	if subs, ok := subcommands[cmd]; ok {
		if len(rest) == 0 {
			return subs
		}
		path = append(path, rest[0])
		rest = rest[1:]
	}
	flags := flagsOf(ctx, path)
	cfg, _, _ := config.Load(cfgPath)

	// The value of a flag?
	if len(rest) > 0 {
		prev := strings.TrimLeft(rest[len(rest)-1], "-")
		if takesValue, known := flags[prev]; known && takesValue && strings.HasPrefix(rest[len(rest)-1], "-") && !strings.Contains(prev, "=") {
			return flagValues(cfg, path, prev)
		}
	}
	if strings.HasPrefix(cur, "-") {
		out := make([]string, 0, len(flags))
		for f := range flags {
			if len(f) == 1 {
				out = append(out, "-"+f)
			} else {
				out = append(out, "--"+f)
			}
		}
		sort.Strings(out)
		return out
	}
	switch strings.Join(path, " ") {
	case "kube", "connect", "eks access":
		if positionals(rest, flags) == 0 {
			return currentNames(cfg, "eks")
		}
	case "shell":
		return currentNames(cfg, "ec2")
	case "ec2 start", "ec2 stop":
		if positionals(rest, flags) == 0 {
			return currentNames(cfg, "ec2")
		}
	case "aws login":
		return assignmentWords(cfg)
	case "prompt init":
		return []string{"bash", "zsh"}
	}
	return nil
}

// positionals counts the non-flag words in rest.
func positionals(rest []string, flags map[string]bool) int {
	n := 0
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if strings.HasPrefix(w, "-") {
			if name := strings.TrimLeft(w, "-"); !strings.Contains(name, "=") && flags[name] {
				i++ // skip its value
			}
			continue
		}
		n++
	}
	return n
}

var flagLineRe = regexp.MustCompile(`(?m)^  -([A-Za-z][\w-]*)( \S+)?`)

// flagsOf asks the command for its flags (as `-h` prints them): name →
// whether it takes a value.
func flagsOf(ctx context.Context, path []string) map[string]bool {
	var errb bytes.Buffer
	dispatch(ctx, append(append([]string{}, path...), "-h"), io.Discard, &errb)
	flags := map[string]bool{}
	for _, m := range flagLineRe.FindAllStringSubmatch(errb.String(), -1) {
		flags[m[1]] = m[2] != ""
	}
	return flags
}

func flagValues(cfg config.Config, path []string, flag string) []string {
	cmd := strings.Join(path, " ")
	switch {
	case fileFlags[flag]:
		return []string{"__files__"}
	case flag == "profile":
		return managedProfiles()
	case flag == "region":
		return knownRegions(cfg)
	case flag == "instance" || flag == "via-instance":
		return currentNames(cfg, "ec2")
	case flag == "via" && cmd == "shell":
		return []string{"aws", "legacy"}
	case flag == "via":
		return []string{"auto", "direct", "bastion"}
	case flag == "o" || flag == "output":
		return []string{"table", "json"}
	case flag == "shell":
		return []string{"bash", "zsh", "powershell", "plain"}
	case flag == "format":
		return []string{"sh", "powershell", "none"}
	case flag == "mode":
		return []string{config.ModeWorkstation, config.ModeBastion}
	case flag == "cloud":
		return []string{"aws", "azure"}
	case flag == "env":
		return cfg.Environments
	case flag == "account":
		return assignmentField(cfg, func(a awssso.Assignment) string { return config.StripAccountTag(a.AccountName) })
	case flag == "role":
		return assignmentField(cfg, func(a awssso.Assignment) string { return a.Role })
	}
	return nil
}

func managedProfiles() []string {
	path, err := awssso.ConfigPath()
	if err != nil {
		return nil
	}
	m, err := awssso.LoadManaged(path)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(m.Profiles))
	for name := range m.Profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// currentAccount is the account of the profile commands would act with.
func currentAccount(cfg config.Config) string {
	name := resolveProfile(cfg, "")
	if name == "" {
		return ""
	}
	if path, err := awssso.ConfigPath(); err == nil {
		if m, err := awssso.LoadManaged(path); err == nil {
			if p, ok := m.Profiles[name]; ok && p.AccountID != "" {
				return p.AccountID
			}
		}
	}
	return name
}

func currentNames(cfg config.Config, kind string) []string {
	if acct := currentAccount(cfg); acct != "" {
		return loadNames(cfg, acct, kind)
	}
	return nil
}

// knownRegions are the regions nedctl has seen enabled for any account.
func knownRegions(cfg config.Config) []string {
	if len(cfg.AWS.Regions) > 0 {
		return cfg.AWS.Regions
	}
	set := map[string]bool{}
	if log, err := cfg.AuditLogPath(); err == nil {
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(log), "regions", "*.json"))
		for _, f := range files {
			var c regionCache
			if data, err := os.ReadFile(f); err == nil && json.Unmarshal(data, &c) == nil {
				for _, r := range c.Enabled {
					set[r] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// cachedAssignments reads the account list from the last sign-in, however
// old: completion only needs the names.
func cachedAssignments(cfg config.Config) []awssso.Assignment {
	p, err := assignmentCachePath(cfg)
	if err != nil {
		return nil
	}
	var c assignmentCache
	if data, err := os.ReadFile(p); err == nil && json.Unmarshal(data, &c) == nil && c.StartURL == cfg.AWS.StartURL {
		return c.Assignments
	}
	return nil
}

func assignmentField(cfg config.Config, f func(awssso.Assignment) string) []string {
	set := map[string]bool{}
	for _, a := range cachedAssignments(cfg) {
		if v := f(a); v != "" && !strings.ContainsAny(v, " \t") {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// assignmentWords are the words `aws login` filters on: environments,
// squads, account names and roles, lower case.
func assignmentWords(cfg config.Config) []string {
	set := map[string]bool{}
	for _, a := range cachedAssignments(cfg) {
		squad, env := cfg.AWS.Classify(a.AccountID, a.AccountName, cfg.Environments)
		for _, v := range []string{env, squad, config.StripAccountTag(a.AccountName), a.Role} {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" && !strings.ContainsAny(v, " \t") {
				set[v] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
