package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"nedctl/internal/kube"
	"nedctl/internal/ui"
)

// cmdStatus is the home screen — `nedctl` on its own at a terminal, or
// `nedctl status`: who you are signed in as and for how long, the current
// kube-context, and the commands used most, with the last cluster. It reads
// only local state, so it is instant and works offline.
func cmdStatus(cfgPath string, w io.Writer) int {
	s := helpStyle(w)
	fmt.Fprintf(w, "%s %s\n\n", s.Bold("nedctl"), s.Dim(Version))
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(w, "  %s\n  %s\n", s.Fail("config error: "+err.Error()), s.Hint("fix it, or run nedctl doctor"))
		return ExitFailure
	}
	if !cfg.AWS.Configured() && !cfg.Azure.Configured() && cfg.InventoryPath == "" && cfg.InventoryURL == "" {
		fmt.Fprintf(w, "  Welcome. Start with %s — it takes a minute.\n\n", s.Bold("nedctl setup"))
		fmt.Fprintf(w, "  %s\n", s.Hint("nedctl help lists every command"))
		return ExitOK
	}

	var lastCluster string
	if cfg.AWS.Configured() {
		name := resolveProfile(cfg, "")
		switch p, managed, ok := managedProfile(name); {
		case name == "":
			fmt.Fprintf(w, "  %s  %s\n", s.Fg(ui.Grey, "●"), "not signed in — "+s.Bold("nedctl aws login")+" (or any command signs you in)")
		case !ok:
			fmt.Fprintf(w, "  %s  aws:%s\n", s.Fg(ui.Grey, "●"), name)
		default:
			col := cfg.ColorFor(p.Environment)
			label := "aws:" + firstNonBlank(p.Squad, p.AccountID) + "[" + envWord(cfg, p.Environment) + "]"
			role := p.Role
			if cfg.AWS.Elevated(p.Role) {
				role += " " + s.Fg(elevatedColor, "▲ elevated")
			}
			fmt.Fprintf(w, "  %s  %s  %s  %s\n", s.Fg(col, "●"), s.BoldFg(col, label), role, signInState(s, managed.Session.Name))
			lastCluster = loadLastCluster(cfg, profileContext{Name: name, AccountID: p.AccountID})
		}
	}
	if k, err := kube.ViewCurrent(context.Background()); err == nil && k.CurrentContext != "" {
		cl := kube.ClassifyCurrent(k, guardFleet(cfg, io.Discard), cfg.ProdEnvs(), cfg.ProdPatterns)
		env := cl.Environment
		if env == "" && cl.Production {
			env = "prod"
		}
		col := cfg.ColorFor(env)
		label := "k8s:" + k.CurrentContext
		if env != "" {
			label += "[" + envWord(cfg, env) + "]"
		}
		fmt.Fprintf(w, "  %s  %s\n", s.Fg(col, "●"), s.Fg(col, label))
	}

	fmt.Fprintln(w)
	var rows [][2]string
	if cfg.AWS.Configured() || !cfg.Azure.Configured() {
		rows = append(rows, [2]string{"nedctl kube", "kubectl on a cluster"},
			[2]string{"nedctl shell", "a shell on an instance"},
			[2]string{"nedctl console", "the AWS console, same account and role"},
			[2]string{"nedctl aws login", "switch account"})
		if lastCluster != "" {
			rows[0][1] += s.Dim("   last: " + lastCluster)
		}
	}
	if cfg.Azure.Configured() {
		rows = append(rows, [2]string{"nedctl azure kube", "kubectl on an AKS cluster, on its bastion"},
			[2]string{"nedctl azure shell", "SSH to an AKS bastion or Azure machine"})
	}
	rows = append(rows, [2]string{"nedctl debug pod", "a debug pod or node shell (shown and approved first)"},
		[2]string{"nedctl help", "everything else"})
	for _, r := range rows {
		fmt.Fprintf(w, "  %s  %s\n", ui.Pad(s.Bold(r[0]), 19), r[1])
	}
	return ExitOK
}

func managedProfile(name string) (awssso.Profile, awssso.Managed, bool) {
	if name == "" {
		return awssso.Profile{}, awssso.Managed{}, false
	}
	path, err := awssso.ConfigPath()
	if err != nil {
		return awssso.Profile{}, awssso.Managed{}, false
	}
	m, err := awssso.LoadManaged(path)
	if err != nil {
		return awssso.Profile{}, m, false
	}
	p, ok := m.Profiles[name]
	return p, m, ok
}

// envWord is an environment as nedctl shows it: production in capitals.
func envWord(cfg config.Config, env string) string {
	if cfg.IsProdEnvironment(env) {
		return strings.ToUpper(env)
	}
	return strings.ToLower(env)
}

func signInState(s ui.Style, session string) string {
	left, ok := signInLeft(session)
	switch {
	case !ok:
		return s.Dim("not signed in")
	case left <= 0:
		return s.Fg(ui.Amber, "sign-in expired — the next command renews it")
	case left < time.Hour:
		return s.Fg(ui.Amber, fmt.Sprintf("%dm left", int(left.Minutes())))
	default:
		return s.Dim(fmt.Sprintf("%dh%02dm left", int(left.Hours()), int(left.Minutes())%60))
	}
}
