package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nedctl/internal/audit"
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

	homeTunnels(cfg, s, w)
	homeActivity(cfg, s, w)
	homeChecks(cfg, s, w)

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
	if tip := homeTip(cfg); tip != "" {
		fmt.Fprintf(w, "\n  %s\n", s.Dim("tip: "+tip))
	}
	return ExitOK
}

// homeTunnels lists the EKS tunnels open on this machine (published by a
// kube or connect still running).
func homeTunnels(cfg config.Config, s ui.Style, w io.Writer) {
	dir, err := tunnelDir(cfg)
	if err != nil {
		return
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.tunnel.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r tunnelRecord
		if json.Unmarshal(data, &r) != nil || r.PID <= 0 || !processAlive(r.PID) {
			continue
		}
		users := tunnelUsers(cfg, r.Cluster)
		extra := ""
		if users > 0 {
			extra = fmt.Sprintf(", %d other session(s) on it", users)
		}
		fmt.Fprintf(w, "  %s  tunnel %s via %s on 127.0.0.1:%d %s\n", s.Fg(ui.Green, "⇄"), s.Bold(r.Cluster), firstNonBlank(r.HopName, r.Hop), r.Port,
			s.Dim("(open "+shortDuration(now().Sub(r.Started).Round(time.Minute))+extra+")"))
	}
}

// homeActivity shows the last few things this machine did, from the audit
// trail, and says loudly if the trail's hash chain is broken.
func homeActivity(cfg config.Config, s ui.Style, w io.Writer) {
	path, err := cfg.AuditLogPath()
	if err != nil {
		return
	}
	events, res, err := audit.Read(path)
	if err != nil {
		return
	}
	if !res.OK {
		fmt.Fprintf(w, "  %s\n", s.Fail(fmt.Sprintf("the audit trail fails its integrity check at line %d (%s) — tell security; nedctl audit verify shows it", res.Line, res.Problem)))
	}
	var recent []audit.Event
	for i := len(events) - 1; i >= 0 && len(recent) < 3; i-- {
		if events[i].Phase == audit.PhaseEnd {
			recent = append(recent, events[i])
		}
	}
	if len(recent) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s\n", s.Dim("recently"))
	for _, e := range recent {
		when := e.Time
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			when = t.Local().Format("Mon 15:04")
		}
		mark := s.Fg(ui.Green, "✔")
		if e.Outcome != audit.OutcomeSuccess {
			mark = s.Fg(ui.Red, "✖")
		}
		fmt.Fprintf(w, "  %s  %s  %s %s\n", mark, s.Dim(when), e.Action, firstNonBlank(e.Cluster, e.Environment))
	}
}

// homeChecks is the quick local hygiene count (no network).
func homeChecks(cfg config.Config, s ui.Style, w io.Writer) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	bad := 0
	for _, c := range hygieneChecks(home) {
		if c.Status == "warn" || c.Status == "fail" {
			bad++
		}
	}
	if bad > 0 {
		fmt.Fprintf(w, "\n  %s\n", s.Warn(fmt.Sprintf("%d risky leftover(s) on this machine — nedctl doctor --hygiene", bad)))
	}
}

var homeTips = []string{
	"nedctl health --env prod --board shows every prod cluster on a live board",
	"nedctl explain deploy/NAME -n NS says in plain words why a workload is failing",
	"nedctl cp POD:/path --save puts a file in your Downloads folder (Windows' from WSL)",
	"nedctl logs hides secrets and card numbers by itself — safe on a shared screen",
	"nedctl connect CLUSTER --tab keeps one tunnel open that every other command reuses",
	"nedctl app NAME --env dev,qa,prod compares an app's version across environments",
	"nedctl update installs the latest release, checking the bank's signature first",
}

// homeTip is a different tip each day.
func homeTip(cfg config.Config) string {
	if !cfg.AWS.Configured() && !cfg.Azure.Configured() {
		return ""
	}
	return homeTips[now().YearDay()%len(homeTips)]
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
