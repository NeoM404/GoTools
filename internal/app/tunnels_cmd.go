package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl tunnels` shows every EKS tunnel nedctl holds on this machine —
// which cluster, port and instance, who holds it, whether its Session
// Manager session is open or closed for idleness, and who else uses it —
// and closes them: one, or all. Records whose holder is gone are cleared
// as it goes.

// liveTunnels reads the published tunnels, clearing dead holders' records.
func liveTunnels(cfg config.Config) []tunnelRecord {
	dir, err := tunnelDir(cfg)
	if err != nil {
		return nil
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.tunnel.json"))
	var out []tunnelRecord
	for _, f := range files {
		data, err := os.ReadFile(f)
		var r tunnelRecord
		if err != nil || json.Unmarshal(data, &r) != nil || r.PID <= 0 {
			continue
		}
		if !processAlive(r.PID) {
			_ = os.Remove(f)
			_ = os.RemoveAll(leaseDir(f))
			_ = os.Remove(f + ".close")
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cluster < out[j].Cluster })
	return out
}

func cmdTunnels(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	sub := "ls"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("tunnels "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	all := fs.Bool("all", false, "close: every tunnel")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl tunnels [ls] [-o json] | nedctl tunnels close CLUSTER|--all"
	if err != nil || (sub != "ls" && sub != "close") || (sub == "ls" && len(pos) > 0) || (sub == "close" && (len(pos) == 1) == *all) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	live := liveTunnels(cfg)
	if sub == "ls" {
		if *output == "json" {
			if live == nil {
				live = []tunnelRecord{}
			}
			return writeJSON(stdout, stderr, live)
		}
		printTunnels(stdout, cfg, live)
		return ExitOK
	}

	var targets []tunnelRecord
	for _, r := range live {
		if *all || r.Cluster == pos[0] {
			targets = append(targets, r)
		}
	}
	if len(targets) == 0 {
		var names []string
		for _, r := range live {
			names = append(names, r.Cluster)
		}
		if *all {
			fmt.Fprintln(stdout, "no tunnels are open")
			return ExitOK
		}
		fmt.Fprintf(stderr, "no open tunnel to %q%s\n", pos[0], didYouMean(pos[0], names))
		return ExitFailure
	}
	st := ui.Style{Color: colorOn(stdout)}
	failed := 0
	for _, r := range targets {
		ev := audit.Event{Action: "tunnel-close", Cloud: "aws", Cluster: r.Cluster, Detail: fmt.Sprintf("tunnel 127.0.0.1:%d via %s held by %s (pid %d)", r.Port, firstNonBlank(r.HopName, r.Hop), firstNonBlank(r.Holder, "nedctl"), r.PID)}
		tr, err := beginAuditEvent(ctx, cfg, ev, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
			return ExitFailure
		}
		if err := requestClose(ctx, cfg, r); err != nil {
			failed++
			tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
			fmt.Fprintln(stderr, st.Fail(fmt.Sprintf("%s: %v", r.Cluster, err)))
			continue
		}
		tr.end(ctx, audit.OutcomeSuccess, "", ev.Detail, stderr)
		fmt.Fprintln(stdout, st.OK(fmt.Sprintf("closed the tunnel to %s (127.0.0.1:%d)", r.Cluster, r.Port)))
	}
	if failed > 0 {
		return ExitFailure
	}
	return ExitOK
}

// closeWait is how long close waits for a holder to stop; a var for tests.
var closeWait = 10 * time.Second

// requestClose asks the holder to stop its tunnel and waits until it has.
func requestClose(ctx context.Context, cfg config.Config, r tunnelRecord) error {
	if r.State == nil {
		return fmt.Errorf("held by an older nedctl that cannot be asked to close — end it in its own terminal (pid %d)", r.PID)
	}
	p, err := closeRequestPath(cfg, r.Cluster)
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		return err
	}
	rec, _ := tunnelRecordPath(cfg, r.Cluster)
	deadline := time.Now().Add(closeWait)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(rec)
		var cur tunnelRecord
		if err != nil || json.Unmarshal(data, &cur) != nil || cur.PID != r.PID || (cur.State != nil && cur.State.Session == "closed") {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	_ = os.Remove(p)
	return fmt.Errorf("its holder (pid %d) did not respond within %s", r.PID, closeWait)
}

func printTunnels(w io.Writer, cfg config.Config, live []tunnelRecord) {
	st := ui.Style{Color: colorOn(w)}
	if len(live) == 0 {
		fmt.Fprintln(w, "no tunnels are open — nedctl kube or nedctl connect opens one")
		return
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "CLUSTER\tPORT\tVIA\tSESSION\tUSED BY\tHELD BY\tOPEN FOR")
	for _, r := range live {
		session := "open"
		if s := r.State; s != nil {
			switch {
			case s.Session == "open" && s.Conns > 0:
				session = fmt.Sprintf("open, %d connection(s)", s.Conns)
			case s.Session == "open":
				session = "open, idle " + shortDuration(now().Sub(s.Since).Round(time.Minute))
			case s.Session == "idle-closed":
				session = "closed when idle (reopens on use)"
			default:
				session = s.Session
			}
		}
		users := "you"
		if n := tunnelUsers(cfg, r.Cluster); n > 0 {
			users = fmt.Sprintf("you + %d session(s)", n)
		}
		fmt.Fprintf(tw, "%s\t127.0.0.1:%d\t%s\t%s\t%s\t%s (pid %d)\t%s\n", r.Cluster, r.Port, firstNonBlank(r.HopName, r.Hop), session, users,
			firstNonBlank(r.Holder, "nedctl"), r.PID, shortDuration(now().Sub(r.Started).Round(time.Minute)))
	}
	tw.Flush()
	idle := "never (tunnelIdleTimeout is 0)"
	if d := cfg.TunnelIdle(); d > 0 {
		idle = "after " + shortDuration(d) + " unused"
	}
	fmt.Fprintf(w, "\n%s\n", st.Dim("Session Manager sessions close "+idle+"; nedctl tunnels close CLUSTER|--all closes a tunnel for good"))
}
