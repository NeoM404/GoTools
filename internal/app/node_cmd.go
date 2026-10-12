package app

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/inventory"
	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// `nedctl node cordon|uncordon|drain` with the checks people skip under
// pressure: before a drain it lists what will move, the disruption budgets
// that would block it and the pods nothing will recreate, has the cluster
// dry-run it, and asks. Recorded, and subject to change control.

var drainTimeoutRe = regexp.MustCompile(`^[0-9]+(s|m)$`)

func cmdNode(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	usage := "usage: nedctl node <cordon|uncordon|drain> NODE [--cluster C] [--dry-run] [--yes] [--timeout 5m]"
	if len(args) == 0 || (args[0] != "cordon" && args[0] != "uncordon" && args[0] != "drain") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("node "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	yes := fs.Bool("yes", false, "do it without asking (after showing and dry-running it)")
	dryRun := fs.Bool("dry-run", false, "show and dry-run only; change nothing")
	timeout := fs.String("timeout", "5m", "drain: give up after this long")
	cr := fs.String("change-record", "", "change record, when change control requires one")
	glass := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil || len(pos) != 1 || !nodeNameRe.MatchString(pos[0]) || !drainTimeoutRe.MatchString(*timeout) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	node := pos[0]
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	sp := spinning(stderr, "Looking up "+node+" on "+s.label()+"…")
	_, err = s.output(ctx, "", "get", "node", node, "-o", "name")
	sp.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "node %s on %s: %v\n", node, s.label(), err)
		return ExitFailure
	}
	st := ui.Style{Color: colorOn(stderr)}
	kargs := []string{action, node}
	if action == "drain" {
		kargs = append(kargs, "--ignore-daemonsets", "--delete-emptydir-data", "--timeout="+*timeout)
	}
	fmt.Fprintf(stderr, "\n%s %s %s on %s (%s)\n  kubectl %s\n", st.Bold("To"), action, node, st.BoldFg(cfg.ColorFor(s.env), s.label()), s.where, strings.Join(kargs, " "))
	moving := 0
	if action == "drain" {
		moving = drainPreview(ctx, s, node, stderr)
	}
	sp = spinning(stderr, "Asking the cluster for a dry run…")
	out, err := s.output(ctx, "", append(append([]string{}, kargs...), "--dry-run=server")...)
	sp.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", st.Fail("The cluster refuses it (server-side dry run):"), err)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "%s\n%s", st.OK("The cluster accepts it (server-side dry run):"), indentLines(indentLines(string(out))))
	if *dryRun {
		fmt.Fprintln(stderr, "Dry run only — nothing was changed.")
		return ExitOK
	}
	if !confirmProduction(cfg, s.pc, s.cluster, false, stderr) {
		return ExitFailure
	}
	if !*yes {
		if !stdinIsTerminal() {
			fmt.Fprintln(stderr, "nothing changed: pass --yes to do it without a terminal (or --dry-run to only check)")
			return ExitUsage
		}
		fmt.Fprintf(stderr, "%s %s? [y/N] ", strings.ToUpper(action[:1])+action[1:], node)
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(stderr, "nothing changed")
			return ExitFailure
		}
	}
	base := audit.Event{Action: "node-" + action, Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		ChangeRecord: strings.TrimSpace(*cr), BreakGlass: strings.TrimSpace(*glass) != "", BreakGlassReason: strings.TrimSpace(*glass),
		Detail: fmt.Sprintf("%s node %s, %s", action, node, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, base.ChangeRecord, *glass, tr, stderr); code != ExitOK {
		return code
	}
	var kout, kerr io.Writer = safetext.Writer(stdout), safetext.Writer(stderr)
	var view *drainView
	if action == "drain" && colorOn(stderr) && !reducedMotion() {
		view = newDrainView(stderr, node, moving)
		kout, kerr = view, view
	}
	err = s.kubectl(ctx, kargs, strings.NewReader(""), kout, kerr, false)
	if view != nil {
		view.stop()
	} else {
		flushSafe(kout, kerr)
	}
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "%s did not complete: %v\n", action, err)
		if action == "drain" {
			fmt.Fprintf(stderr, "%s\n", st.Hint("the node stays cordoned; see what blocks it above, then run drain again — or `nedctl node uncordon "+node+"` to give it back"))
		}
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail, stderr)
	fmt.Fprintln(stderr, st.OK(fmt.Sprintf("%s %s done", action, node)))
	return ExitOK
}

// drainPreview lists what a drain moves and what could block it.
func drainPreview(ctx context.Context, s *kubeSession, node string, stderr io.Writer) int {
	st := ui.Style{Color: colorOn(stderr)}
	sp := spinning(stderr, "Listing the pods on "+node+"…")
	out, err := s.output(ctx, "", "get", "pods", "-A", "--field-selector", "spec.nodeName="+node, "-o",
		`jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.ownerReferences[0].kind}{"\n"}{end}`)
	sp.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "  (could not list the node's pods: %v)\n", err)
		return 0
	}
	moves, bare, daemons := []string{}, []string{}, 0
	namespaces := map[string]bool{}
	for _, l := range nonEmptyLines(string(out)) {
		f := strings.Split(l, "\t")
		if len(f) < 3 {
			continue
		}
		switch f[2] {
		case "DaemonSet":
			daemons++
		case "":
			bare = append(bare, f[0]+"/"+f[1])
		default:
			moves = append(moves, f[0]+"/"+f[1])
			namespaces[f[0]] = true
		}
	}
	fmt.Fprintf(stderr, "  %d pod(s) will move to other nodes; %d DaemonSet pod(s) stay\n", len(moves), daemons)
	for i, m := range moves {
		if i == 10 {
			fmt.Fprintf(stderr, "    … and %d more\n", len(moves)-10)
			break
		}
		fmt.Fprintf(stderr, "    %s\n", m)
	}
	for _, b := range bare {
		fmt.Fprintf(stderr, "  %s\n", st.Fail("pod "+b+" belongs to no controller: the drain stops on it (nedctl never forces); move or delete it first"))
	}
	sp = spinning(stderr, "Checking disruption budgets…")
	out, err = s.output(ctx, "", "get", "pdb", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.disruptionsAllowed}{"\n"}{end}`)
	sp.Stop()
	if err == nil {
		var blocking []string
		for _, l := range nonEmptyLines(string(out)) {
			if f := strings.Split(l, "\t"); len(f) == 3 && f[2] == "0" && namespaces[f[0]] {
				blocking = append(blocking, f[0]+"/"+f[1])
			}
		}
		sort.Strings(blocking)
		for _, b := range blocking {
			fmt.Fprintf(stderr, "  %s\n", st.Warn("disruption budget "+b+" allows no disruption now: the drain waits for it (up to --timeout)"))
		}
	}
	return len(moves)
}
