package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl fleet run -- kubectl …` runs one read-only kubectl command on
// many clusters — every cluster on a bastion in one SSH connection — and
// shows the answers per cluster: "where does image X run?", "which
// clusters still serve API Y?". Changes go through runbooks, never here.

// readOnlyVerbs are the kubectl commands fleet run accepts.
var readOnlyVerbs = map[string]bool{
	"get": true, "describe": true, "logs": true, "top": true, "version": true, "api-resources": true,
	"api-versions": true, "explain": true, "cluster-info": true, "events": true,
}

// checkReadOnly refuses anything but a read-only kubectl command, and
// flags that would point it elsewhere or never return.
func checkReadOnly(cmd []string) error {
	if len(cmd) < 2 || cmd[0] != "kubectl" {
		return fmt.Errorf("give a kubectl command after --, e.g. -- kubectl get pods -A")
	}
	verb := cmd[1]
	switch {
	case verb == "auth" && len(cmd) > 2 && (cmd[2] == "can-i" || cmd[2] == "whoami"):
	case !readOnlyVerbs[verb]:
		return fmt.Errorf("fleet run is read-only: %q is not allowed (use get, describe, logs, top, events, …; changes go through `nedctl run`)", verb)
	}
	for _, a := range cmd[2:] {
		name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		switch name {
		case "kubeconfig", "context", "cluster", "server", "s", "token", "user", "as", "as-group", "as-uid", "certificate-authority", "client-key", "client-certificate", "insecure-skip-tls-verify":
			return fmt.Errorf("%s is not allowed: nedctl chooses the clusters", a)
		case "f", "follow", "w", "watch", "watch-only":
			return fmt.Errorf("%s is not allowed: across many clusters a command must finish", a)
		}
	}
	return nil
}

func fleetRun(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleet run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	prefix := fs.Bool("prefix", false, "start every line with its cluster's name (for grep) instead of a heading per cluster")
	ours, command := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			ours, command = args[:i], args[i+1:]
			break
		}
	}
	if pos, err := parseInterspersed(fs, ours); err != nil || len(pos) > 0 || command == nil {
		fmt.Fprintln(stderr, "usage: nedctl fleet run [--env qa | --aws | --cluster C] [--match WORD] [--prefix] -- kubectl <read-only command>")
		return ExitUsage
	}
	if err := checkReadOnly(command); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, []probe{command[1:]}, stderr)
	if code != ExitOK {
		return code
	}
	st := ui.Style{Color: colorOn(stdout)}
	failed := 0
	for i, r := range results {
		name := firstNonBlank(r.Cluster, r.Where)
		err := r.reachErr()
		if !*prefix {
			if i > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprintln(stdout, st.BoldFg(cfg.ColorFor(r.Env), "== "+strings.TrimSpace(strings.ToUpper(r.Env)+" "+name)))
		}
		if err != nil {
			failed++
			if *prefix {
				fmt.Fprintf(stdout, "%s  %s\n", name, st.Fail(err.Error()))
			} else {
				fmt.Fprintln(stdout, st.Fail(err.Error()))
			}
			continue
		}
		for _, l := range strings.Split(strings.TrimRight(string(r.Outs[0].Out), "\n"), "\n") {
			if *prefix {
				if l != "" {
					fmt.Fprintf(stdout, "%s  %s\n", name, l)
				}
			} else {
				fmt.Fprintln(stdout, l)
			}
		}
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "%d of %d cluster(s) failed\n", failed, len(results))
		return ExitFailure
	}
	return ExitOK
}
