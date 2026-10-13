package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/inventory"
)

// `nedctl exec POD` opens a shell (or runs a command) inside a container,
// the way `kubectl exec -it` does, with what a bank needs around it: the
// session is recorded in the audit trail, production asks for a change
// record or a break-glass reason when change control is on, and production
// sessions are recorded (redacted) with the recording's SHA-256 in the
// trail.

func cmdExec(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	var command []string
	for i, a := range args {
		if a == "--" {
			args, command = args[:i], args[i+1:]
			break
		}
	}
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ns := fs.String("n", "default", "namespace")
	container := fs.String("c", "", "container (default: the pod's first)")
	cluster := fs.String("cluster", "", "the cluster (default: pick one)")
	env := fs.String("env", "", "AKS: the environment whose bastion to use")
	profile := fs.String("aws-profile", "", "EKS: the AWS profile to act with")
	cr := fs.String("change-record", "", "change record, when change control requires one")
	glass := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	yes := fs.Bool("yes", false, "skip the production confirmation and pause")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 || !podNameRe.MatchString(pos[0]) || !config.ValidNamespace(*ns) || (*container != "" && !podNameRe.MatchString(*container)) {
		fmt.Fprintln(stderr, "usage: nedctl exec POD [-c CONTAINER] [-n NS] [--cluster C] [--change-record CHG | --break-glass REASON] [-- COMMAND…]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: *cluster, env: *env, awsProfile: *profile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	prod := s.pc.Production || cfg.IsProdEnvironment(s.env)
	if !confirmProduction(cfg, s.pc, s.cluster, *yes, stderr) || !productionPause(ctx, cfg, prod, s.cluster, *yes, stderr) {
		return ExitFailure
	}
	kargs := []string{"exec", "-it", pos[0], "-n", *ns}
	if *container != "" {
		kargs = append(kargs, "-c", *container)
	}
	shown := "a shell"
	if len(command) > 0 {
		kargs = append(append(kargs, "--"), command...)
		shown = strings.Join(command, " ")
	} else {
		kargs = append(kargs, "--", "sh", "-c", sizedShell())
	}
	base := audit.Event{Action: "kube-exec", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: prod,
		ChangeRecord: strings.TrimSpace(*cr), BreakGlass: strings.TrimSpace(*glass) != "", BreakGlassReason: strings.TrimSpace(*glass),
		Detail: fmt.Sprintf("%s in pod %s/%s%s, %s", shown, *ns, pos[0], ifNonBlank(" container ", *container), s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, base.ChangeRecord, *glass, tr, stderr); code != ExitOK {
		return code
	}
	note, err := recordSession(ctx, cfg, s, prod, map[string]any{"action": "kube-exec", "pod": *ns + "/" + pos[0]}, stderr, kargs...)
	switch {
	case errors.Is(err, errNotRecorded):
		tr.end(ctx, audit.OutcomeRefused, s.pc.Role, err.Error(), stderr)
		fmt.Fprintln(stderr, err)
		return ExitFailure
	case err != nil:
		// The shell's own exit status (exit 1 after a failed command) is
		// not nedctl's failure; the session happened.
		tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail+note+"; ended: "+err.Error(), stderr)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail+note, stderr)
	return ExitOK
}
