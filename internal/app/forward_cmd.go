package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
)

// `nedctl forward` makes a service, pod or deployment in a cluster
// reachable on this machine's 127.0.0.1, for a browser, Postman or a
// database tool. On EKS kubectl port-forwards through the session's
// tunnel. On AKS kubectl port-forwards on the bastion (to its loopback)
// and SSH carries that port here, in one SSH connection; when it ends,
// both end.

// bastionPort picks the bastion-side port; a seam for tests.
var bastionPort = func() int { return 30000 + rand.IntN(30000) }

func cmdForward(ctx context.Context, cfgPath string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	ns := addNamespaceFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	usage := "usage: nedctl forward <svc/NAME|pod/NAME|deploy/NAME> [LOCAL:]REMOTE [-n NS] [--cluster C]"
	if len(pos) != 2 || !config.ValidNamespace(*ns) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	target, ok := forwardTarget(pos[0])
	local, remote, perr := parsePorts(pos[1])
	if !ok || perr != nil {
		if perr != nil {
			fmt.Fprintln(stderr, perr)
		}
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(local))); err != nil {
		fmt.Fprintf(stderr, "port %d is in use on this machine — choose another: %d:%d\n", local, local+1, remote)
		return ExitFailure
	} else {
		ln.Close()
	}
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
	if !confirmProduction(cfg, s.pc, s.cluster, false, stderr) {
		return ExitFailure
	}
	base := audit.Event{Action: "port-forward", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("%s in %s port %d to 127.0.0.1:%d here, %s", target, *ns, remote, local, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "Forwarding 127.0.0.1:%d → %s:%d in %s on %s. Ctrl-C stops.\n", local, target, remote, *ns, s.label())
	if remote == 443 || remote == 8443 {
		fmt.Fprintf(stderr, "  open https://127.0.0.1:%d/\n", local)
	} else if remote == 80 || remote == 8080 || remote == 3000 {
		fmt.Fprintf(stderr, "  open http://127.0.0.1:%d/\n", local)
	}

	if s.bastion == nil {
		err = s.kubectl(ctx, []string{"port-forward", "-n", *ns, target, fmt.Sprintf("%d:%d", local, remote), "--address", "127.0.0.1"}, childStdin(), io.Discard, stderr, true)
	} else {
		bp := bastionPort()
		remoteCmd := remoteBash(sessionScript, "", "", "", s.cluster, "kubectl", "port-forward", "-n", *ns, target, fmt.Sprintf("%d:%d", bp, remote), "--address", "127.0.0.1")
		sshargs := append([]string{"-o", "ExitOnForwardFailure=yes", "-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", local, bp)},
			sshArgs(cfg, *s.bastion, stdinIsTerminal(), remoteCmd)...)
		err = execx.Interactive(ctx, execx.Spec{Stdin: childStdin(), Stdout: io.Discard, Name: "ssh", Args: sshargs, Timeout: cfg.AWS.Timeout()})
		if err != nil {
			err = sshError(*s.bastion, err)
		}
	}
	if err != nil && ctx.Err() == nil && !interruptedExit(err) {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "forwarding ended: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail, stderr)
	fmt.Fprintln(stderr, "forwarding stopped")
	return ExitOK
}

// interruptedExit is a child ended by Ctrl-C (exit 130), the normal way
// to stop forwarding.
func interruptedExit(err error) bool {
	return strings.Contains(err.Error(), "exit status 130") || strings.Contains(err.Error(), "signal: interrupt")
}

func forwardTarget(s string) (string, bool) {
	kind, name, ok := strings.Cut(s, "/")
	if !ok || !podNameRe.MatchString(name) {
		return "", false
	}
	switch strings.ToLower(kind) {
	case "svc", "service":
		return "svc/" + name, true
	case "pod", "po":
		return "pod/" + name, true
	case "deploy", "deployment":
		return "deployment/" + name, true
	case "sts", "statefulset":
		return "statefulset/" + name, true
	}
	return "", false
}

// parsePorts reads REMOTE or LOCAL:REMOTE. Without a local port the remote
// one is used, unless it is privileged (below 1024): then 8000+remote.
func parsePorts(s string) (local, remote int, err error) {
	l, r, two := strings.Cut(s, ":")
	if !two {
		r = l
	}
	if remote, err = strconv.Atoi(r); err != nil || remote < 1 || remote > 65535 {
		return 0, 0, fmt.Errorf("%q: ports are 1-65535", s)
	}
	switch {
	case two:
		if local, err = strconv.Atoi(l); err != nil || local < 1 || local > 65535 {
			return 0, 0, fmt.Errorf("%q: ports are 1-65535", s)
		}
	case remote < 1024:
		local = 8000 + remote
	default:
		local = remote
	}
	return local, remote, nil
}
