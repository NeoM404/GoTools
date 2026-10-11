package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/picker"
)

// kubeSession runs kubectl against one chosen cluster, for commands that
// need several calls (look, show, deploy, use, clean up): on this machine
// through the EKS tunnel (held open for the whole session) or directly, or
// on the AKS bastion over SSH with the cluster selected for each call only.
type kubeSession struct {
	cloud, cluster, env, where string
	pc                         profileContext
	bastion                    *sshTarget // AKS: the bastion kubectl runs on
	// kubectl runs kubectl with args; tty asks for a terminal (exec -it).
	kubectl func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) error
	close   func()
}

// output runs kubectl and returns its stdout; its stderr is in the error.
func (s *kubeSession) output(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	if err := s.kubectl(ctx, args, strings.NewReader(stdin), &out, &errb, false); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return out.Bytes(), fmt.Errorf("%s", msg)
		}
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

// interactive runs kubectl attached to the terminal.
func (s *kubeSession) interactive(ctx context.Context, args ...string) error {
	return s.kubectl(ctx, args, childStdin(), nil, nil, true)
}

func (s *kubeSession) label() string {
	return strings.ToUpper(s.env) + " · " + s.cluster
}

// sessionFlags pick the cluster a session is for.
type sessionFlags struct {
	cluster, env, awsProfile string
}

// openKubeSession settles the cloud and the cluster, then opens the way
// to it. An AKS cluster is recognised by --env or by a name nedctl has seen
// on a bastion (or that names an environment with a bastion); otherwise
// EKS. With neither configured both ways, a picker asks.
func openKubeSession(ctx context.Context, cfg config.Config, f sessionFlags, stderr io.Writer) (*kubeSession, int) {
	aws, azure := cfg.AWS.Configured(), cfg.Azure.Configured()
	cloud := ""
	switch {
	case !aws && !azure:
		fmt.Fprintln(stderr, "no clusters to reach — run `nedctl setup` (AWS) or add azure.bastions to the config (Azure)")
		return nil, ExitFailure
	case f.env != "" || (azure && f.cluster != "" && envOfName(cfg, f.cluster) != ""):
		cloud = "azure"
	case aws && !azure, f.cluster != "" && aws:
		cloud = "aws"
	case azure && !aws:
		cloud = "azure"
	case !stdinIsTerminal():
		fmt.Fprintln(stderr, "which cluster? pass --cluster NAME (and --env ENV for AKS)")
		return nil, ExitUsage
	default:
		idx, err := picker.Picker{Title: "Which cloud", Header: []string{"CLOUD", "CLUSTERS"},
			Rows: []picker.Row{{Cells: []string{"AWS", "EKS in the account you are signed in to"}}, {Cells: []string{"Azure", "AKS through the bastions"}}},
			In:   stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return nil, ExitFailure
		}
		cloud = []string{"aws", "azure"}[idx]
	}
	if cloud == "azure" {
		if !azure {
			fmt.Fprintln(stderr, "Azure access is not set up (azure.bastions) — see docs/azure.md")
			return nil, ExitFailure
		}
		return openAKSSession(ctx, cfg, f, stderr)
	}
	return openEKSSession(ctx, cfg, f, stderr)
}

func openAKSSession(ctx context.Context, cfg config.Config, f sessionFlags, stderr io.Writer) (*kubeSession, int) {
	env := strings.ToLower(f.env)
	if env == "" && f.cluster != "" {
		env = envOfName(cfg, f.cluster)
	}
	env, code := chooseEnv(cfg, env, stderr)
	if code != ExitOK {
		return nil, code
	}
	t := bastionTarget(cfg, env)
	pc := azurePC(cfg, t)
	var terms []string
	if f.cluster != "" {
		terms = []string{f.cluster}
	}
	name, code := chooseAKS(ctx, cfg, t, pc, terms, false, stderr)
	if code != ExitOK {
		return nil, code
	}
	saveLast(cfg, pc, "aks", name)
	label, title := promptLabel(cfg, env, name, false), strings.ToUpper(env)+" · "+name
	s := &kubeSession{cloud: "azure", cluster: name, env: env, where: "on bastion " + t.Name, pc: pc, bastion: &t, close: func() {}}
	s.kubectl = func(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, tty bool) error {
		remote := remoteBash(sessionScript, append([]string{label, title, "", name, "kubectl"}, args...)...)
		err := execx.Interactive(ctx, execx.Spec{Stdin: in, Stdout: out, Stderr: errw, Name: "ssh",
			Args: sshArgs(cfg, t, tty, remote), Timeout: cfg.AWS.Timeout()})
		if err != nil {
			return sshError(t, err)
		}
		return nil
	}
	return s, ExitOK
}

// sessionTunnelPort is the local tunnel port (0: a free one); tests set it.
var sessionTunnelPort = 0

func openEKSSession(ctx context.Context, cfg config.Config, f sessionFlags, stderr io.Writer) (*kubeSession, int) {
	pc, ok := loadProfileContext(ctx, cfg, f.awsProfile, stderr)
	if !ok {
		return nil, ExitFailure
	}
	var pos []string
	if f.cluster != "" {
		if !eksNameRe.MatchString(f.cluster) {
			fmt.Fprintf(stderr, "--cluster %q is not a cluster name\n", f.cluster)
			return nil, ExitUsage
		}
		pos = []string{f.cluster}
	}
	name, rs, code := resolveClusterArg(ctx, cfg, pc, regionSearch{}, pos, stderr)
	if code != ExitOK {
		return nil, code
	}
	plan, code := planTunnel(ctx, cfg, pc, rs, name, viaAuto, "", sessionTunnelPort, stderr)
	if code != ExitOK {
		return nil, code
	}
	saveLastCluster(cfg, pc, name)
	s := &kubeSession{cloud: "aws", cluster: plan.cluster.Name, env: pc.Environment, pc: pc, where: "directly", close: func() {}}
	if !plan.direct {
		logPath, logFile, err := tunnelLog(cfg, plan.cluster.Name)
		if err != nil {
			fmt.Fprintf(stderr, "opening the tunnel log: %v\n", err)
			return nil, ExitFailure
		}
		fmt.Fprintf(stderr, "Opening the tunnel through %s…\n", firstNonBlank(plan.hop.Name, plan.hop.ID))
		tunnel, err := execx.Start(ctx, execx.Spec{Name: "aws", Args: portForwardArgs(plan, pc.Name), Stdout: logFile, Stderr: logFile, Timeout: cfg.AWS.Timeout()})
		if err != nil {
			logFile.Close()
			fmt.Fprintf(stderr, "starting the tunnel: %v\n", err)
			return nil, ExitFailure
		}
		if err := waitForTunnel(tunnel, plan.port, tunnelReadyTimeout); err != nil {
			tunnel.Stop(3 * time.Second)
			logFile.Close()
			fmt.Fprintf(stderr, "the tunnel did not open: %v\n%s(full log: %s)\n", err, logTail(logPath, 8), logPath)
			return nil, ExitFailure
		}
		s.where = "through " + firstNonBlank(plan.hop.Name, plan.hop.ID)
		s.close = func() {
			tunnel.Stop(3 * time.Second)
			logFile.Close()
		}
	}
	env := []string{"KUBECONFIG=" + plan.kubeconfig}
	s.kubectl = func(ctx context.Context, args []string, in io.Reader, out, errw io.Writer, tty bool) error {
		return execx.Interactive(ctx, execx.Spec{Stdin: in, Stdout: out, Stderr: errw, Name: "kubectl", Args: args, Env: env, Timeout: cfg.AWS.Timeout()})
	}
	return s, ExitOK
}
