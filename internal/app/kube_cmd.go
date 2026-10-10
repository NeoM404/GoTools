package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
	"nedctl/internal/picker"
)

// tunnelReadyTimeout bounds the wait for the port-forward to accept
// connections (Session Manager takes a few seconds through a proxy).
var tunnelReadyTimeout = 60 * time.Second

// cmdKube is connect in one step: the tunnel runs in the background, a shell
// (or one command after --) runs with KUBECONFIG set, and leaving the shell
// closes the tunnel. Same preparation, audit and change control as connect.
func cmdKube(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kube", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to act with (default: $AWS_PROFILE, then the last `nedctl aws login`)")
	viaInstance := fs.String("via-instance", "", "instance to tunnel through (default: the account's devops instance)")
	port := fs.Int("port", 0, "local port for the tunnel (default: a free one)")
	via := fs.String("via", viaAuto, "auto (direct if the endpoint answers from here, else the devops instance), direct, or bastion")
	crFlag := fs.String("change-record", "", "change record for this access, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	var rs regionSearch
	addRegionFlags(fs, &rs)

	ours, command := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			ours, command = args[:i], args[i+1:]
			break
		}
	}
	pos, err := parseInterspersed(fs, ours)
	if err != nil {
		return ExitUsage
	}
	if len(pos) > 1 || (len(pos) == 1 && !eksNameRe.MatchString(pos[0])) || (command != nil && len(command) == 0) {
		fmt.Fprintln(stderr, "usage: nedctl kube [eks-cluster] [--profile P] [--via auto|direct|bastion] [--via-instance I] [--port N] [--region R] [-- command args…]")
		return ExitUsage
	}
	if *port < 0 || *port > 65535 {
		fmt.Fprintln(stderr, "--port must be 1-65535")
		return ExitUsage
	}
	if !validVia(*via) {
		fmt.Fprintf(stderr, "--via %q: want auto, direct or bastion\n", *via)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	pc, ok := loadProfileContext(ctx, cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	name, rs, code := resolveClusterArg(ctx, cfg, pc, rs, pos, stderr)
	if code != ExitOK {
		return code
	}
	plan, code := planTunnel(ctx, cfg, pc, rs, name, *via, *viaInstance, *port, stderr)
	if code != ExitOK {
		return code
	}
	saveLastCluster(cfg, pc, name)

	what := "interactive shell"
	if command != nil {
		what = "command " + command[0]
	}
	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	base := audit.Event{Action: "eks-connect", Cloud: "aws", Cluster: plan.cluster.Name, Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("kube %s; tunnel 127.0.0.1:%d → %s:443 via %s (%s), profile %s", what, plan.port, plan.cluster.Host,
			plan.hop.ID, firstNonBlank(plan.hop.Name, "unnamed"), pc.Name)}
	if plan.direct {
		base.Detail = fmt.Sprintf("kube %s; direct to %s:443, profile %s", what, plan.cluster.Host, pc.Name)
	}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to connect: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: plan.cluster.Name, Environment: pc.Environment}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}

	if plan.direct {
		banner(cfg, pc, plan.cluster.Name, stderr)
		fmt.Fprintln(stderr, "Direct: the endpoint answers from here, no tunnel needed.")
		return runKubeChild(ctx, cfg, pc, plan, command, tr, base, nil, "", stderr)
	}
	logPath, logFile, err := tunnelLog(cfg, plan.cluster.Name)
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "opening the tunnel log: %v\n", err)
		return ExitFailure
	}
	defer logFile.Close()
	banner(cfg, pc, plan.cluster.Name, stderr)
	fmt.Fprintf(stderr, "Opening the tunnel through %s…\n", firstNonBlank(plan.hop.Name, plan.hop.ID))
	tunnel, err := execx.Start(ctx, execx.Spec{Name: "aws", Args: portForwardArgs(plan, pc.Name),
		Stdout: logFile, Stderr: logFile, Timeout: cfg.AWS.Timeout()})
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "starting the tunnel: %v\n", err)
		return ExitFailure
	}
	defer tunnel.Stop(3 * time.Second)
	if err := waitForTunnel(tunnel, plan.port, tunnelReadyTimeout); err != nil {
		tunnel.Stop(3 * time.Second)
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "the tunnel did not open: %v\n%s(full log: %s)\n", err, logTail(logPath, 8), logPath)
		return ExitFailure
	}

	return runKubeChild(ctx, cfg, pc, plan, command, tr, base, tunnel, logPath, stderr)
}

// runKubeChild runs the shell or the command with KUBECONFIG set, then
// closes the tunnel (when there is one) and the audit record.
func runKubeChild(ctx context.Context, cfg config.Config, pc profileContext, plan tunnelPlan, command []string,
	tr *trail, base audit.Event, tunnel *execx.Process, logPath string, stderr io.Writer) int {
	env := []string{"KUBECONFIG=" + plan.kubeconfig, "NEDCTL_KUBECONFIG=" + plan.kubeconfig, "NEDCTL_KUBE=" + plan.cluster.Name}
	var childErr error
	if command != nil {
		childErr = execx.Interactive(ctx, execx.Spec{Name: command[0], Args: command[1:], Env: env, Timeout: cfg.AWS.Timeout()})
	} else {
		name, shellArgs, shellEnv, cleanup := kubeShell(cfg, pc, plan.cluster.Name)
		defer cleanup()
		closing := "Type exit to close the tunnel."
		if tunnel == nil {
			closing = "Type exit when done."
		}
		fmt.Fprintf(stderr, "⎈ %s ready — kubectl works in this shell. %s\n  other terminals: export KUBECONFIG=%s\n", plan.cluster.Name, closing, plan.kubeconfig)
		childErr = execx.Interactive(ctx, execx.Spec{Name: name, Args: shellArgs, Env: append(env, shellEnv...), Timeout: cfg.AWS.Timeout()})
	}

	if tunnel != nil {
		if done, terr := tunnel.Exited(); done {
			fmt.Fprintf(stderr, "warning: the tunnel ended while you were working (%v)\n%s", terr, logTail(logPath, 5))
		}
		tunnel.Stop(3 * time.Second)
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	if tunnel != nil {
		fmt.Fprintln(stderr, "tunnel closed")
	}

	if childErr != nil && command != nil {
		var exit *exec.ExitError
		if errors.As(childErr, &exit) && exit.ExitCode() > 0 {
			return exit.ExitCode() // scripts see the command's own exit code
		}
		fmt.Fprintf(stderr, "%v\n", childErr)
		return ExitFailure
	}
	return ExitOK
}

// waitForTunnel polls until the local port accepts a connection, failing
// as soon as the port-forward process ends or the deadline passes.
func waitForTunnel(p *execx.Process, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	for {
		if done, err := p.Exited(); done {
			if err == nil {
				err = errors.New("the port-forward ended")
			}
			return err
		}
		if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("port %d not open after %s", port, timeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// tunnelLog opens a fresh 0600 log for the port-forward's output, next to
// the audit log, so the plugin's chatter stays out of the shell.
func tunnelLog(cfg config.Config, cluster string) (string, *os.File, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", nil, err
	}
	dir := filepath.Join(filepath.Dir(log), "tunnels")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	p := filepath.Join(dir, cluster+".log")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	return p, f, err
}

func logTail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, "  | "+l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// kubeShell returns the shell to start, its arguments and extra
// environment. The user's own startup files load first; afterwards
// KUBECONFIG is set back to this cluster's (a ~/.bashrc or ~/.zshrc that
// exports KUBECONFIG would otherwise silently point kubectl elsewhere),
// with a note when that happened, and the prompt is prefixed with the
// cluster in its environment's colour. bash and zsh get this; other shells
// start as they are with KUBECONFIG in their environment.
func kubeShell(cfg config.Config, pc profileContext, cluster string) (string, []string, []string, func()) {
	none := func() {}
	shell := os.Getenv("SHELL")
	if shell == "" {
		if runtime.GOOS == "windows" {
			return "powershell.exe", []string{"-NoLogo"}, nil, none
		}
		shell = "/bin/sh"
	}
	label := "⎈ " + strings.TrimSpace(cluster+" "+strings.ToUpper(pc.Environment))
	r, g, b, colored := picker.RGB(cfg.ColorFor(pc.Environment))
	colored = colored && os.Getenv("NO_COLOR") == ""
	// The cluster name is restricted to [A-Za-z0-9_-] and the environment to
	// letters, so nothing below can break out of its quotes.
	restore := `if [ -n "$NEDCTL_KUBECONFIG" ] && [ "$KUBECONFIG" != "$NEDCTL_KUBECONFIG" ]; then
  echo "nedctl: your shell startup changed KUBECONFIG; set back to $NEDCTL_KUBECONFIG for this shell" >&2
fi
export KUBECONFIG="$NEDCTL_KUBECONFIG"
`
	switch filepath.Base(shell) {
	case "bash":
		prefix := label
		if colored {
			prefix = fmt.Sprintf(`\[\e[1;38;2;%d;%d;%dm\]%s\[\e[0m\]`, r, g, b, label)
		}
		rc, err := os.CreateTemp("", "nedctl-kube-*.bashrc")
		if err != nil {
			return shell, nil, nil, none
		}
		// __nedctl_kube_prefix keeps the prefix when `nedctl prompt init`
		// rebuilds PS1 before each prompt.
		fmt.Fprintf(rc, "[ -f ~/.bashrc ] && . ~/.bashrc\n%sPS1='%s '\"$PS1\"\n__nedctl_kube_prefix='%s'\n", restore, prefix, prefix)
		rc.Close()
		_ = os.Chmod(rc.Name(), 0o600)
		return shell, []string{"--rcfile", rc.Name(), "-i"}, nil, func() { os.Remove(rc.Name()) }
	case "zsh":
		prefix := label
		if colored {
			prefix = fmt.Sprintf("%%B%%F{#%02x%02x%02x}%s%%f%%b", r, g, b, label)
		}
		dir, err := os.MkdirTemp("", "nedctl-kube-zsh-")
		if err != nil {
			return shell, nil, nil, none
		}
		// zsh reads .zshenv and .zshrc from $ZDOTDIR: these load the user's
		// own files from $HOME, then restore KUBECONFIG and set the prompt.
		_ = os.WriteFile(filepath.Join(dir, ".zshenv"), []byte(`[ -f "$HOME/.zshenv" ] && . "$HOME/.zshenv"`+"\n"), 0o600)
		_ = os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(`export ZDOTDIR="$HOME"
[ -f "$HOME/.zshrc" ] && . "$HOME/.zshrc"
`+restore+`PROMPT='`+prefix+` '"$PROMPT"
__nedctl_kube_prefix='`+prefix+`'
`), 0o600)
		return shell, []string{"-i"}, []string{"ZDOTDIR=" + dir}, func() { os.RemoveAll(dir) }
	}
	return shell, nil, nil, none
}
