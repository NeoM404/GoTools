package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
	"nedctl/internal/picker"
)

// Azure access goes through SSH. Each environment's AKS bastion holds the
// kubeconfig the platform provisions (a shared AKS local account), and
// there is no az CLI to fetch per-person credentials, so nedctl does not
// bring clusters to the workstation: it takes the engineer to the right
// bastion with the right cluster selected for that session only, coloured
// by environment and recorded. The same works from WSL, macOS and Windows
// (OpenSSH ships with Windows 10 and 11).

// sshTarget is one machine nedctl opens SSH to.
type sshTarget struct {
	Name, Dest, Env, Jump string
	Bastion               bool
}

// kubeContextRe is a kube-context nedctl selects on a bastion. AKS names
// contexts after their cluster; anything else is left out of the lists.
var kubeContextRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// azureTargets lists the bastions, in environment order, then the hosts.
func azureTargets(cfg config.Config) []sshTarget {
	var list []sshTarget
	for _, env := range azureEnvs(cfg) {
		dest, _ := cfg.Azure.Bastion(env)
		list = append(list, sshTarget{Name: bastionName(dest), Dest: dest, Env: env, Bastion: true})
	}
	for _, h := range cfg.Azure.Hosts {
		t := sshTarget{Name: h.Name, Dest: firstNonBlank(h.Host, h.Name), Env: strings.ToLower(h.Environment), Jump: h.Jump}
		if strings.EqualFold(h.Jump, "bastion") {
			t.Jump, _ = cfg.Azure.Bastion(h.Environment)
		}
		list = append(list, t)
	}
	return list
}

// bastionName is how a bastion is shown: its destination without the user.
func bastionName(dest string) string {
	if _, host, ok := strings.Cut(dest, "@"); ok {
		return host
	}
	return dest
}

// azureEnvs are the environments with a bastion, in the order of the
// environments setting (dev, ete, qa, prod), others after in name order.
func azureEnvs(cfg config.Config) []string {
	order := map[string]int{}
	for i, e := range append(append([]string{}, cfg.Environments...), "dev", "ete", "qa", "prod") {
		if _, ok := order[strings.ToLower(e)]; !ok {
			order[strings.ToLower(e)] = i
		}
	}
	var envs []string
	for k := range cfg.Azure.Bastions {
		envs = append(envs, strings.ToLower(k))
	}
	sort.Slice(envs, func(i, j int) bool {
		oi, iok := order[envs[i]]
		oj, jok := order[envs[j]]
		switch {
		case iok && jok:
			return oi < oj
		case iok != jok:
			return iok
		}
		return envs[i] < envs[j]
	})
	return envs
}

// takeEnv removes the environment names from the words typed, so
// `nedctl azure kube payments qa` means "payments, in QA".
func takeEnv(cfg config.Config, terms []string) (string, []string) {
	known := map[string]bool{}
	for _, t := range azureTargets(cfg) {
		if t.Env != "" {
			known[t.Env] = true
		}
	}
	env, rest := "", []string(nil)
	for _, t := range terms {
		if known[strings.ToLower(t)] && env == "" {
			env = strings.ToLower(t)
			continue
		}
		rest = append(rest, t)
	}
	return env, rest
}

// envOfName finds the environment a cluster belongs to: where it was seen
// before, else an environment word in its name (acm-k8s-qa-cluster → qa).
func envOfName(cfg config.Config, name string) string {
	for _, env := range azureEnvs(cfg) {
		for _, n := range loadNames(cfg, "azure-"+env, "aks") {
			if n == name {
				return env
			}
		}
	}
	found := ""
	for _, w := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
		if _, ok := cfg.Azure.Bastion(w); ok {
			if found != "" && found != w {
				return "" // two environments named: do not guess
			}
			found = w
		}
	}
	return found
}

func azurePC(cfg config.Config, t sshTarget) profileContext {
	return profileContext{Name: t.Name, AccountID: "azure-" + t.Env, Environment: t.Env, Production: cfg.IsProdEnvironment(t.Env)}
}

// sshArgs builds ssh's arguments. The destination is validated, so it can
// never be read as an option; the remote command is one string the remote
// login shell runs.
func sshArgs(cfg config.Config, t sshTarget, tty bool, remote string) []string {
	args := []string{"-o", "ServerAliveInterval=30", "-o", "AddKeysToAgent=yes"}
	if tty {
		args = append(args, "-t")
	} else {
		args = append(args, "-T")
	}
	if cfg.Azure.User != "" && !strings.Contains(t.Dest, "@") {
		args = append(args, "-l", cfg.Azure.User)
	}
	if t.Jump != "" {
		args = append(args, "-J", t.Jump)
	}
	args = append(args, t.Dest)
	if remote != "" {
		args = append(args, remote)
	}
	return args
}

// remoteBash is a command for the remote login shell: script run by bash
// as a login shell (the host's PATH and settings), with args as $1….
func remoteBash(script string, args ...string) string {
	parts := []string{"bash", "-lc", shellQuote(script), "nedctl"}
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// listContextsScript prints the bastion's kube-contexts.
const listContextsScript = `kubectl config get-contexts -o name`

// sessionScript runs on the remote host. $1 is the prompt label, $2 the
// terminal title, $3 the Windows Terminal tab colour (a palette index, or
// empty), $4 the kube-context (empty for a plain shell); any further
// arguments are one command to run instead of a shell.
//
// The kube-context is selected for this session only: a small file that
// sets just current-context (made with mktemp in the bastion's temp
// directory, mode 0600 — ~/.kube is often read-only, owned by the
// platform) goes first in KUBECONFIG, in front of the
// host's own kubeconfig. Credentials stay where the platform put them —
// nothing is copied — and the engineer's other sessions (or `kubectx` in
// another terminal) cannot switch this one to another cluster. `kubectx`
// in this shell changes only this shell.
const sessionScript = `label=$1 title=$2 tab=$3 ctx=$4; shift 4
if [ -n "$ctx" ]; then
  if ! kubectl config get-contexts "$ctx" >/dev/null 2>&1; then
    echo "nedctl: there is no kube-context \"$ctx\" on $(hostname) — see nedctl azure clusters --refresh" >&2
    exit 3
  fi
  tmp="${TMPDIR:-/tmp}"
  find "$tmp" -maxdepth 1 -name 'nedctl-ctx.*' -user "$(id -u)" -mmin +1440 -delete 2>/dev/null
  NEDCTL_CTX=$(mktemp "$tmp/nedctl-ctx.XXXXXX") || exit 1
  printf 'apiVersion: v1\nkind: Config\ncurrent-context: "%s"\n' "$ctx" > "$NEDCTL_CTX" || exit 1
  export NEDCTL_CTX
  if [ $# -gt 0 ]; then
    KUBECONFIG="$NEDCTL_CTX:${KUBECONFIG:-$HOME/.kube/config}" "$@"
    rc=$?
    rm -f "$NEDCTL_CTX"
    exit $rc
  fi
elif [ $# -gt 0 ]; then
  exec "$@"
fi
NEDCTL_RC=$(mktemp "${TMPDIR:-/tmp}/nedctl-rc.XXXXXX") || exit 1
cat > "$NEDCTL_RC" <<'EOF'
[ -f ~/.bashrc ] && . ~/.bashrc
rm -f "$NEDCTL_RC"
if [ -n "$NEDCTL_CTX" ]; then
  export KUBECONFIG="$NEDCTL_CTX:${KUBECONFIG:-$HOME/.kube/config}"
  trap 'rm -f "$NEDCTL_CTX"' EXIT
fi
__nedctl_title() {
  printf '\033]0;%s\007' "$NEDCTL_TITLE"
  [ -n "$NEDCTL_TAB" ] && printf '\033[2;15;%s,|' "$NEDCTL_TAB"
  return 0
}
PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }__nedctl_title"
PS1="$NEDCTL_PS1 $PS1"
EOF
export NEDCTL_RC NEDCTL_PS1="$label" NEDCTL_TITLE="$title" NEDCTL_TAB="$tab"
exec bash --rcfile "$NEDCTL_RC" -i
`

// promptLabel is the remote prompt's prefix, e.g. [QA acm-k8s-qa-cluster]
// in the environment's colour. It holds only an environment word and a
// validated name, so nothing in it is expanded by the remote shell.
func promptLabel(cfg config.Config, env, what string, colored bool) string {
	label := "[" + strings.TrimSpace(strings.ToUpper(env)+" "+what) + "]"
	if r, g, b, ok := picker.RGB(cfg.ColorFor(env)); ok && colored {
		return fmt.Sprintf(`\[\e[1;38;2;%d;%d;%dm\]%s\[\e[0m\]`, r, g, b, label)
	}
	return label
}

// tabIndex is the palette entry the remote prompt keeps the Windows
// Terminal tab coloured with, or "" outside Windows Terminal.
func tabIndex(cfg config.Config, env string) string {
	if os.Getenv("WT_SESSION") == "" {
		return ""
	}
	if i, ok := nearestXterm256(cfg.ColorFor(env)); ok {
		return fmt.Sprint(i)
	}
	return ""
}

func cmdAzure(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl azure <kube|shell|clusters|hosts|cp> ...")
		return ExitUsage
	}
	switch args[0] {
	case "kube":
		return azureKube(ctx, cfgPath, args[1:], stderr)
	case "shell":
		return azureShell(ctx, cfgPath, args[1:], stderr)
	case "clusters":
		return azureClusters(ctx, cfgPath, args[1:], stdout, stderr)
	case "hosts":
		return azureHosts(cfgPath, args[1:], stdout, stderr)
	case "cp":
		return azureCp(ctx, cfgPath, args[1:], stderr)
	}
	fmt.Fprintf(stderr, "unknown azure subcommand %q (want kube, shell, clusters or hosts)\n", args[0])
	return ExitUsage
}

// loadAzure loads the config and checks Azure access is set up.
func loadAzure(cfgPath string, stderr io.Writer) (config.Config, bool) {
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return cfg, false
	}
	if !cfg.Azure.Configured() {
		fmt.Fprintln(stderr, `Azure access is not set up — add your bastions to the config, e.g.
  "azure": {"bastions": {"dev": "aks-dev", "qa": "aks-qa"}}
(an alias from ~/.ssh/config, a host name or an address). See docs/azure.md.`)
		return cfg, false
	}
	return cfg, true
}

// chooseEnv settles the environment: given, the only one, or picked.
func chooseEnv(cfg config.Config, env string, stderr io.Writer) (string, int) {
	envs := azureEnvs(cfg)
	if env != "" {
		if _, ok := cfg.Azure.Bastion(env); !ok {
			fmt.Fprintf(stderr, "no bastion for %q — azure.bastions has %s\n", env, strings.Join(envs, ", "))
			return "", ExitUsage
		}
		return strings.ToLower(env), ExitOK
	}
	switch {
	case len(envs) == 0:
		fmt.Fprintln(stderr, "no AKS bastions in the config (azure.bastions)")
		return "", ExitFailure
	case len(envs) == 1:
		return envs[0], ExitOK
	case !stdinIsTerminal():
		fmt.Fprintf(stderr, "which environment? add one of: %s (or --env)\n", strings.Join(envs, ", "))
		return "", ExitUsage
	}
	rows := make([]picker.Row, len(envs))
	for i, env := range envs {
		dest, _ := cfg.Azure.Bastion(env)
		known := ""
		if n := len(loadNames(cfg, "azure-"+env, "aks")); n > 0 {
			known = fmt.Sprintf("%d clusters", n)
		}
		rows[i] = picker.Row{Cells: []string{strings.ToUpper(env), bastionName(dest), known}, Color: cfg.ColorFor(env)}
	}
	idx, err := picker.Picker{Title: "AKS environments", Header: []string{"ENV", "BASTION", ""},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", ExitFailure
	}
	return envs[idx], ExitOK
}

func bastionTarget(cfg config.Config, env string) sshTarget {
	dest, _ := cfg.Azure.Bastion(env)
	return sshTarget{Name: bastionName(dest), Dest: dest, Env: env, Bastion: true}
}

// listAKS asks a bastion for its kube-contexts and remembers them for
// completion. ssh runs in the foreground, so a first-time host key
// question or a key passphrase can be answered.
func listAKS(ctx context.Context, cfg config.Config, t sshTarget, stderr io.Writer) ([]string, error) {
	fmt.Fprintf(stderr, "Listing clusters on %s…\n", t.Name)
	var out bytes.Buffer
	err := execx.Interactive(ctx, execx.Spec{Stdin: childStdin(), Name: "ssh", Args: sshArgs(cfg, t, false, remoteBash(listContextsScript)),
		Stdout: &out, Timeout: cfg.Timeout()})
	if err != nil {
		return nil, sshError(t, err)
	}
	var names []string
	for _, l := range strings.Split(out.String(), "\n") {
		if l = strings.TrimSpace(l); kubeContextRe.MatchString(l) {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	rememberAKS(cfg, t.Env, names)
	return names, nil
}

type akName string

func (n akName) nameOf() string { return string(n) }

func rememberAKS(cfg config.Config, env string, names []string) {
	items := make([]akName, len(names))
	for i, n := range names {
		items[i] = akName(n)
	}
	rememberNames(cfg, profileContext{AccountID: "azure-" + env}, "aks", items, false)
}

// sshError explains ssh's own failures (exit 255); a remote command's exit
// code is left as it is.
func sshError(t sshTarget, err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 255 {
		return fmt.Errorf("could not reach %s over SSH — on the VPN? key loaded (ssh-add -l)? Try: ssh %s", t.Name, t.Dest)
	}
	var nf *execx.NotFoundError
	if errors.As(err, &nf) {
		return errors.New("ssh is not installed — run `nedctl doctor`")
	}
	return err
}

func azureKube(ctx context.Context, cfgPath string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure kube", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFlag := fs.String("env", "", "environment whose bastion to use (default: from the cluster name, else pick)")
	refresh := fs.Bool("refresh", false, "list the bastion's clusters again instead of using what nedctl remembers")
	yes := fs.Bool("yes", false, "confirm production access without being asked (when confirmProduction is on)")
	tab := fs.Bool("tab", false, "open the session in a new Windows Terminal tab coloured by environment")
	crFlag := fs.String("change-record", "", "change record for this access, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")

	ours, command := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			ours, command = args[:i], args[i+1:]
			break
		}
	}
	terms, err := parseInterspersed(fs, ours)
	if err != nil {
		return ExitUsage
	}
	if command != nil && len(command) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl azure kube [cluster|words…] [--env E] [-- command args…]")
		return ExitUsage
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	env, terms := takeEnv(cfg, terms)
	env = firstNonBlank(strings.ToLower(*envFlag), env)
	if env == "" && len(terms) == 1 {
		env = envOfName(cfg, terms[0])
	}
	env, code := chooseEnv(cfg, env, stderr)
	if code != ExitOK {
		return code
	}
	t := bastionTarget(cfg, env)
	pc := azurePC(cfg, t)

	name, code := chooseAKS(ctx, cfg, t, pc, terms, *refresh, stderr)
	if code != ExitOK {
		return code
	}
	saveLast(cfg, pc, "aks", name)
	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	if *tab {
		tabArgs := []string{"azure", "kube", name, "--env", env}
		tabArgs = appendControl(tabArgs, cr, glass)
		return openTabFor(cfg, env, strings.ToUpper(env)+" · "+name, tabArgs, stderr)
	}
	if !confirmProduction(cfg, pc, name, *yes, stderr) {
		return ExitFailure
	}
	what := "interactive shell"
	if command != nil {
		what = "command " + command[0]
	}
	base := audit.Event{Action: "aks-session", Cloud: "azure", Cluster: name, Environment: env, Production: pc.Production,
		ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("kube %s on bastion %s, kube-context %s; the bastion's kubeconfig (an AKS local account, so the cluster's audit log cannot name the engineer)", what, t.Dest, name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to connect: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: name, Environment: env}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	color := colorOn(stderr)
	if command == nil {
		azureBanner(cfg, env, name, "on "+t.Name, pc.Production, stderr)
		fmt.Fprintf(stderr, "⎈ kubectl, helm and kubectx in this shell use %s only. Type exit when done.\n", name)
	}
	remote := remoteBash(sessionScript, append([]string{promptLabel(cfg, env, name, color), strings.ToUpper(env) + " · " + name, tabIndex(cfg, env), name}, command...)...)
	err = execx.Interactive(ctx, execx.Spec{Stdin: childStdin(), Name: "ssh", Args: sshArgs(cfg, t, command == nil || stdinIsTerminal(), remote),
		Timeout: cfg.AWS.Timeout()})
	return endSSH(ctx, tr, t, base, command != nil, err, stderr)
}

// chooseAKS picks the cluster: a name nedctl already knows goes straight
// in; otherwise the bastion is asked, and the words narrow its list.
func chooseAKS(ctx context.Context, cfg config.Config, t sshTarget, pc profileContext, terms []string, refresh bool, stderr io.Writer) (string, int) {
	if len(terms) == 1 && !refresh && kubeContextRe.MatchString(terms[0]) {
		for _, n := range loadNames(cfg, "azure-"+t.Env, "aks") {
			if n == terms[0] {
				return n, ExitOK
			}
		}
	}
	all, err := listAKS(ctx, cfg, t, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", ExitFailure
	}
	var cands []string
	for _, n := range all {
		if len(terms) == 1 && n == terms[0] {
			return n, ExitOK
		}
		ok := true
		for _, w := range terms {
			ok = ok && strings.Contains(strings.ToLower(n), strings.ToLower(w))
		}
		if ok {
			cands = append(cands, n)
		}
	}
	label := strings.ToUpper(t.Env) + " (" + t.Name + ")"
	switch {
	case len(all) == 0:
		fmt.Fprintf(stderr, "no kube-contexts on %s\n", t.Name)
		return "", ExitFailure
	case len(cands) == 0:
		fmt.Fprintf(stderr, "no cluster on %s matches %q\n", label, strings.Join(terms, " "))
		return "", ExitFailure
	case len(cands) == 1:
		return cands[0], ExitOK
	case !stdinIsTerminal():
		fmt.Fprintf(stderr, "%d clusters on %s match — name one: %s\n", len(cands), label, strings.Join(cands, ", "))
		return "", ExitUsage
	}
	last := loadLast(cfg, pc, "aks", kubeContextRe.MatchString)
	sort.SliceStable(cands, func(i, j int) bool { return cands[i] == last && cands[j] != last })
	rows := make([]picker.Row, len(cands))
	for i, n := range cands {
		mark := ""
		if n == last {
			mark = "last used"
		}
		rows[i] = picker.Row{Cells: []string{n, mark}, Color: cfg.ColorFor(t.Env)}
	}
	idx, err := picker.Picker{Title: "AKS clusters in " + label, Header: []string{"CLUSTER", ""},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", ExitFailure
	}
	return cands[idx], ExitOK
}

func azureShell(ctx context.Context, cfgPath string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure shell", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFlag := fs.String("env", "", "only machines in this environment")
	plain := fs.Bool("plain", false, "plain ssh: no prompt or title changes on the remote side (for hosts without bash)")
	yes := fs.Bool("yes", false, "confirm production access without being asked (when confirmProduction is on)")
	tab := fs.Bool("tab", false, "open the session in a new Windows Terminal tab coloured by environment")
	crFlag := fs.String("change-record", "", "change record for this session, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	terms, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	env, terms := takeEnv(cfg, terms)
	env = firstNonBlank(strings.ToLower(*envFlag), env)
	t, code := chooseTarget(cfg, env, terms, stderr)
	if code != ExitOK {
		return code
	}
	pc := azurePC(cfg, t)
	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	if *tab {
		tabArgs := []string{"azure", "shell", t.Name}
		if *plain {
			tabArgs = append(tabArgs, "--plain")
		}
		return openTabFor(cfg, t.Env, strings.TrimLeft(strings.ToUpper(t.Env)+" · "+t.Name, " ·"), appendControl(tabArgs, cr, glass), stderr)
	}
	if !confirmProduction(cfg, pc, t.Name, *yes, stderr) {
		return ExitFailure
	}
	kind := "host"
	if t.Bastion {
		kind = "AKS bastion"
	}
	detail := fmt.Sprintf("ssh to %s %s (%s)", kind, t.Name, t.Dest)
	if t.Jump != "" {
		detail += " via " + t.Jump
	}
	base := audit.Event{Action: "ssh-session", Cloud: "azure", Environment: t.Env, Production: pc.Production,
		ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass, Detail: detail}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to start the session: every session must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: t.Name, Environment: t.Env}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	azureBanner(cfg, t.Env, t.Name, kind, pc.Production, stderr)
	remote := ""
	if !*plain {
		remote = remoteBash(sessionScript, promptLabel(cfg, t.Env, t.Name, colorOn(stderr)), strings.TrimLeft(strings.ToUpper(t.Env)+" · "+t.Name, " ·"), tabIndex(cfg, t.Env), "")
	}
	err = execx.Interactive(ctx, execx.Spec{Stdin: childStdin(), Name: "ssh", Args: sshArgs(cfg, t, true, remote), Timeout: cfg.AWS.Timeout()})
	return endSSH(ctx, tr, t, base, false, err, stderr)
}

// chooseTarget resolves the words to one machine, using the picker when
// several match.
func chooseTarget(cfg config.Config, env string, terms []string, stderr io.Writer) (sshTarget, int) {
	var cands []sshTarget
	for _, t := range azureTargets(cfg) {
		if env != "" && t.Env != env {
			continue
		}
		if len(terms) == 1 && (strings.EqualFold(t.Name, terms[0]) || t.Dest == terms[0]) {
			return t, ExitOK
		}
		hay := strings.ToLower(t.Name + " " + t.Dest + " " + t.Env)
		ok := true
		for _, w := range terms {
			ok = ok && strings.Contains(hay, strings.ToLower(w))
		}
		if ok {
			cands = append(cands, t)
		}
	}
	switch {
	case len(cands) == 1:
		return cands[0], ExitOK
	case len(cands) == 0:
		fmt.Fprintf(stderr, "no machine matches %q — `nedctl azure hosts` lists them\n", strings.TrimSpace(env+" "+strings.Join(terms, " ")))
		return sshTarget{}, ExitFailure
	case !stdinIsTerminal():
		names := make([]string, len(cands))
		for i, t := range cands {
			names[i] = t.Name
		}
		fmt.Fprintf(stderr, "%d machines match — name one: %s\n", len(cands), strings.Join(names, ", "))
		return sshTarget{}, ExitUsage
	}
	rows := make([]picker.Row, len(cands))
	for i, t := range cands {
		kind := "host"
		if t.Bastion {
			kind = "AKS bastion"
		}
		rows[i] = picker.Row{Cells: []string{t.Name, strings.ToUpper(t.Env), kind, bastionName(t.Jump)}, Color: cfg.ColorFor(t.Env)}
	}
	idx, err := picker.Picker{Title: "Azure machines", Header: []string{"NAME", "ENV", "KIND", "VIA"},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return sshTarget{}, ExitFailure
	}
	return cands[idx], ExitOK
}

// endSSH closes the audit record and turns ssh's result into an exit code.
// A one-off command's own exit code is passed on, for scripts.
func endSSH(ctx context.Context, tr *trail, t sshTarget, base audit.Event, command bool, err error, stderr io.Writer) int {
	principal := "ssh:" + t.Dest
	if err == nil {
		tr.end(ctx, audit.OutcomeSuccess, principal, base.Detail, stderr)
		return ExitOK
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() != 255 {
		// The remote side ran and ended this way: the access happened.
		tr.end(ctx, audit.OutcomeSuccess, principal, fmt.Sprintf("%s; exit status %d", base.Detail, exit.ExitCode()), stderr)
		switch {
		case command:
			return exit.ExitCode()
		case exit.ExitCode() == 3: // the session script found no such kube-context
			return ExitFailure
		}
		return ExitOK
	}
	err = sshError(t, err)
	tr.end(ctx, audit.OutcomeFailure, principal, err.Error(), stderr)
	fmt.Fprintln(stderr, err)
	return ExitFailure
}

// azureBanner names the target in the title and colours the tab before
// ssh starts; the remote prompt keeps both while the session lasts.
func azureBanner(cfg config.Config, env, target, where string, prod bool, stderr io.Writer) {
	title := strings.TrimLeft(strings.ToUpper(env)+" · "+target, " ·")
	if colorOn(stderr) {
		fmt.Fprintf(stderr, "\x1b]0;%s\x07", title)
		colorTab(stderr, cfg.ColorFor(env))
		title = picker.Paint(cfg.ColorFor(env), title)
	}
	fmt.Fprintf(stderr, "▶ %s %s\n", title, where)
	if prod {
		fmt.Fprintln(stderr, "⚠️ PRODUCTION — this session is recorded.")
	}
}

func appendControl(args []string, cr, glass string) []string {
	if cr != "" {
		args = append(args, "--change-record", cr)
	}
	if glass != "" {
		args = append(args, "--break-glass", glass)
	}
	return args
}

func openTabFor(cfg config.Config, env, title string, args []string, stderr io.Writer) int {
	code := openWTTab(cfg, env, title, "run without --tab to use this terminal", args, stderr)
	if code == ExitOK {
		fmt.Fprintf(stderr, "opened a tab: %s\n", title)
	}
	return code
}

// akRow is one line of `nedctl azure clusters`.
type akRow struct {
	Cluster     string `json:"cluster"`
	Environment string `json:"environment"`
	Bastion     string `json:"bastion"`
}

func azureClusters(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure clusters", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFlag := fs.String("env", "", "only this environment")
	refresh := fs.Bool("refresh", false, "ask the bastions again instead of using what nedctl remembers")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	env := strings.ToLower(*envFlag)
	if len(pos) == 1 {
		env = strings.ToLower(pos[0])
	}
	envs := azureEnvs(cfg)
	if env != "" {
		if _, ok := cfg.Azure.Bastion(env); !ok {
			fmt.Fprintf(stderr, "no bastion for %q — azure.bastions has %s\n", env, strings.Join(envs, ", "))
			return ExitUsage
		}
		envs = []string{env}
	}
	rows := []akRow{}
	failed := false
	for _, e := range envs {
		t := bastionTarget(cfg, e)
		names := loadNames(cfg, "azure-"+e, "aks")
		if *refresh || len(names) == 0 {
			if names, err = listAKS(ctx, cfg, t, stderr); err != nil {
				fmt.Fprintln(stderr, err)
				failed = true
				continue
			}
		}
		for _, n := range names {
			rows = append(rows, akRow{Cluster: n, Environment: e, Bastion: t.Name})
		}
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, rows); code != ExitOK {
			return code
		}
	} else {
		tw := newTable(stdout)
		fmt.Fprintln(tw, "ENV\tCLUSTER\tBASTION")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Environment, r.Cluster, r.Bastion)
		}
		tw.Flush()
	}
	if failed {
		return ExitFailure
	}
	return ExitOK
}

func azureHosts(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure hosts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	type row struct {
		Name        string `json:"name"`
		Environment string `json:"environment"`
		Kind        string `json:"kind"`
		Destination string `json:"destination"`
		Via         string `json:"via,omitempty"`
	}
	rows := []row{}
	for _, t := range azureTargets(cfg) {
		kind := "host"
		if t.Bastion {
			kind = "aks bastion"
		}
		rows = append(rows, row{t.Name, t.Env, kind, t.Dest, t.Jump})
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, rows)
	}
	tw := newTable(stdout)
	fmt.Fprintln(tw, "ENV\tNAME\tKIND\tSSH\tVIA")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Environment, r.Name, r.Kind, r.Destination, r.Via)
	}
	tw.Flush()
	return ExitOK
}
