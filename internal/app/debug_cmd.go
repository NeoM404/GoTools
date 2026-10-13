package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/inventory"
	"nedctl/internal/picker"
	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// `nedctl debug` puts a debugging container where it is needed — a pod in
// a namespace, a pod on a node with the node's processes, network and
// files, or an ephemeral container beside a running pod — on EKS or AKS.
// Nothing is created before the engineer has seen exactly what will be
// deployed and the cluster has accepted it in a server-side dry run, and
// approved it. Debug pods are labelled, never get a service-account token,
// have a hard time limit, and are removed when the session ends.

// debugProfiles are kubectl debug's profiles, as nedctl applies them.
var debugProfiles = map[string]string{
	"general":    "no extra privileges (on a node: the node's processes, network and files at /host)",
	"netadmin":   "adds NET_ADMIN and NET_RAW, for tcpdump and routing",
	"sysadmin":   "privileged: full access to the node",
	"restricted": "non-root, no capabilities (pods only)",
}

var (
	podNameRe  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	nodeNameRe = podNameRe
	netHostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)
)

// debugPod is the pod nedctl deploys.
type debugPod struct {
	Name, Namespace, Image, Owner, Kind, Profile, Node string
	TTL                                                time.Duration
}

// manifest is the pod as YAML: exactly what is shown and what is sent.
// Every value is validated or JSON-quoted, so none can change its
// structure.
func (p debugPod) manifest() string {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	secs := int(p.TTL.Seconds())
	onNode := p.Kind == "node"
	hostFiles := onNode || p.Kind == "cp" // cp: the node's files, read-only, and nothing else of the host
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("apiVersion: v1")
	w("kind: Pod")
	w("metadata:")
	w("  name: %s", q(p.Name))
	w("  namespace: %s", q(p.Namespace))
	w("  labels:")
	w(`    app.kubernetes.io/managed-by: nedctl`)
	w(`    nedctl.io/debug: "true"`)
	w("    nedctl.io/kind: %s", q(p.Kind))
	w("    nedctl.io/owner: %s", q(p.Owner))
	w("spec:")
	w("  restartPolicy: Never")
	w("  activeDeadlineSeconds: %d   # removed after %s at the latest", secs, shortDuration(p.TTL))
	w("  terminationGracePeriodSeconds: 0")
	w("  automountServiceAccountToken: false")
	if p.Node != "" {
		w("  nodeName: %s", q(p.Node))
	}
	if onNode {
		w("  hostPID: true")
		w("  hostNetwork: true")
		w("  hostIPC: true")
	}
	if hostFiles {
		w("  tolerations:")
		w("  - operator: Exists")
	}
	w("  containers:")
	w("  - name: debugger")
	w("    image: %s", q(p.Image))
	w(`    command: ["sleep", "%d"]`, secs)
	switch p.Profile {
	case "netadmin":
		w("    securityContext:")
		w("      capabilities:")
		w("        add: [NET_ADMIN, NET_RAW]")
	case "sysadmin":
		w("    securityContext:")
		w("      privileged: true")
	case "restricted":
		w("    securityContext:")
		w("      runAsNonRoot: true")
		w("      runAsUser: 65534")
		w("      allowPrivilegeEscalation: false")
		w("      capabilities:")
		w("        drop: [ALL]")
		w("      seccompProfile:")
		w("        type: RuntimeDefault")
	}
	if hostFiles {
		w("    volumeMounts:")
		w("    - name: host-root")
		w("      mountPath: /host")
		if !onNode {
			w("      readOnly: true")
		}
		w("  volumes:")
		w("  - name: host-root")
		w("    hostPath:")
		w("      path: /")
	}
	return b.String()
}

// debugOwner is the engineer as a label value: the local user name.
func debugOwner() string {
	u := currentUser()
	if i := strings.LastIndexAny(u, `\/`); i >= 0 {
		u = u[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(u) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 {
			b.WriteByte('-')
		}
	}
	o := strings.Trim(b.String(), "-")
	if len(o) > 30 {
		o = strings.Trim(o[:30], "-")
	}
	return firstNonBlank(o, "unknown")
}

// randomSuffix keeps two sessions of one engineer apart.
var randomSuffix = func() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// debugFlags are the flags every debug subcommand shares.
type debugFlags struct {
	session                   sessionFlags
	namespace, image, profile string
	yes, dryRun               bool
	cr, glass                 string
}

func newDebugFlags(name string, cfg config.Config, stderr io.Writer, image, profile bool) (*flag.FlagSet, *debugFlags) {
	fs := flag.NewFlagSet("debug "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	d := &debugFlags{}
	fs.StringVar(&d.session.cluster, "cluster", "", "the cluster (default: pick one; an AKS name picks its bastion)")
	fs.StringVar(&d.session.env, "env", "", "AKS: the environment whose bastion to use")
	fs.StringVar(&d.session.awsProfile, "aws-profile", "", "EKS: AWS profile to act with (default: the current one)")
	fs.StringVar(&d.namespace, "n", "", "namespace (default: "+cfg.Debug.DebugNamespace()+")")
	fs.StringVar(&d.namespace, "namespace", "", "namespace (default: "+cfg.Debug.DebugNamespace()+")")
	if image {
		fs.StringVar(&d.image, "image", "", "image: "+strings.Join(cfg.Debug.ImageNames(), ", ")+", or any image reference (default "+cfg.Debug.DefaultImage()+")")
	}
	if profile {
		fs.StringVar(&d.profile, "profile", "", "general, netadmin, sysadmin or restricted (see nedctl help debug)")
	}
	fs.BoolVar(&d.yes, "yes", false, "deploy without asking, after showing what will be deployed (needed without a terminal)")
	fs.BoolVar(&d.dryRun, "dry-run", false, "show what would be deployed and check it with the cluster; deploy nothing")
	fs.StringVar(&d.cr, "change-record", "", "change record, when change control requires one")
	fs.StringVar(&d.glass, "break-glass", "", "emergency access without a change record; recorded and flagged")
	return fs, d
}

func (d *debugFlags) check(cfg config.Config, stderr io.Writer) bool {
	if d.namespace == "" {
		d.namespace = cfg.Debug.DebugNamespace()
	}
	if !config.ValidNamespace(d.namespace) {
		fmt.Fprintf(stderr, "-n %q is not a namespace name\n", d.namespace)
		return false
	}
	ref := cfg.Debug.ImageFor(firstNonBlank(d.image, cfg.Debug.DefaultImage()))
	if !config.ValidImageRef(ref) {
		fmt.Fprintf(stderr, "--image %q is not an image reference\n", d.image)
		return false
	}
	d.image = ref
	if _, ok := debugProfiles[d.profile]; d.profile != "" && !ok {
		fmt.Fprintf(stderr, "--profile %q: want general, netadmin, sysadmin or restricted\n", d.profile)
		return false
	}
	return true
}

func cmdDebug(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl debug <pod|node|attach|net|ls|clean> ...")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "pod", "node", "net":
		return debugWithPod(ctx, cfg, sub, rest, stdout, stderr)
	case "attach":
		return debugAttach(ctx, cfg, rest, stderr)
	case "ls", "clean":
		return debugList(ctx, cfg, sub, rest, stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown debug subcommand %q (want pod, node, attach, net, ls or clean)\n", sub)
	return ExitUsage
}

// debugWithPod is `debug pod`, `debug node` and `debug net`: show the pod,
// dry-run it, approve, create, wait, use, remove.
func debugWithPod(ctx context.Context, cfg config.Config, kind string, args []string, stdout, stderr io.Writer) int {
	fs, d := newDebugFlags(kind, cfg, stderr, true, kind != "net")
	onNode := ""
	if kind == "pod" {
		fs.StringVar(&onNode, "on-node", "", "run the pod on this node")
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	usage := map[string]string{
		"pod":  "usage: nedctl debug pod [--image I] [-n NS] [--on-node N] [--profile P] [--cluster C]",
		"node": "usage: nedctl debug node [NODE] [--profile general|netadmin|sysadmin] [--image I] [--cluster C]",
		"net":  "usage: nedctl debug net HOST[:PORT] [--image I] [-n NS] [--cluster C]",
	}[kind]
	if (kind == "pod" && len(pos) > 0) || (kind == "node" && len(pos) > 1) || (kind == "net" && len(pos) != 1) || !d.check(cfg, stderr) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if kind == "node" && d.profile == "restricted" {
		fmt.Fprintln(stderr, "--profile restricted applies to pods; a node debug pod needs the node's namespaces")
		return ExitUsage
	}
	var netHost, netPort string
	if kind == "net" {
		netHost, netPort, err = parseHostPort(pos[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return ExitUsage
		}
	}
	if onNode != "" && !nodeNameRe.MatchString(onNode) {
		fmt.Fprintf(stderr, "--on-node %q is not a node name\n", onNode)
		return ExitUsage
	}

	s, code := openKubeSession(ctx, cfg, d.session, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()

	node := onNode
	if kind == "node" {
		want := ""
		if len(pos) == 1 {
			want = pos[0]
		}
		if node, code = chooseNode(ctx, cfg, s, want, stderr); code != ExitOK {
			return code
		}
	}
	p := debugPod{Name: "nedctl-debug-" + debugOwner() + "-" + randomSuffix(), Namespace: d.namespace, Image: d.image, Owner: debugOwner(),
		Kind: kind, Profile: firstNonBlank(d.profile, "general"), Node: node, TTL: cfg.Debug.DebugTTL()}
	manifest := p.manifest()

	what := map[string]string{"pod": "a debug pod", "node": "a debug pod on node " + node, "net": "a short-lived pod to test " + pos0(pos)}[kind]
	if code := approveDeploy(ctx, cfg, s, what, manifest, true, d, stderr); code != ExitOK || d.dryRun {
		return code
	}

	base := audit.Event{Action: "debug-" + kind, Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		ChangeRecord: strings.TrimSpace(d.cr), BreakGlass: strings.TrimSpace(d.glass) != "", BreakGlassReason: strings.TrimSpace(d.glass),
		Detail: fmt.Sprintf("pod %s/%s, image %s, profile %s%s, %s", p.Namespace, p.Name, p.Image, p.Profile, ifNonBlank(", node ", p.Node), s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to deploy: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, base.ChangeRecord, d.glass, tr, stderr); code != ExitOK {
		return code
	}
	if _, err := s.output(ctx, manifest, "create", "-f", "-"); err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "creating the pod: %v\n", err)
		return ExitFailure
	}
	defer removeDebugPod(ctx, s, p.Namespace, p.Name, stderr)
	sp := working(stderr, fmt.Sprintf("Waiting for %s to start…", p.Name))
	err = waitDebugPod(ctx, s, p.Namespace, p.Name)
	sp.Stop()
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}

	var useErr error
	switch kind {
	case "net":
		out, errw := safetext.Writer(stdout), safetext.Writer(stderr) // replies from the tested host are its text
		useErr = s.kubectl(ctx, []string{"exec", p.Name, "-n", p.Namespace, "--", "sh", "-c", netCheckScript, "nedctl", netHost, netPort}, strings.NewReader(""), out, errw, false)
		flushSafe(out, errw)
	default:
		st := ui.Style{Color: colorOn(stderr)}
		fmt.Fprintf(stderr, "%s %s ready on %s. Type exit to leave; the pod is removed.\n", st.OK("⎈"), p.Name, s.label())
		if kind == "node" {
			fmt.Fprintln(stderr, st.Hint("the node's files are at /host — `chroot /host` runs the node's own tools (journalctl, crictl)"))
		}
		var note string
		note, useErr = recordSession(ctx, cfg, s, s.pc.Production || cfg.IsProdEnvironment(s.env), map[string]any{"action": base.Action, "pod": p.Namespace + "/" + p.Name},
			stderr, "exec", "-it", p.Name, "-n", p.Namespace, "--", "sh", "-c", sizedShell())
		if errors.Is(useErr, errNotRecorded) {
			tr.end(ctx, audit.OutcomeRefused, s.pc.Role, useErr.Error(), stderr)
			fmt.Fprintln(stderr, useErr)
			return ExitFailure
		}
		base.Detail += note
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail, stderr)
	if useErr != nil && kind == "net" {
		return ExitFailure // the script says what failed
	}
	return ExitOK
}

// shortDuration is 2h, 1h30m, 45m, 30s.
func shortDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	s := d.Round(time.Minute).String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(strings.Replace(s, "h0m", "h", 1), "h0m")
}

func pos0(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}

func ifNonBlank(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
}

// approveDeploy shows what will be deployed, has the cluster check it
// (server-side dry run, so admission policies answer too), and asks. With
// --dry-run it stops after the check; with --yes it does not ask.
func approveDeploy(ctx context.Context, cfg config.Config, s *kubeSession, what, manifest string, serverCheck bool, d *debugFlags, stderr io.Writer) int {
	st := ui.Style{Color: colorOn(stderr)}
	fmt.Fprintf(stderr, "\n%s %s on %s (%s):\n\n", st.Bold("To deploy"), what, st.BoldFg(cfg.ColorFor(s.env), s.label()), s.where)
	for _, l := range strings.Split(strings.TrimRight(manifest, "\n"), "\n") {
		fmt.Fprintf(stderr, "    %s\n", l)
	}
	fmt.Fprintln(stderr)
	if serverCheck {
		sp := spinning(stderr, "Asking the cluster for a dry run…")
		_, err := s.output(ctx, manifest, "create", "--dry-run=server", "-f", "-", "-o", "name")
		sp.Stop()
		if err != nil {
			fmt.Fprintf(stderr, "%s %v\n", st.Fail("The cluster refuses it (server-side dry run):"), err)
			return ExitFailure
		}
		fmt.Fprintln(stderr, st.OK("The cluster accepts it (server-side dry run)."))
	}
	if d.dryRun {
		fmt.Fprintln(stderr, "Dry run only — nothing was deployed.")
		return ExitOK
	}
	if !confirmProduction(cfg, s.pc, s.cluster, false, stderr) {
		return ExitFailure
	}
	if d.yes {
		return ExitOK
	}
	if !stdinIsTerminal() {
		fmt.Fprintln(stderr, "nothing deployed: pass --yes to deploy without a terminal (or --dry-run to only check)")
		return ExitUsage
	}
	fmt.Fprintf(stderr, "Deploy it? [y/N] ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return ExitOK
	}
	fmt.Fprintln(stderr, "not deployed")
	return ExitFailure
}

// waitDebugPod waits for the pod to run and, when it does not, says why
// (an image the cluster cannot pull is the usual reason).
func waitDebugPod(ctx context.Context, s *kubeSession, ns, name string) error {
	_, err := s.output(ctx, "", "wait", "--for=condition=Ready", "pod/"+name, "-n", ns, "--timeout=180s")
	if err == nil {
		return nil
	}
	out, _ := s.output(ctx, "", "get", "pod", name, "-n", ns, "-o",
		`jsonpath={.status.phase}{" "}{.status.containerStatuses[0].state.waiting.reason}{" "}{.status.containerStatuses[0].state.waiting.message}{" "}{.status.conditions[?(@.type=="PodScheduled")].message}`)
	why := strings.Join(strings.Fields(string(out)), " ")
	msg := fmt.Sprintf("the debug pod did not start: %s", firstNonBlank(why, err.Error()))
	if strings.Contains(why, "ImagePull") || strings.Contains(why, "ErrImage") {
		msg += "\n→ the cluster could not pull the image. If it may only use an internal registry, map the short names to it in the config: \"debug\": {\"images\": {\"netshoot\": \"<registry>/netshoot:v0.13\"}}"
	}
	return fmt.Errorf("%s", msg)
}

func removeDebugPod(ctx context.Context, s *kubeSession, ns, name string, stderr io.Writer) {
	if _, err := s.output(context.WithoutCancel(ctx), "", "delete", "pod", name, "-n", ns, "--wait=false", "--ignore-not-found"); err != nil {
		fmt.Fprintf(stderr, "warning: could not remove %s/%s (%v) — it ends by itself at its time limit; `nedctl debug clean` removes it now\n", ns, name, err)
		return
	}
	fmt.Fprintf(stderr, "removed debug pod %s/%s\n", ns, name)
}

// netCheckScript tests reaching $1 (port $2) from inside the cluster: DNS,
// TCP, and for web ports TLS and HTTP. It exits non-zero when DNS or TCP
// fails.
const netCheckScript = `h=$1 p=$2 rc=0
echo "== DNS  $h"
nslookup "$h" 2>&1 | sed -n '/^Name:/,$p' | grep -v '^$' || { getent hosts "$h" || { echo "   cannot resolve $h"; rc=1; }; }
if [ -n "$p" ] && [ $rc -eq 0 ]; then
  echo "== TCP  $h:$p"
  if nc -z -w 5 "$h" "$p" 2>/dev/null; then echo "   open"; else echo "   cannot connect"; rc=1; fi
fi
if [ $rc -eq 0 ] && command -v openssl >/dev/null 2>&1 && { [ "$p" = 443 ] || [ "$p" = 8443 ] || [ "$p" = 6443 ]; }; then
  echo "== TLS  certificate"
  echo | openssl s_client -connect "$h:$p" -servername "$h" 2>/dev/null | openssl x509 -noout -subject -issuer -enddate 2>/dev/null | sed 's/^/   /'
fi
if [ $rc -eq 0 ] && command -v curl >/dev/null 2>&1 && [ -n "$p" ]; then
  case "$p" in 443|8443) u="https://$h:$p/";; *) u="http://$h:$p/";; esac
  echo "== HTTP $u"
  curl -ksS -o /dev/null --max-time 10 -w '   HTTP %{http_code} in %{time_total}s\n' "$u" 2>&1 | sed 's/^curl: /   /'
fi
exit $rc
`

// parseHostPort accepts host or host:port.
func parseHostPort(s string) (string, string, error) {
	host, port := s, ""
	if h, p, ok := strings.Cut(s, ":"); ok {
		host, port = h, p
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("%q: the port must be 1-65535", s)
		}
	}
	if !netHostRe.MatchString(host) {
		return "", "", fmt.Errorf("%q is not a host name or address", host)
	}
	return host, port, nil
}

// nodeRow is one node in the picker.
type nodeRow struct {
	Name, Status, Pool, Zone, Version string
}

// chooseNode resolves the node: an exact name, words narrowing the list,
// or the picker.
func chooseNode(ctx context.Context, cfg config.Config, s *kubeSession, want string, stderr io.Writer) (string, int) {
	out, err := s.output(ctx, "", "get", "nodes", "-o", "json")
	if err != nil {
		fmt.Fprintf(stderr, "listing nodes on %s: %v\n", s.label(), err)
		return "", ExitFailure
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Status struct {
				Conditions []struct{ Type, Status string } `json:"conditions"`
				NodeInfo   struct {
					KubeletVersion string `json:"kubeletVersion"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		fmt.Fprintf(stderr, "reading the node list: %v\n", err)
		return "", ExitFailure
	}
	var nodes []nodeRow
	for _, it := range list.Items {
		if !nodeNameRe.MatchString(it.Metadata.Name) {
			continue
		}
		r := nodeRow{Name: it.Metadata.Name, Status: "NotReady", Version: it.Status.NodeInfo.KubeletVersion,
			Zone: it.Metadata.Labels["topology.kubernetes.io/zone"]}
		for _, k := range []string{"kubernetes.azure.com/agentpool", "agentpool", "eks.amazonaws.com/nodegroup", "karpenter.sh/nodepool"} {
			if v := it.Metadata.Labels[k]; v != "" {
				r.Pool = v
				break
			}
		}
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				r.Status = "Ready"
			}
		}
		if want == r.Name {
			return r.Name, ExitOK
		}
		if strings.Contains(strings.ToLower(r.Name+" "+r.Pool+" "+r.Zone), strings.ToLower(want)) {
			nodes = append(nodes, r)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	switch {
	case len(nodes) == 0:
		fmt.Fprintf(stderr, "no node on %s matches %q\n", s.label(), want)
		return "", ExitFailure
	case len(nodes) == 1:
		return nodes[0].Name, ExitOK
	case !stdinIsTerminal():
		names := make([]string, len(nodes))
		for i, n := range nodes {
			names[i] = n.Name
		}
		fmt.Fprintf(stderr, "%d nodes — name one: %s\n", len(nodes), strings.Join(names, ", "))
		return "", ExitUsage
	}
	rows := make([]picker.Row, len(nodes))
	for i, n := range nodes {
		rows[i] = picker.Row{Cells: []string{n.Name, n.Status, n.Pool, n.Zone, n.Version}, Color: cfg.ColorFor(s.env)}
	}
	idx, err := picker.Picker{Title: "Nodes on " + s.label(), Header: []string{"NODE", "STATUS", "POOL", "ZONE", "VERSION"},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", ExitFailure
	}
	return nodes[idx].Name, ExitOK
}

// debugAttach adds an ephemeral container to a running pod, sharing the
// processes of one of its containers: for images without a shell, or a
// container that keeps crashing.
func debugAttach(ctx context.Context, cfg config.Config, args []string, stderr io.Writer) int {
	fs, d := newDebugFlags("attach", cfg, stderr, true, true)
	container := ""
	fs.StringVar(&container, "c", "", "the container to share processes with (default: the pod's first)")
	fs.StringVar(&container, "container", "", "the container to share processes with (default: the pod's first)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || !podNameRe.MatchString(pos[0]) || !d.check(cfg, stderr) {
		fmt.Fprintln(stderr, "usage: nedctl debug attach POD [-n NS] [-c CONTAINER] [--image I] [--profile general|netadmin|sysadmin|restricted] [--cluster C]")
		return ExitUsage
	}
	pod := pos[0]
	s, code := openKubeSession(ctx, cfg, d.session, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	out, err := s.output(ctx, "", "get", "pod", pod, "-n", d.namespace, "-o", "jsonpath={.spec.containers[*].name}")
	if err != nil {
		fmt.Fprintf(stderr, "pod %s/%s on %s: %v\n", d.namespace, pod, s.label(), err)
		return ExitFailure
	}
	names := strings.Fields(string(out))
	switch {
	case len(names) == 0:
		fmt.Fprintf(stderr, "pod %s/%s has no containers\n", d.namespace, pod)
		return ExitFailure
	case container == "":
		container = names[0]
	case !contains(names, container):
		fmt.Fprintf(stderr, "pod %s has no container %q (it has %s)\n", pod, container, strings.Join(names, ", "))
		return ExitUsage
	}
	name := "nedctl-debug-" + randomSuffix()
	profile := firstNonBlank(d.profile, "general")
	kargs := []string{"debug", "pod/" + pod, "-n", d.namespace, "-it", "--image", d.image, "--target", container, "--container", name, "--profile", profile}
	shown := fmt.Sprintf(`# an ephemeral container added to pod %s, sharing the processes of %q
# (profile %s: %s). It stops when you exit; Kubernetes keeps it listed in
# the pod until the pod is replaced, and the pod itself is not restarted.
kubectl %s`, pod, container, profile, debugProfiles[profile], strings.Join(kargs, " "))
	// Ephemeral containers have no dry run in kubectl; what is shown is
	// the exact command.
	if code := approveDeploy(ctx, cfg, s, "a debug container", shown, false, d, stderr); code != ExitOK || d.dryRun {
		return code
	}
	base := audit.Event{Action: "debug-attach", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		ChangeRecord: strings.TrimSpace(d.cr), BreakGlass: strings.TrimSpace(d.glass) != "", BreakGlassReason: strings.TrimSpace(d.glass),
		Detail: fmt.Sprintf("ephemeral container %s in pod %s/%s (target %s), image %s, profile %s, %s", name, d.namespace, pod, container, d.image, profile, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to deploy: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, base.ChangeRecord, d.glass, tr, stderr); code != ExitOK {
		return code
	}
	note, err := recordSession(ctx, cfg, s, s.pc.Production || cfg.IsProdEnvironment(s.env), map[string]any{"action": base.Action, "pod": d.namespace + "/" + pod}, stderr, kargs...)
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error()+note, stderr)
		fmt.Fprintf(stderr, "kubectl debug: %v (it needs kubectl 1.27 or newer %s)\n", err, s.where)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail+note, stderr)
	return ExitOK
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// debugPodInfo is one row of `debug ls`.
type debugPodInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Owner     string `json:"owner"`
	Kind      string `json:"kind"`
	Node      string `json:"node"`
	Phase     string `json:"phase"`
	Age       string `json:"age"`
}

// debugList is `debug ls` (every debug pod on the cluster) and `debug
// clean` (remove yours, or with --all everyone's, after approval).
func debugList(ctx context.Context, cfg config.Config, sub string, args []string, stdout, stderr io.Writer) int {
	fs, d := newDebugFlags(sub, cfg, stderr, false, false)
	all := fs.Bool("all", false, "clean: everyone's debug pods, not only yours")
	output := addOutputFlag(fs)
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	s, code := openKubeSession(ctx, cfg, d.session, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	out, err := s.output(ctx, "", "get", "pods", "-A", "-l", "nedctl.io/debug=true", "-o", "json")
	if err != nil {
		fmt.Fprintf(stderr, "listing debug pods on %s: %v\n", s.label(), err)
		return ExitFailure
	}
	pods, err := parseDebugPods(out)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	if sub == "ls" {
		if *output == "json" {
			return writeJSON(stdout, stderr, pods)
		}
		if len(pods) == 0 {
			fmt.Fprintf(stdout, "no debug pods on %s\n", s.label())
			return ExitOK
		}
		tw := newTable(stdout)
		fmt.Fprintln(tw, "NAMESPACE\tNAME\tOWNER\tKIND\tNODE\tSTATE\tAGE")
		for _, p := range pods {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.Namespace, p.Name, p.Owner, p.Kind, p.Node, strings.ToLower(p.Phase), p.Age)
		}
		tw.Flush()
		return ExitOK
	}

	me := debugOwner()
	var mine []debugPodInfo
	for _, p := range pods {
		if *all || p.Owner == me {
			mine = append(mine, p)
		}
	}
	if len(mine) == 0 {
		fmt.Fprintf(stderr, "no debug pods of yours on %s\n", s.label())
		return ExitOK
	}
	var shown strings.Builder
	byNS := map[string][]string{}
	for _, p := range mine {
		fmt.Fprintf(&shown, "delete pod %s/%s   (%s, %s, %s)\n", p.Namespace, p.Name, p.Owner, strings.ToLower(p.Phase), p.Age)
		byNS[p.Namespace] = append(byNS[p.Namespace], p.Name)
	}
	if code := approveDeploy(ctx, cfg, s, "removal of debug pods", shown.String(), false, d, stderr); code != ExitOK || d.dryRun {
		return code
	}
	base := audit.Event{Action: "debug-clean", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("removed %d debug pod(s), %s", len(mine), s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
		return ExitFailure
	}
	namespaces := make([]string, 0, len(byNS))
	for ns := range byNS {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		if _, err := s.output(ctx, "", append([]string{"delete", "pod", "-n", ns, "--wait=false", "--ignore-not-found"}, byNS[ns]...)...); err != nil {
			tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
			fmt.Fprintf(stderr, "removing debug pods in %s: %v\n", ns, err)
			return ExitFailure
		}
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, base.Detail, stderr)
	fmt.Fprintf(stderr, "removed %d debug pod(s)\n", len(mine))
	return ExitOK
}

func parseDebugPods(data []byte) ([]debugPodInfo, error) {
	var list struct {
		Items []struct {
			Metadata struct {
				Name, Namespace   string
				Labels            map[string]string
				CreationTimestamp time.Time
			}
			Spec   struct{ NodeName string }
			Status struct{ Phase string }
		}
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("reading the pod list: %w", err)
	}
	pods := []debugPodInfo{}
	for _, it := range list.Items {
		age := "-"
		if !it.Metadata.CreationTimestamp.IsZero() {
			age = shortDuration(now().Sub(it.Metadata.CreationTimestamp))
		}
		pods = append(pods, debugPodInfo{Name: it.Metadata.Name, Namespace: it.Metadata.Namespace, Owner: it.Metadata.Labels["nedctl.io/owner"],
			Kind: it.Metadata.Labels["nedctl.io/kind"], Node: it.Spec.NodeName, Phase: it.Status.Phase, Age: age})
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Namespace+pods[i].Name < pods[j].Namespace+pods[j].Name })
	return pods, nil
}

// flushSafe writes what remains in safetext writers.
func flushSafe(ws ...io.Writer) {
	for _, w := range ws {
		if f, ok := w.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
}
