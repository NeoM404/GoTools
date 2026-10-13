package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// Probes are read-only kubectl commands run on one cluster or many: the
// AKS clusters on a bastion (one SSH connection runs them all, a few
// clusters at a time), the EKS clusters of the signed-in account (one
// tunnel each, in turn), or one chosen cluster. health, fleet run, app,
// posture, images and access review are built on them.

// probe is one kubectl command, without "kubectl".
type probe []string

// probeOut is one probe's result on one cluster.
type probeOut struct {
	Out []byte
	Err error
}

// clusterOut is every probe's result on one cluster.
type clusterOut struct {
	Cloud, Env, Cluster, Where string
	Outs                       []probeOut
	Err                        error // the cluster could not be reached at all
}

// clusterSel says which clusters: one (--cluster, or picked), the AKS
// clusters of environments (--env, narrowed by --match), or every EKS
// cluster in the signed-in account (--aws).
type clusterSel struct {
	cluster, env, match, awsProfile string
	awsEnv                          string // EKS in these environments' accounts of your squad
	aws                             bool
	sink                            *probeSink // optional: told as clusters are found and as each one's results arrive
}

// probeSink hears about a run as it happens, for live displays: the
// clusters about to be read, then each cluster's results as they arrive
// (in the order clusters finish).
type probeSink struct {
	start  func(cloud, env string, clusters []string)
	result func(clusterOut)
}

func (k *probeSink) started(cloud, env string, clusters []string) {
	if k != nil && k.start != nil {
		k.start(cloud, env, clusters)
	}
}

func (k *probeSink) got(co clusterOut) {
	if k != nil && k.result != nil {
		k.result(co)
	}
}

func addClusterSel(fs *flag.FlagSet, sel *clusterSel, multi bool) {
	fs.StringVar(&sel.cluster, "cluster", "", "the cluster (default: pick one; an AKS name picks its bastion)")
	fs.StringVar(&sel.awsProfile, "aws-profile", "", "EKS: AWS profile to act with (default: the current one)")
	if multi {
		fs.StringVar(&sel.env, "env", "", "AKS: every cluster on these environments' bastions, e.g. qa or dev,qa")
		fs.StringVar(&sel.match, "match", "", "with --env or --aws: only clusters whose name contains this")
		fs.BoolVar(&sel.aws, "aws", false, "every EKS cluster in the account you are signed in to")
		fs.StringVar(&sel.awsEnv, "aws-env", "", "EKS: every cluster in your squad's accounts for these environments, e.g. ete,qa (same role where you hold it)")
	} else {
		fs.StringVar(&sel.env, "env", "", "AKS: the environment whose bastion to use")
	}
}

func (sel clusterSel) multi() bool {
	return sel.cluster == "" && (sel.aws || sel.env != "" || sel.awsEnv != "")
}

// runProbes runs the probes on the selected clusters.
func runProbes(ctx context.Context, cfg config.Config, sel clusterSel, probes []probe, stderr io.Writer) ([]clusterOut, int) {
	if !sel.multi() {
		s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
		if code != ExitOK {
			return nil, code
		}
		defer s.close()
		sel.sink.started(s.cloud, s.env, []string{s.cluster})
		sp := spinning(stderr, "Reading "+s.label()+"…")
		co := sessionProbes(ctx, s, probes)
		sp.Stop()
		sel.sink.got(co)
		return []clusterOut{co}, ExitOK
	}
	var all []clusterOut
	if sel.env != "" {
		if !cfg.Azure.Configured() {
			fmt.Fprintln(stderr, "--env needs Azure access (azure.bastions) — see docs/azure.md")
			return nil, ExitFailure
		}
		for _, env := range strings.Split(strings.ToLower(sel.env), ",") {
			env = strings.TrimSpace(env)
			if _, ok := cfg.Azure.Bastion(env); !ok {
				fmt.Fprintf(stderr, "no bastion for %q — azure.bastions has %s\n", env, strings.Join(azureEnvs(cfg), ", "))
				return nil, ExitUsage
			}
			all = append(all, bastionProbes(ctx, cfg, bastionTarget(cfg, env), sel.match, probes, sel.sink, stderr)...)
		}
	}
	if sel.aws {
		all = append(all, eksProbes(ctx, cfg, sel, probes, stderr)...)
	}
	if sel.awsEnv != "" {
		cur, ok := loadProfileContext(ctx, cfg, sel.awsProfile, stderr)
		if !ok {
			return nil, ExitFailure
		}
		for _, env := range strings.Split(strings.ToLower(sel.awsEnv), ",") {
			if env = strings.TrimSpace(env); env == "" {
				continue
			}
			name, err := profileForEnv(ctx, cfg, cur, env, stderr)
			if err != nil {
				co := clusterOut{Cloud: "aws", Env: env, Where: "EKS " + strings.ToUpper(env), Err: err}
				sel.sink.got(co)
				all = append(all, co)
				continue
			}
			sub := sel
			sub.awsProfile = name
			all = append(all, eksProbes(ctx, cfg, sub, probes, stderr)...)
		}
	}
	return all, ExitOK
}

func sessionProbes(ctx context.Context, s *kubeSession, probes []probe) clusterOut {
	co := clusterOut{Cloud: s.cloud, Env: s.env, Cluster: s.cluster, Where: s.where}
	for i, p := range probes {
		if i > 0 && co.Outs[0].Err != nil {
			// As on a bastion: a cluster that does not answer its first
			// request is not asked the rest.
			co.Outs = append(co.Outs, probeOut{nil, errors.New("not read: the cluster did not answer")})
			continue
		}
		out, err := s.output(ctx, "", append([]string{"--request-timeout=20s"}, p...)...)
		co.Outs = append(co.Outs, probeOut{out, err})
	}
	return co
}

// eksProbes runs the probes on every EKS cluster of the account, opening
// each cluster's tunnel in turn.
func eksProbes(ctx context.Context, cfg config.Config, sel clusterSel, probes []probe, stderr io.Writer) []clusterOut {
	pc, ok := loadProfileContext(ctx, cfg, sel.awsProfile, stderr)
	if !ok {
		return []clusterOut{{Cloud: "aws", Err: errors.New("not signed in")}}
	}
	hits, _, err := searchRegions(ctx, cfg, pc, regionSearch{}, "eks", stderr, func(region string) ([]clusterHit, error) {
		return clustersIn(ctx, cfg, pc.Name, region)
	})
	if err != nil {
		return []clusterOut{{Cloud: "aws", Env: pc.Environment, Err: err}}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	var names []string
	for _, h := range hits {
		if sel.match == "" || strings.Contains(h.Name, sel.match) {
			names = append(names, h.Name)
		}
	}
	sel.sink.started("aws", pc.Environment, names)
	var all []clusterOut
	for _, name := range names {
		s, code := openEKSSession(ctx, cfg, sessionFlags{cluster: name, awsProfile: sel.awsProfile}, stderr)
		if code != ExitOK {
			co := clusterOut{Cloud: "aws", Env: pc.Environment, Cluster: name, Err: errors.New("could not reach the cluster")}
			sel.sink.got(co)
			all = append(all, co)
			continue
		}
		sp := spinning(stderr, "Reading "+s.label()+"…")
		co := sessionProbes(ctx, s, probes)
		sp.Stop()
		s.close()
		sel.sink.got(co)
		all = append(all, co)
	}
	return all
}

// Markers framing each probe's output in the bastion script's output.
const (
	probeMark = "@@nedctl-probe@@"
	probeEnd  = "@@nedctl-end@@"
	probeDone = "@@nedctl-done@@" // on stderr as each cluster finishes, for progress
)

// bastionProbeScript runs every probe on every context given as an
// argument, eight clusters at a time (a new one starts as one finishes),
// and prints each cluster's results as soon as it is done — one writer, so
// clusters never interleave: per probe a mark line (context, probe), its
// stdout, an end line (exit code) and its stderr on one line. As each cluster finishes, a done line (context,
// probes failed) goes to stderr so progress shows. $1 is the request timeout; the probes are the
// functions p0, p1… defined in front of it.
const bastionProbeScript = `t=$1; shift
CAP=90
d=$(mktemp -d "${TMPDIR:-/tmp}/nedctl-probe.XXXXXX") || exit 1
trap 'rm -rf "$d"' EXIT
run() {
  c=$1 i=0 f=0 start=$SECONDS skip=""
  while [ $i -lt $N ]; do
    if [ -z "$skip" ] && [ $((SECONDS-start)) -ge "$CAP" ]; then
      skip="not read: the cluster took more than ${CAP}s"
    fi
    if [ -n "$skip" ]; then
      : > "$d/$c.$i.out"; echo "$skip" > "$d/$c.$i.err"; rc=124
    else
      "p$i" "$c" "$t" > "$d/$c.$i.out" 2> "$d/$c.$i.err"
      rc=$?
      # A cluster that does not answer its first question is not asked the
      # rest: each would wait out the same timeout.
      [ $i -eq 0 ] && [ $rc -ne 0 ] && skip="not read: the cluster did not answer"
    fi
    echo $rc > "$d/$c.$i.rc"
    [ $rc -eq 0 ] || f=$((f+1))
    i=$((i+1))
  done
  : > "$d/$c.done"
  printf '%s %s %s\n' '` + probeDone + `' "$c" $f >&2
}
emit() {
  c=$1 i=0
  while [ $i -lt $N ]; do
    printf '\n%s %s %s\n' '` + probeMark + `' "$c" $i
    cat "$d/$c.$i.out"
    printf '\n%s %s ' '` + probeEnd + `' "$(cat "$d/$c.$i.rc")"
    tr '\n' ' ' < "$d/$c.$i.err" | cut -c1-500
    echo
    i=$((i+1))
  done
}
collect() {
  for c in "$@"; do
    if [ -f "$d/$c.done" ] && [ ! -f "$d/$c.sent" ]; then
      emit "$c"
      : > "$d/$c.sent"
    fi
  done
}
for c in "$@"; do
  while [ "$(jobs -rp | wc -l)" -ge 8 ]; do collect "$@"; sleep 0.2; done
  run "$c" &
done
while [ "$(jobs -rp | wc -l)" -gt 0 ]; do collect "$@"; sleep 0.2; done
wait
collect "$@"
`

// probeFunctions defines p0, p1… for the bastion script. Every argument
// is quoted, so none can change the script.
func probeFunctions(probes []probe) string {
	var b strings.Builder
	fmt.Fprintf(&b, "N=%d\n", len(probes))
	for i, p := range probes {
		q := make([]string, len(p))
		for j, a := range p {
			q[j] = shellQuote(a)
		}
		fmt.Fprintf(&b, "p%d() { kubectl --context \"$1\" --request-timeout=\"$2\" %s; }\n", i, strings.Join(q, " "))
	}
	return b.String()
}

// bastionProbes lists the bastion's clusters (or uses the remembered
// list), then runs the probes on them in one SSH connection.
func bastionProbes(ctx context.Context, cfg config.Config, t sshTarget, match string, probes []probe, sink *probeSink, stderr io.Writer) []clusterOut {
	names, err := listAKS(ctx, cfg, t, stderr)
	if err != nil {
		return []clusterOut{{Cloud: "azure", Env: t.Env, Where: "on bastion " + t.Name, Err: err}}
	}
	var clusters []string
	for _, n := range names {
		if match == "" || strings.Contains(n, match) {
			clusters = append(clusters, n)
		}
	}
	if len(clusters) == 0 {
		fmt.Fprintf(stderr, "no clusters on %s match %q\n", t.Name, match)
		return nil
	}
	fmt.Fprintf(stderr, "Reading %d cluster(s) on %s, 8 at a time (up to 20s a request)…\n", len(clusters), t.Name)
	sink.started("azure", t.Env, clusters)
	var out bytes.Buffer
	var stdout io.Writer = &out
	if sink != nil {
		stdout = io.MultiWriter(&out, &probeStream{n: len(probes), emit: func(chunk []byte, c string) {
			sink.got(parseProbeOutput(chunk, "azure", t.Env, "on bastion "+t.Name, []string{c}, len(probes))[0])
		}})
	}
	prog := newProbeProgress(stderr, t.Name, len(clusters))
	script := probeFunctions(probes) + bastionProbeScript
	err = execx.Interactive(ctx, execx.Spec{Stdin: strings.NewReader(""), Name: "ssh", Stdout: stdout, Stderr: prog,
		Args: sshArgs(cfg, t, false, remoteBash(script, append([]string{"20s"}, clusters...)...)), Timeout: cfg.AWS.Timeout()})
	prog.finish()
	if err != nil {
		err = sshError(t, err)
		if msg := safetext.Text(strings.TrimSpace(prog.other.String())); msg != "" && !strings.Contains(err.Error(), "could not reach") {
			err = fmt.Errorf("%w: %s", err, msg)
		}
		return []clusterOut{{Cloud: "azure", Env: t.Env, Where: "on bastion " + t.Name, Err: err}}
	}
	return parseProbeOutput(out.Bytes(), "azure", t.Env, "on bastion "+t.Name, clusters, len(probes))
}

// working shows msg with a spinner while a wait lasts, on a terminal; in
// a log or pipe it prints msg once, as before. Stop it when the wait ends.
func working(w io.Writer, msg string) *ui.Spinner {
	st := ui.Style{Color: colorOn(w)}
	if !st.Color {
		fmt.Fprintln(w, msg)
	}
	return st.Spinner(w, msg)
}

// spinning is working that prints nothing off a terminal: for short waits
// whose result is printed straight after.
func spinning(w io.Writer, msg string) *ui.Spinner {
	return ui.Style{Color: colorOn(w)}.Spinner(w, msg)
}

// probeProgress reads the bastion script's stderr: each done line moves a
// counter, shown on a spinner on a terminal and every quarter otherwise;
// any other line is kept for the error should SSH fail.
type probeProgress struct {
	w           io.Writer
	where       string
	total, done int
	failed      int
	spin        *ui.Spinner // nil when not a terminal
	partial     []byte
	other       bytes.Buffer
}

func newProbeProgress(w io.Writer, where string, total int) *probeProgress {
	p := &probeProgress{w: w, where: where, total: total}
	if st := (ui.Style{Color: colorOn(w)}); st.Color {
		p.spin = st.Spinner(w, p.message())
	}
	return p
}

func (p *probeProgress) message() string {
	msg := fmt.Sprintf("Reading clusters on %s: %d/%d done", p.where, p.done, p.total)
	if p.failed > 0 {
		msg += fmt.Sprintf(", %d with errors", p.failed)
	}
	return msg + "…"
}

func (p *probeProgress) Write(b []byte) (int, error) {
	p.partial = append(p.partial, b...)
	for {
		i := bytes.IndexByte(p.partial, '\n')
		if i < 0 {
			break
		}
		line := string(p.partial[:i])
		p.partial = p.partial[i+1:]
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != probeDone {
			if p.other.Len() < 4<<10 {
				p.other.WriteString(line + "\n")
			}
			continue
		}
		p.done++
		if f[2] != "0" {
			p.failed++
		}
		switch {
		case p.spin != nil:
			p.spin.Set(p.message())
		case p.done == p.total || p.done%max(1, p.total/4) == 0:
			fmt.Fprintln(p.w, p.summary())
		}
	}
	return len(b), nil
}

// finish stops the spinner, leaving a one-line summary behind.
func (p *probeProgress) finish() {
	if p.spin == nil {
		return
	}
	p.spin.Stop()
	if p.done > 0 {
		fmt.Fprintln(p.w, p.summary())
	}
}

func (p *probeProgress) summary() string {
	msg := fmt.Sprintf("  %d/%d clusters read", p.done, p.total)
	if p.failed > 0 {
		msg += fmt.Sprintf(" (%d with errors)", p.failed)
	}
	return msg
}

// probeStream watches the bastion script's output and hands over each
// cluster's chunk once its last probe has ended (the script sends a
// cluster's probes together).
type probeStream struct {
	n       int
	emit    func(chunk []byte, cluster string)
	partial []byte
	chunk   bytes.Buffer
	cur     string
	last    int
}

func (p *probeStream) Write(b []byte) (int, error) {
	p.partial = append(p.partial, b...)
	for {
		i := bytes.IndexByte(p.partial, '\n')
		if i < 0 {
			return len(b), nil
		}
		line := p.partial[:i+1]
		trim := strings.TrimRight(string(line), "\n")
		if strings.HasPrefix(trim, probeMark+" ") {
			if f := strings.Fields(trim); len(f) == 3 {
				idx, _ := strconv.Atoi(f[2])
				if idx == 0 {
					p.chunk.Reset()
					p.cur = f[1]
				}
				p.last = idx
			}
		}
		p.chunk.Write(line)
		if strings.HasPrefix(trim, probeEnd+" ") && p.last == p.n-1 && p.cur != "" {
			p.emit(append([]byte("\n"), p.chunk.Bytes()...), p.cur)
			p.chunk.Reset()
			p.cur = ""
		}
		p.partial = p.partial[i+1:]
	}
}

// parseProbeOutput splits the bastion script's output into results.
func parseProbeOutput(data []byte, cloud, env, where string, clusters []string, n int) []clusterOut {
	byCluster := map[string]*clusterOut{}
	var order []*clusterOut
	for _, c := range clusters {
		co := &clusterOut{Cloud: cloud, Env: env, Cluster: c, Where: where, Outs: make([]probeOut, n)}
		for i := range co.Outs {
			co.Outs[i].Err = errors.New("no result")
		}
		byCluster[c] = co
		order = append(order, co)
	}
	var cur *probeOut
	var buf bytes.Buffer
	for _, line := range strings.SplitAfter(string(data), "\n") {
		trim := strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(trim, probeMark+" "):
			f := strings.Fields(trim)
			cur = nil
			buf.Reset()
			if len(f) == 3 {
				if co, ok := byCluster[f[1]]; ok {
					if i, err := strconv.Atoi(f[2]); err == nil && i >= 0 && i < n {
						cur = &co.Outs[i]
					}
				}
			}
		case strings.HasPrefix(trim, probeEnd+" ") && cur != nil:
			rest := strings.TrimPrefix(trim, probeEnd+" ")
			rc, msg, _ := strings.Cut(rest, " ")
			out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
			cur.Out = safetext.Bytes(append([]byte(nil), out...))
			cur.Err = nil
			if rc != "0" {
				cur.Err = fmt.Errorf("%s", firstNonBlank(safetext.Text(strings.TrimSpace(msg)), "exit status "+rc))
			}
			cur = nil
		case cur != nil:
			buf.WriteString(line)
		}
	}
	res := make([]clusterOut, len(order))
	for i, co := range order {
		res[i] = *co
	}
	return res
}

// reachErr is the first error of a cluster's results: unreachable, or
// the first probe failing.
func (co clusterOut) reachErr() error {
	if co.Err != nil {
		return co.Err
	}
	if len(co.Outs) > 0 && co.Outs[0].Err != nil {
		return co.Outs[0].Err
	}
	return nil
}
