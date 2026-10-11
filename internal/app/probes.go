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
	aws                             bool
}

func addClusterSel(fs *flag.FlagSet, sel *clusterSel, multi bool) {
	fs.StringVar(&sel.cluster, "cluster", "", "the cluster (default: pick one; an AKS name picks its bastion)")
	fs.StringVar(&sel.awsProfile, "aws-profile", "", "EKS: AWS profile to act with (default: the current one)")
	if multi {
		fs.StringVar(&sel.env, "env", "", "AKS: every cluster on these environments' bastions, e.g. qa or dev,qa")
		fs.StringVar(&sel.match, "match", "", "with --env or --aws: only clusters whose name contains this")
		fs.BoolVar(&sel.aws, "aws", false, "every EKS cluster in the account you are signed in to")
	} else {
		fs.StringVar(&sel.env, "env", "", "AKS: the environment whose bastion to use")
	}
}

func (sel clusterSel) multi() bool { return sel.cluster == "" && (sel.aws || sel.env != "") }

// runProbes runs the probes on the selected clusters.
func runProbes(ctx context.Context, cfg config.Config, sel clusterSel, probes []probe, stderr io.Writer) ([]clusterOut, int) {
	if !sel.multi() {
		s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
		if code != ExitOK {
			return nil, code
		}
		defer s.close()
		return []clusterOut{sessionProbes(ctx, s, probes)}, ExitOK
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
			all = append(all, bastionProbes(ctx, cfg, bastionTarget(cfg, env), sel.match, probes, stderr)...)
		}
	}
	if sel.aws {
		all = append(all, eksProbes(ctx, cfg, sel, probes, stderr)...)
	}
	return all, ExitOK
}

func sessionProbes(ctx context.Context, s *kubeSession, probes []probe) clusterOut {
	co := clusterOut{Cloud: s.cloud, Env: s.env, Cluster: s.cluster, Where: s.where}
	for _, p := range probes {
		out, err := s.output(ctx, "", p...)
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
	var all []clusterOut
	for _, h := range hits {
		if sel.match != "" && !strings.Contains(h.Name, sel.match) {
			continue
		}
		s, code := openEKSSession(ctx, cfg, sessionFlags{cluster: h.Name, awsProfile: sel.awsProfile}, stderr)
		if code != ExitOK {
			all = append(all, clusterOut{Cloud: "aws", Env: pc.Environment, Cluster: h.Name, Err: errors.New("could not reach the cluster")})
			continue
		}
		all = append(all, sessionProbes(ctx, s, probes))
		s.close()
	}
	return all
}

// Markers framing each probe's output in the bastion script's output.
const (
	probeMark = "@@nedctl-probe@@"
	probeEnd  = "@@nedctl-end@@"
)

// bastionProbeScript runs every probe on every context given as an
// argument, eight clusters at a time, then prints the results in order:
// a mark line (context, probe), its stdout, an end line (exit code) and
// its stderr on one line. $1 is the request timeout; the probes are the
// functions p0, p1… defined in front of it.
const bastionProbeScript = `t=$1; shift
d=$(mktemp -d "${TMPDIR:-/tmp}/nedctl-probe.XXXXXX") || exit 1
trap 'rm -rf "$d"' EXIT
run() {
  c=$1 i=0
  while [ $i -lt $N ]; do
    "p$i" "$c" "$t" > "$d/$c.$i.out" 2> "$d/$c.$i.err"
    echo $? > "$d/$c.$i.rc"
    i=$((i+1))
  done
}
n=0
for c in "$@"; do
  run "$c" &
  n=$((n+1))
  [ $((n % 8)) -eq 0 ] && wait
done
wait
for c in "$@"; do
  i=0
  while [ $i -lt $N ]; do
    printf '\n%s %s %s\n' '` + probeMark + `' "$c" $i
    cat "$d/$c.$i.out"
    printf '\n%s %s ' '` + probeEnd + `' "$(cat "$d/$c.$i.rc")"
    tr '\n' ' ' < "$d/$c.$i.err" | cut -c1-500
    echo
    i=$((i+1))
  done
done
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
func bastionProbes(ctx context.Context, cfg config.Config, t sshTarget, match string, probes []probe, stderr io.Writer) []clusterOut {
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
	fmt.Fprintf(stderr, "Reading %d cluster(s) on %s…\n", len(clusters), t.Name)
	var out bytes.Buffer
	script := probeFunctions(probes) + bastionProbeScript
	err = execx.Interactive(ctx, execx.Spec{Stdin: strings.NewReader(""), Name: "ssh", Stdout: &out,
		Args: sshArgs(cfg, t, false, remoteBash(script, append([]string{"20s"}, clusters...)...)), Timeout: cfg.AWS.Timeout()})
	if err != nil {
		err = sshError(t, err)
		return []clusterOut{{Cloud: "azure", Env: t.Env, Where: "on bastion " + t.Name, Err: err}}
	}
	return parseProbeOutput(out.Bytes(), "azure", t.Env, "on bastion "+t.Name, clusters, len(probes))
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
			cur.Out = append([]byte(nil), out...)
			cur.Err = nil
			if rc != "0" {
				cur.Err = fmt.Errorf("%s", firstNonBlank(strings.TrimSpace(msg), "exit status "+rc))
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
