package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl diff NAME --env qa,prod` answers "it works in QA but not in
// prod": the same deployment or statefulset side by side wherever it runs —
// images, replicas, resources, probes, service account, node placement,
// environment variable NAMES and the ConfigMaps and Secrets it loads. Only
// names are ever read, never values. Read-only.

var diffProbe = probe{"get", "deployments,statefulsets", "-A", "-o",
	`jsonpath={range .items[*]}W{"\t"}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.spec.strategy.type}{.spec.updateStrategy.type}{"\t"}{.spec.template.spec.serviceAccountName}{"\t"}{.spec.template.spec.nodeSelector}{"\t"}{.spec.template.spec.tolerations[*].key}{"\n"}` +
		`{range .spec.template.spec.containers[*]}C{"\t"}{.name}{"\t"}{.image}{"\t"}{.resources.requests.cpu}{"\t"}{.resources.requests.memory}{"\t"}{.resources.limits.cpu}{"\t"}{.resources.limits.memory}{"\t"}{range .env[*]}{.name}{" "}{end}{"\t"}{range .envFrom[*]}{.configMapRef.name}{.secretRef.name}{" "}{end}{"\t"}{.readinessProbe.httpGet.path}{.readinessProbe.tcpSocket.port}{.readinessProbe.exec.command[0]}{"\t"}{.livenessProbe.httpGet.path}{.livenessProbe.tcpSocket.port}{.livenessProbe.exec.command[0]}{"\n"}{end}{end}`}

// diffSide is the app in one place: attribute → value.
type diffSide struct {
	Where string            `json:"where"`
	Env   string            `json:"environment"`
	Attrs map[string]string `json:"attributes"`
}

func diffSides(results []clusterOut, name, ns string) ([]diffSide, []string) {
	var sides []diffSide
	var unreachable []string
	for _, r := range results {
		if err := r.reachErr(); err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", firstNonBlank(r.Cluster, r.Where), err))
			continue
		}
		var cur *diffSide
		for _, line := range strings.Split(string(r.Outs[0].Out), "\n") {
			f := strings.Split(line, "\t")
			switch {
			case len(f) >= 9 && f[0] == "W":
				cur = nil
				if f[3] != name || (ns != "" && f[2] != ns) {
					continue
				}
				sides = append(sides, diffSide{Where: strings.TrimSpace(strings.ToUpper(r.Env) + " " + r.Cluster + "/" + f[2]), Env: r.Env, Attrs: map[string]string{
					"kind": strings.ToLower(f[1]), "replicas": firstNonBlank(f[4], "1"), "strategy": f[5], "service account": firstNonBlank(f[6], "default"),
					"node selector": f[7], "tolerations": strings.Join(strings.Fields(f[8]), " "),
				}})
				cur = &sides[len(sides)-1]
			case len(f) >= 11 && f[0] == "C" && cur != nil:
				c := f[1]
				set := func(k, v string) { cur.Attrs[c+": "+k] = v }
				set("image", f[2])
				set("cpu request", f[3])
				set("memory request", f[4])
				set("cpu limit", f[5])
				set("memory limit", f[6])
				set("env names", sortedWords(f[7]))
				set("loads (ConfigMap/Secret)", sortedWords(f[8]))
				set("readiness probe", f[9])
				set("liveness probe", f[10])
			}
		}
	}
	return sides, unreachable
}

func sortedWords(s string) string {
	w := strings.Fields(s)
	sort.Strings(w)
	return strings.Join(w, " ")
}

func cmdDiff(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	ns := fs.String("n", "", "only this namespace")
	all := fs.Bool("all", false, "also show what is the same everywhere")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 || !podNameRe.MatchString(pos[0]) || (*ns != "" && !config.ValidNamespace(*ns)) {
		fmt.Fprintln(stderr, "usage: nedctl diff NAME [--env qa,prod | --aws] [--match WORD] [-n NS] [--all] [-o json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if !sel.multi() && sel.cluster == "" {
		sel.env = strings.Join(azureEnvs(cfg), ",")
		sel.aws = sel.env == "" && cfg.AWS.Configured()
	}
	results, code := runProbes(ctx, cfg, sel, []probe{diffProbe}, stderr)
	if code != ExitOK {
		return code
	}
	sides, unreachable := diffSides(results, pos[0], *ns)
	for _, u := range unreachable {
		fmt.Fprintf(stderr, "warning: %s\n", u)
	}
	if len(sides) == 0 {
		fmt.Fprintf(stderr, "%s not found (exact name; -n narrows the namespace) — nedctl app %s searches by part of the name\n", pos[0], pos[0])
		return ExitFailure
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, sides)
	}
	printDiff(stdout, cfg, pos[0], sides, *all)
	return ExitOK
}

func printDiff(w io.Writer, cfg config.Config, name string, sides []diffSide, all bool) {
	st := ui.Style{Color: colorOn(w)}
	keys := map[string]bool{}
	for _, s := range sides {
		for k := range s.Attrs {
			keys[k] = true
		}
	}
	var attrs []string
	for k := range keys {
		attrs = append(attrs, k)
	}
	sort.Slice(attrs, func(i, j int) bool {
		ci, cj := strings.Contains(attrs[i], ": "), strings.Contains(attrs[j], ": ")
		if ci != cj {
			return !ci // the workload's own attributes first, then per container
		}
		return attrs[i] < attrs[j]
	})
	fmt.Fprintf(w, "%s in %d place(s)\n\n", st.Bold(name), len(sides))
	if len(sides) == 1 {
		fmt.Fprintln(w, st.Dim("only one place has it — nothing to compare; showing what it runs with"))
		all = true
	}
	tw := newTable(w)
	head := []string{headerMark, "SETTING"}
	for _, s := range sides {
		head = append(head, s.Where)
	}
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	differ := 0
	for _, a := range attrs {
		vals := make([]string, len(sides))
		same := true
		for i, s := range sides {
			v, ok := s.Attrs[a]
			switch {
			case !ok:
				v = "(no such container)"
			case v == "":
				v = "-"
			}
			vals[i] = v
			same = same && v == vals[0]
		}
		if same && !all && !strings.HasSuffix(a, ": image") {
			continue
		}
		mark := " "
		if !same {
			mark = st.Fg(ui.Amber, "≠")
			differ++
		}
		if strings.HasSuffix(a, "env names") || strings.HasSuffix(a, "loads (ConfigMap/Secret)") {
			vals = setDiff(vals)
		}
		cells := append([]string{mark, a}, vals...)
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
	fmt.Fprintln(w)
	switch {
	case len(sides) == 1:
	case differ == 0:
		fmt.Fprintln(w, st.OK("the same everywhere (images shown) — the difference is outside the workload: data, network, dependencies"))
	default:
		fmt.Fprintln(w, st.Warn(fmt.Sprintf("%d difference(s) — environment variable values and Secret contents are never read, only their names", differ)))
	}
}

// setDiff turns full word lists into what each side has that the first
// does not (+) and lacks (−), which is what matters in a long list.
func setDiff(vals []string) []string {
	base := map[string]bool{}
	for _, w := range strings.Fields(vals[0]) {
		base[w] = true
	}
	out := make([]string, len(vals))
	out[0] = vals[0]
	if len(out[0]) > 40 {
		out[0] = fmt.Sprintf("%d names", len(base))
	}
	for i := 1; i < len(vals); i++ {
		have := map[string]bool{}
		var plus, minus []string
		for _, w := range strings.Fields(vals[i]) {
			have[w] = true
			if !base[w] {
				plus = append(plus, "+"+w)
			}
		}
		for w := range base {
			if !have[w] {
				minus = append(minus, "−"+w)
			}
		}
		sort.Strings(minus)
		if len(plus)+len(minus) == 0 {
			out[i] = "same"
			continue
		}
		out[i] = strings.Join(append(plus, minus...), " ")
	}
	return out
}
