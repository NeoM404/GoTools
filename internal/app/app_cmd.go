package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl app NAME` finds an application everywhere it runs — every AKS
// cluster on the chosen bastions, and the signed-in account's EKS clusters
// with --aws — and shows, per environment, its image version, how many
// replicas are ready and when it last changed. "QA has 1.4.2, prod 1.3.9"
// without opening a shell. Read-only.

// appRow is one deployment or statefulset found.
type appRow struct {
	Environment string   `json:"environment"`
	Cluster     string   `json:"cluster"`
	Namespace   string   `json:"namespace"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Desired     int      `json:"desired"`
	Ready       int      `json:"ready"`
	Images      []string `json:"images"`
	Updated     string   `json:"updated,omitempty"`
}

// appProbe lists deployments and statefulsets compactly (tab-separated),
// so a bastion of many clusters answers in kilobytes, not megabytes.
var appProbe = probe{"get", "deployments,statefulsets", "-A", "-o",
	`jsonpath={range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.replicas}{"\t"}{.status.readyReplicas}{"\t"}{.spec.template.spec.containers[*].image}{"\t"}{.status.conditions[?(@.type=="Progressing")].lastUpdateTime}{"\n"}{end}`}

func cmdApp(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	ns := fs.String("n", "", "only this namespace")
	exact := fs.Bool("exact", false, "the name must match exactly (default: names containing it)")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || !podNameRe.MatchString(pos[0]) || (*ns != "" && !config.ValidNamespace(*ns)) {
		fmt.Fprintln(stderr, "usage: nedctl app NAME [--env dev,qa | --cluster C | --aws] [--match WORD] [-n NS] [--exact]")
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
		// Everywhere by default: every bastion's environment.
		if !cfg.Azure.Configured() && !cfg.AWS.Configured() {
			fmt.Fprintln(stderr, "no clusters to search — run `nedctl setup` or add azure.bastions")
			return ExitFailure
		}
		sel.env = strings.Join(azureEnvs(cfg), ",")
		sel.aws = sel.env == "" && cfg.AWS.Configured()
	}
	results, code := runProbes(ctx, cfg, sel, []probe{appProbe}, stderr)
	if code != ExitOK {
		return code
	}
	rows, unreachable := appRows(results, pos[0], *ns, *exact)
	if *output == "json" {
		if code := writeJSON(stdout, stderr, rows); code != ExitOK {
			return code
		}
	} else {
		printApp(stdout, cfg, pos[0], rows, len(results))
	}
	for _, u := range unreachable {
		fmt.Fprintf(stderr, "warning: %s\n", u)
	}
	if len(rows) == 0 {
		return ExitFailure
	}
	return ExitOK
}

func appRows(results []clusterOut, name, ns string, exact bool) ([]appRow, []string) {
	rows := []appRow{}
	var unreachable []string
	for _, r := range results {
		if err := r.reachErr(); err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", firstNonBlank(r.Cluster, r.Where), err))
			continue
		}
		for _, line := range strings.Split(string(r.Outs[0].Out), "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 7 {
				continue
			}
			match := f[2] == name || (!exact && strings.Contains(f[2], name))
			if !match || (ns != "" && f[1] != ns) {
				continue
			}
			desired, err := strconv.Atoi(f[3])
			if err != nil {
				desired = 1
			}
			ready, _ := strconv.Atoi(f[4])
			rows = append(rows, appRow{Environment: r.Env, Cluster: r.Cluster, Namespace: f[1], Kind: strings.ToLower(f[0]), Name: f[2],
				Desired: desired, Ready: ready, Images: strings.Fields(f[5]), Updated: f[6]})
		}
	}
	order := map[string]int{"dev": 0, "ete": 1, "qa": 2, "prod": 3}
	sort.SliceStable(rows, func(i, j int) bool {
		oi, iok := order[rows[i].Environment]
		oj, jok := order[rows[j].Environment]
		if !iok {
			oi = 9
		}
		if !jok {
			oj = 9
		}
		if oi != oj {
			return oi < oj
		}
		return rows[i].Cluster+rows[i].Namespace+rows[i].Name < rows[j].Cluster+rows[j].Namespace+rows[j].Name
	})
	return rows, unreachable
}

// imageTag is what people call the version: the tag (or a short digest).
func imageTag(image string) string {
	if _, d, ok := strings.Cut(image, "@"); ok {
		return strings.TrimPrefix(d, "sha256:")[:min(12, len(strings.TrimPrefix(d, "sha256:")))]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[i+1:]
	}
	return "latest"
}

func printApp(w io.Writer, cfg config.Config, name string, rows []appRow, searched int) {
	st := ui.Style{Color: colorOn(w)}
	if len(rows) == 0 {
		fmt.Fprintf(w, "%s not found on the %d cluster(s) searched\n", name, searched)
		return
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "ENV\tCLUSTER\tNAMESPACE\tNAME\tREADY\tVERSION\tUPDATED")
	for _, r := range rows {
		tags := make([]string, len(r.Images))
		for i, im := range r.Images {
			tags[i] = imageTag(im)
		}
		ready := fmt.Sprintf("%d/%d", r.Ready, r.Desired)
		if r.Ready < r.Desired {
			ready = st.Fg(ui.Amber, ready)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Environment, r.Cluster, r.Namespace, r.Name, ready, strings.Join(tags, ","), strings.TrimSuffix(r.Updated, "Z"))
	}
	tw.Flush()
	// One line that answers "what runs where", when the names agree.
	var parts []string
	seen := map[string]bool{}
	for _, r := range rows {
		if len(r.Images) == 0 {
			continue
		}
		key := r.Environment + " " + imageTag(r.Images[0])
		if !seen[key] {
			seen[key] = true
			parts = append(parts, st.Fg(cfg.ColorFor(r.Environment), key))
		}
	}
	if len(parts) > 1 {
		fmt.Fprintf(w, "\nversions: %s\n", strings.Join(parts, " · "))
	}
}
