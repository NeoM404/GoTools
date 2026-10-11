package app

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl images` is the inventory of every image actually running: by
// reference, with the digests running it, its registry, and where — the
// list a scanner (trivy, Defender, Inspector) works from. It flags images
// from unapproved registries, mutable tags, and a tag running with
// different digests (someone re-pushed it). Read-only.

var imagesProbe = probe{"get", "pods", "-A", "-o",
	`jsonpath={range .items[*]}P{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{range .status.containerStatuses[*]}C{"\t"}{.name}{"\t"}{.image}{"\t"}{.imageID}{"\n"}{end}{range .status.initContainerStatuses[*]}C{"\t"}{.name}{"\t"}{.image}{"\t"}{.imageID}{"\n"}{end}{end}`}

// imageRow is one image reference and where it runs.
type imageRow struct {
	Image      string   `json:"image"`
	Registry   string   `json:"registry"`
	Tag        string   `json:"tag"`
	Digests    []string `json:"digests"`
	Clusters   []string `json:"clusters"`
	Namespaces []string `json:"namespaces"`
	Containers int      `json:"containers"`
	Flags      []string `json:"flags,omitempty"`
}

func cmdImages(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("images", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	registry := fs.String("registry", "", "only images from this registry")
	onlyFlagged := fs.Bool("flagged", false, "only images with a flag (unapproved registry, mutable tag, several digests)")
	failUnapproved := fs.Bool("fail-on-unapproved", false, "exit 1 when an image comes from a registry not in security.approvedRegistries")
	output := fs.String("o", "table", "output format: table|json|csv")
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(stderr, "usage: nedctl images [--cluster C | --env prod | --aws] [--match WORD] [--registry R] [--flagged] [-o table|json|csv]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" && *output != "csv" {
		fmt.Fprintf(stderr, "invalid output format %q (want: table|json|csv)\n", *output)
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, []probe{imagesProbe}, stderr)
	if code != ExitOK {
		return code
	}
	rows, unreachable := imageInventory(cfg, results)
	var shown []imageRow
	unapproved := false
	for _, r := range rows {
		for _, f := range r.Flags {
			unapproved = unapproved || f == "unapproved-registry"
		}
		if (*registry != "" && r.Registry != strings.ToLower(*registry)) || (*onlyFlagged && len(r.Flags) == 0) {
			continue
		}
		shown = append(shown, r)
	}
	switch *output {
	case "json":
		if shown == nil {
			shown = []imageRow{}
		}
		if code := writeJSON(stdout, stderr, shown); code != ExitOK {
			return code
		}
	case "csv":
		w := csv.NewWriter(stdout)
		_ = w.Write([]string{"image", "registry", "tag", "digests", "clusters", "namespaces", "containers", "flags"})
		for _, r := range shown {
			_ = w.Write([]string{r.Image, r.Registry, r.Tag, strings.Join(r.Digests, " "), strings.Join(r.Clusters, " "),
				strings.Join(r.Namespaces, " "), fmt.Sprint(r.Containers), strings.Join(r.Flags, " ")})
		}
		w.Flush()
	default:
		printImages(stdout, shown, len(rows))
	}
	for _, u := range unreachable {
		fmt.Fprintf(stderr, "warning: %s\n", u)
	}
	if *failUnapproved && unapproved {
		return ExitFailure
	}
	return ExitOK
}

func imageInventory(cfg config.Config, results []clusterOut) ([]imageRow, []string) {
	type acc struct {
		row                    imageRow
		digests, clusters, nss map[string]bool
	}
	all := map[string]*acc{}
	var unreachable []string
	for _, r := range results {
		if err := r.reachErr(); err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", firstNonBlank(r.Cluster, r.Where), err))
			continue
		}
		ns := ""
		for _, l := range strings.Split(string(r.Outs[0].Out), "\n") {
			f := strings.Split(l, "\t")
			switch {
			case len(f) >= 3 && f[0] == "P":
				ns = f[1]
			case len(f) >= 4 && f[0] == "C" && f[2] != "":
				a := all[f[2]]
				if a == nil {
					a = &acc{row: imageRow{Image: f[2], Registry: registryOf(f[2]), Tag: imageTag(f[2])},
						digests: map[string]bool{}, clusters: map[string]bool{}, nss: map[string]bool{}}
					all[f[2]] = a
				}
				if _, d, ok := strings.Cut(f[3], "@"); ok {
					a.digests[d] = true
				}
				a.clusters[r.Cluster] = true
				a.nss[ns] = true
				a.row.Containers++
			}
		}
	}
	keys := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	rows := make([]imageRow, 0, len(all))
	for _, a := range all {
		r := a.row
		r.Digests, r.Clusters, r.Namespaces = keys(a.digests), keys(a.clusters), keys(a.nss)
		if !cfg.Security.RegistryApproved(r.Registry) {
			r.Flags = append(r.Flags, "unapproved-registry")
		}
		if r.Tag == "latest" {
			r.Flags = append(r.Flags, "mutable-tag")
		}
		if len(r.Digests) > 1 && !strings.Contains(r.Image, "@") {
			r.Flags = append(r.Flags, "several-digests")
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Image < rows[j].Image })
	return rows, unreachable
}

func printImages(w io.Writer, rows []imageRow, total int) {
	st := ui.Style{Color: colorOn(w)}
	tw := newTable(w)
	fmt.Fprintln(tw, "IMAGE\tDIGEST\tCLUSTERS\tCONTAINERS\tFLAGS")
	for _, r := range rows {
		d := "-"
		if len(r.Digests) > 0 {
			d = strings.TrimPrefix(r.Digests[0], "sha256:")
			d = d[:min(12, len(d))]
			if len(r.Digests) > 1 {
				d += fmt.Sprintf(" +%d", len(r.Digests)-1)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", r.Image, d, len(r.Clusters), r.Containers, strings.Join(r.Flags, ", "))
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d image(s) shown of %d running. %s\n", len(rows), total, st.Dim("-o csv for a scanner; -o json for everything"))
}
