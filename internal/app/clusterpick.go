package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/picker"
)

// resolveClusterArg turns kube/connect's optional cluster argument into a
// cluster name and, when it was chosen from a list, the region it is in (so
// planning does not search again). With no name: one cluster is used
// directly, several are offered in a picker with the last one used first.
func resolveClusterArg(ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, pos []string, stderr io.Writer) (string, regionSearch, int) {
	if len(pos) == 1 {
		return pos[0], rs, ExitOK
	}
	all, searched, err := searchRegions(ctx, cfg, pc, rs, "eks", stderr, func(region string) ([]clusterHit, error) {
		return clustersIn(ctx, cfg, pc.Name, region)
	})
	if err != nil {
		fmt.Fprintf(stderr, "listing clusters with %s: %v\n", pc.Name, err)
		return "", rs, ExitFailure
	}
	switch {
	case len(all) == 0:
		fmt.Fprintf(stderr, "no EKS clusters in %s (searched %s)\n", pc.label(), strings.Join(searched, ", "))
		return "", rs, ExitFailure
	case len(all) == 1:
		fmt.Fprintf(stderr, "Using %s, the only cluster in %s (%s)\n", all[0].Name, pc.label(), all[0].Region)
		return all[0].Name, regionSearch{Flag: all[0].Region}, ExitOK
	}
	last := loadLastCluster(cfg, pc)
	sort.SliceStable(all, func(i, j int) bool {
		if (all[i].Name == last) != (all[j].Name == last) {
			return all[i].Name == last
		}
		return all[i].Name < all[j].Name
	})
	if !stdinIsTerminal() {
		names := make([]string, len(all))
		for i, h := range all {
			names[i] = h.Name
		}
		fmt.Fprintf(stderr, "%d clusters in %s — name one: %s\n", len(all), pc.label(), strings.Join(names, ", "))
		return "", rs, ExitUsage
	}
	rows := make([]picker.Row, len(all))
	for i, h := range all {
		mark := ""
		if h.Name == last {
			mark = "last used"
		}
		rows[i] = picker.Row{Cells: []string{h.Name, h.Region, mark}, Color: cfg.ColorFor(pc.Environment), ColorCol: 0}
	}
	idx, err := picker.Picker{Title: "Clusters in " + pc.label(), Header: []string{"CLUSTER", "REGION", ""},
		Rows: rows, In: stdin, Out: stderr, Color: colorOn(stderr)}.Pick()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return "", rs, ExitFailure
	}
	return all[idx].Name, regionSearch{Flag: all[idx].Region}, ExitOK
}

func lastClusterPath(cfg config.Config, pc profileContext) (string, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	key := firstNonBlank(pc.AccountID, strings.NewReplacer("/", "_", "\\", "_").Replace(pc.Name))
	return filepath.Join(filepath.Dir(log), "last-cluster", key), nil
}

func loadLastCluster(cfg config.Config, pc profileContext) string {
	p, err := lastClusterPath(cfg, pc)
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if name := strings.TrimSpace(string(data)); eksNameRe.MatchString(name) {
		return name
	}
	return ""
}

func saveLastCluster(cfg config.Config, pc profileContext, name string) {
	p, err := lastClusterPath(cfg, pc)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(p), 0o700) == nil {
		_ = writeFileAtomic(p, []byte(name+"\n"), 0o600)
	}
}
