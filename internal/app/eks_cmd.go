package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
	"nedctl/internal/execx"
)

func cmdEKS(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: nedctl eks <auth|access> ...")
		return ExitUsage
	}
	switch args[0] {
	case "auth":
		return eksAuth(ctx, cfgPath, args[1:], stdout, stderr)
	case "access":
		return eksAccess(ctx, cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown eks subcommand %q\n", args[0])
		return ExitUsage
	}
}

// eksAuthRow is one cluster's authentication posture.
type eksAuthRow struct {
	Cluster     string `json:"cluster"`
	Profile     string `json:"profile"`
	Account     string `json:"account,omitempty"`
	Environment string `json:"environment,omitempty"`
	Region      string `json:"region"`
	Version     string `json:"version"`
	AuthMode    string `json:"authenticationMode"`
	Endpoint    string `json:"endpoint"` // private | public | public+private
	Action      string `json:"action,omitempty"`
}

type eksAuthReport struct {
	Clusters []eksAuthRow `json:"clusters"`
	Errors   []string     `json:"errors"`
	// ConfigMapOnly counts clusters that cannot use access entries yet.
	ConfigMapOnly int `json:"configMapOnly"`
}

func (r eksAuthRow) regionOf() string { return r.Region }

// clusterHit is one EKS cluster in one region.
type clusterHit struct{ Name, Region string }

func (c clusterHit) regionOf() string { return c.Region }

func clustersIn(ctx context.Context, cfg config.Config, profile, region string) ([]clusterHit, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-clusters", "--profile", profile, "--region", region, "--output", "json")
	if err != nil {
		return nil, err
	}
	var list struct{ Clusters []string }
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parsing eks list-clusters: %w", err)
	}
	hits := make([]clusterHit, 0, len(list.Clusters))
	for _, n := range list.Clusters {
		if !eksNameRe.MatchString(n) {
			return nil, fmt.Errorf("eks returned an invalid cluster name %q", n)
		}
		hits = append(hits, clusterHit{Name: n, Region: region})
	}
	return hits, nil
}

// findCluster returns the region a cluster lives in, searching like every
// other command. A name found in two regions must be disambiguated.
func findCluster(ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, name string, stderr io.Writer) (string, error) {
	all, searched, err := searchRegions(ctx, cfg, pc, rs, "eks", stderr, func(region string) ([]clusterHit, error) {
		return clustersIn(ctx, cfg, pc.Name, region)
	})
	if err != nil {
		return "", err
	}
	var regions []string
	for _, h := range all {
		if h.Name == name {
			regions = append(regions, h.Region)
		}
	}
	switch len(regions) {
	case 0:
		return "", fmt.Errorf("no cluster %q in %s (searched %s) — check the account, or try --all-regions", name, pc.label(), strings.Join(searched, ", "))
	case 1:
		return regions[0], nil
	}
	return "", fmt.Errorf("cluster %q exists in %s — pass --region", name, strings.Join(regions, " and "))
}

// authAction is the recommended next step for a mode.
func authAction(mode string) string {
	switch mode {
	case "CONFIG_MAP":
		return "move to API_AND_CONFIG_MAP (aws-auth keeps working; one-way)"
	case "API_AND_CONFIG_MAP":
		return "mirror aws-auth into access entries, then consider API"
	}
	return ""
}

func eksAuth(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eks auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var profiles multiFlag
	fs.Var(&profiles, "profile", "profile to report on (repeatable; default: the current profile)")
	allProfiles := fs.Bool("all-profiles", false, "every profile `nedctl aws login` has written")
	failOnConfigMap := fs.Bool("fail-on-configmap", false, "exit 1 if any cluster still uses CONFIG_MAP only")
	var rs regionSearch
	addRegionFlags(fs, &rs)
	output := addOutputFlag(fs)
	if err := fs.Parse(args); err != nil {
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
	meta := map[string]awssso.Profile{}
	if path, err := awssso.ConfigPath(); err == nil {
		if m, err := awssso.LoadManaged(path); err == nil {
			meta = m.Profiles
			if len(m.Profiles) > 0 {
				warnSignIn(m.Session.Name, stderr)
			}
		}
	}
	if *allProfiles {
		for name := range meta {
			profiles = append(profiles, name)
		}
		sort.Strings(profiles)
	}
	if len(profiles) == 0 {
		if p := resolveProfile(cfg, ""); p != "" {
			profiles = append(profiles, p)
		}
	}
	if len(profiles) == 0 {
		fmt.Fprintln(stderr, "no profile selected — run `nedctl aws login`, or pass --profile / --all-profiles")
		return ExitFailure
	}

	rep := eksAuthReport{Clusters: []eksAuthRow{}, Errors: []string{}}
	searchedAll := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, p := range profiles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pc := profileContext{Name: p, AccountID: meta[p].AccountID, Squad: meta[p].Squad, Environment: meta[p].Environment}
			rows, searched, err := searchRegions(ctx, cfg, pc, rs, "eks", stderr, func(region string) ([]eksAuthRow, error) {
				return authRows(ctx, cfg, p, region)
			})
			mu.Lock()
			for _, r := range searched {
				searchedAll[r] = true
			}
			defer mu.Unlock()
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", p, err))
				return
			}
			for i := range rows {
				rows[i].Account, rows[i].Environment = meta[p].AccountID, meta[p].Environment
			}
			rep.Clusters = append(rep.Clusters, rows...)
		}()
	}
	wg.Wait()
	sort.Slice(rep.Clusters, func(i, j int) bool {
		a, b := rep.Clusters[i], rep.Clusters[j]
		if a.AuthMode != b.AuthMode {
			return a.AuthMode == "CONFIG_MAP"
		}
		return a.Profile+a.Cluster < b.Profile+b.Cluster
	})
	sort.Strings(rep.Errors)
	for _, r := range rep.Clusters {
		if r.AuthMode == "CONFIG_MAP" {
			rep.ConfigMapOnly++
		}
	}
	code := ExitOK
	if len(rep.Errors) > 0 || (*failOnConfigMap && rep.ConfigMapOnly > 0) {
		code = ExitFailure
	}
	if *output == "json" {
		if rc := writeJSON(stdout, stderr, rep); rc != ExitOK {
			return rc
		}
		return code
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLUSTER\tENV\tACCOUNT\tREGION\tAUTH MODE\tENDPOINT\tVERSION\tNEXT STEP")
	for _, r := range rep.Clusters {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Cluster, dash(r.Environment), dash(r.Account), r.Region, r.AuthMode, r.Endpoint, r.Version, dash(r.Action))
	}
	tw.Flush()
	regions := make([]string, 0, len(searchedAll))
	for r := range searchedAll {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	fmt.Fprintf(stdout, "\n%d cluster(s) · %d on CONFIG_MAP only (no access entries possible yet) · searched %s\n",
		len(rep.Clusters), rep.ConfigMapOnly, dash(strings.Join(regions, ", ")))
	for _, e := range rep.Errors {
		fmt.Fprintf(stderr, "could not read: %s\n", e)
	}
	return code
}

// authRows describes every EKS cluster the profile can see in one region.
func authRows(ctx context.Context, cfg config.Config, profile, region string) ([]eksAuthRow, error) {
	hits, err := clustersIn(ctx, cfg, profile, region)
	if err != nil {
		return nil, err
	}
	var rows []eksAuthRow
	for _, h := range hits {
		name := h.Name
		out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-cluster", "--name", name, "--profile", profile, "--region", region, "--output", "json")
		if err != nil {
			return nil, err
		}
		var d struct {
			Cluster struct {
				Arn, Version       string
				AccessConfig       struct{ AuthenticationMode string } `json:"accessConfig"`
				ResourcesVpcConfig struct {
					EndpointPublicAccess  bool `json:"endpointPublicAccess"`
					EndpointPrivateAccess bool `json:"endpointPrivateAccess"`
				} `json:"resourcesVpcConfig"`
			} `json:"cluster"`
		}
		if err := json.Unmarshal(out, &d); err != nil {
			return nil, fmt.Errorf("parsing eks describe-cluster %s: %w", name, err)
		}
		mode := d.Cluster.AccessConfig.AuthenticationMode
		if mode == "" {
			mode = "CONFIG_MAP" // clusters created before access entries report none
		}
		var ep []string
		if d.Cluster.ResourcesVpcConfig.EndpointPublicAccess {
			ep = append(ep, "public")
		}
		if d.Cluster.ResourcesVpcConfig.EndpointPrivateAccess {
			ep = append(ep, "private")
		}
		rows = append(rows, eksAuthRow{Cluster: name, Profile: profile, Region: region, Version: d.Cluster.Version,
			AuthMode: mode, Endpoint: strings.Join(ep, "+"), Action: authAction(mode)})
	}
	return rows, nil
}

// accessEntry is one principal's access to a cluster.
type accessEntry struct {
	Principal string   `json:"principal"`
	Type      string   `json:"type,omitempty"`
	Username  string   `json:"username,omitempty"`
	Groups    []string `json:"kubernetesGroups,omitempty"`
	Policies  []string `json:"policies"`
}

func eksAccess(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("eks access", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to act with")
	var rs regionSearch
	addRegionFlags(fs, &rs)
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || !eksNameRe.MatchString(pos[0]) {
		fmt.Fprintln(stderr, "usage: nedctl eks access <cluster> [--profile P] [-o table|json]")
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
	pc, ok := loadProfileContext(cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	profile, name := pc.Name, pos[0]
	region, err := findCluster(ctx, cfg, pc, rs, name, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-access-entries", "--cluster-name", name, "--profile", profile, "--region", region, "--output", "json")
	if err != nil {
		fmt.Fprintf(stderr, "listing access entries for %s: %v\n→ a cluster on CONFIG_MAP has none: see `nedctl eks auth`\n", name, err)
		return ExitFailure
	}
	var list struct {
		AccessEntries []string `json:"accessEntries"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		fmt.Fprintf(stderr, "parsing eks list-access-entries: %v\n", err)
		return ExitFailure
	}
	entries := []accessEntry{}
	for _, arn := range list.AccessEntries {
		e := accessEntry{Principal: arn, Policies: []string{}}
		if out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-access-entry", "--cluster-name", name, "--principal-arn", arn, "--profile", profile, "--region", region, "--output", "json"); err == nil {
			var d struct {
				AccessEntry struct {
					Type, Username   string
					KubernetesGroups []string `json:"kubernetesGroups"`
				} `json:"accessEntry"`
			}
			if json.Unmarshal(out, &d) == nil {
				e.Type, e.Username, e.Groups = d.AccessEntry.Type, d.AccessEntry.Username, d.AccessEntry.KubernetesGroups
			}
		}
		out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-associated-access-policies", "--cluster-name", name, "--principal-arn", arn, "--profile", profile, "--region", region, "--output", "json")
		if err != nil {
			fmt.Fprintf(stderr, "listing policies for %s: %v\n", arn, err)
			return ExitFailure
		}
		var pol struct {
			AssociatedAccessPolicies []struct {
				PolicyArn   string `json:"policyArn"`
				AccessScope struct {
					Type       string   `json:"type"`
					Namespaces []string `json:"namespaces"`
				} `json:"accessScope"`
			} `json:"associatedAccessPolicies"`
		}
		if err := json.Unmarshal(out, &pol); err != nil {
			fmt.Fprintf(stderr, "parsing eks list-associated-access-policies: %v\n", err)
			return ExitFailure
		}
		for _, p := range pol.AssociatedAccessPolicies {
			short := p.PolicyArn[strings.LastIndex(p.PolicyArn, "/")+1:]
			scope := p.AccessScope.Type
			if len(p.AccessScope.Namespaces) > 0 {
				scope += ":" + strings.Join(p.AccessScope.Namespaces, ",")
			}
			e.Policies = append(e.Policies, short+" ("+scope+")")
		}
		entries = append(entries, e)
	}
	if *output == "json" {
		return writeJSON(stdout, stderr, entries)
	}
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PRINCIPAL\tTYPE\tPOLICIES\tGROUPS")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Principal, dash(e.Type), dash(strings.Join(e.Policies, "; ")), dash(strings.Join(e.Groups, ",")))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d principal(s) can reach %s through access entries (aws-auth mappings, if any, are not shown)\n", len(entries), name)
	return ExitOK
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
