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

	"github.com/NeoM404/GoTools/internal/awssso"
	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/execx"
)

func cmdEKS(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: bankctl eks <auth|access> ...")
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
	allProfiles := fs.Bool("all-profiles", false, "every profile `bankctl aws login` has written")
	failOnConfigMap := fs.Bool("fail-on-configmap", false, "exit 1 if any cluster still uses CONFIG_MAP only")
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
		fmt.Fprintln(stderr, "no profile selected — run `bankctl aws login`, or pass --profile / --all-profiles")
		return ExitFailure
	}

	rep := eksAuthReport{Clusters: []eksAuthRow{}, Errors: []string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, p := range profiles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows, err := authRows(ctx, cfg, p)
			mu.Lock()
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
	fmt.Fprintln(tw, "CLUSTER\tENV\tACCOUNT\tAUTH MODE\tENDPOINT\tVERSION\tNEXT STEP")
	for _, r := range rep.Clusters {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Cluster, dash(r.Environment), dash(r.Account), r.AuthMode, r.Endpoint, r.Version, dash(r.Action))
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\n%d cluster(s) · %d on CONFIG_MAP only (no access entries possible yet)\n", len(rep.Clusters), rep.ConfigMapOnly)
	for _, e := range rep.Errors {
		fmt.Fprintf(stderr, "could not read: %s\n", e)
	}
	return code
}

// authRows describes every EKS cluster the profile can see.
func authRows(ctx context.Context, cfg config.Config, profile string) ([]eksAuthRow, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-clusters", "--profile", profile, "--output", "json")
	if err != nil {
		return nil, err
	}
	var list struct{ Clusters []string }
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parsing eks list-clusters: %w", err)
	}
	var rows []eksAuthRow
	for _, name := range list.Clusters {
		if !eksNameRe.MatchString(name) {
			return nil, fmt.Errorf("eks returned an invalid cluster name %q", name)
		}
		out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-cluster", "--name", name, "--profile", profile, "--output", "json")
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
		region := ""
		if m := eksARN.FindStringSubmatch(d.Cluster.Arn); m != nil {
			region = m[1]
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
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || !eksNameRe.MatchString(pos[0]) {
		fmt.Fprintln(stderr, "usage: bankctl eks access <cluster> [--profile P] [-o table|json]")
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
	profile := resolveProfile(cfg, *profileFlag)
	if profile == "" {
		fmt.Fprintln(stderr, "no profile selected — run `bankctl aws login`, or pass --profile")
		return ExitFailure
	}
	name := pos[0]
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-access-entries", "--cluster-name", name, "--profile", profile, "--output", "json")
	if err != nil {
		fmt.Fprintf(stderr, "listing access entries for %s: %v\n→ a cluster on CONFIG_MAP has none: see `bankctl eks auth`\n", name, err)
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
		if out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-access-entry", "--cluster-name", name, "--principal-arn", arn, "--profile", profile, "--output", "json"); err == nil {
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
		out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "list-associated-access-policies", "--cluster-name", name, "--principal-arn", arn, "--profile", profile, "--output", "json")
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
