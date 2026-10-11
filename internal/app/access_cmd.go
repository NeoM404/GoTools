package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// `nedctl access review` compares who holds powerful Kubernetes roles on
// the clusters — every subject bound to cluster-admin, admin or edit, by a
// ClusterRoleBinding or a RoleBinding — with an approved list kept in the
// repository, so unapproved access is found before an auditor finds it and
// approvals nobody uses any more show up too. Read-only.

var accessProbes = []probe{
	{"get", "clusterrolebindings", "-o", `jsonpath={range .items[*]}{.metadata.name}{"\t"}{.roleRef.name}{"\t"}{range .subjects[*]}{.kind}:{.namespace}:{.name}{" "}{end}{"\n"}{end}`},
	{"get", "rolebindings", "-A", "-o", `jsonpath={range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.roleRef.name}{"\t"}{range .subjects[*]}{.kind}:{.namespace}:{.name}{" "}{end}{"\n"}{end}`},
}

// defaultReviewedRoles are the roles whose holders are reviewed.
var defaultReviewedRoles = []string{"cluster-admin", "admin", "edit"}

// accessRule is one approval: subjects (a regular expression over
// "Kind:name", or "ServiceAccount:namespace/name") may hold roles on
// clusters (a regular expression over cluster names).
type accessRule struct {
	Subject  string   `json:"subject"`
	Roles    []string `json:"roles"`
	Clusters string   `json:"clusters,omitempty"`
	Note     string   `json:"note,omitempty"`

	subjectRe, clustersRe *regexp.Regexp
	used                  bool
}

type approvedAccess struct {
	Rules []*accessRule `json:"rules"`
}

func loadApproved(path string) (*approvedAccess, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a approvedAccess
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i, r := range a.Rules {
		if r.subjectRe, err = regexp.Compile("^(?:" + r.Subject + ")$"); err != nil || r.Subject == "" {
			return nil, fmt.Errorf("%s: rule %d: subject %q: %v", path, i+1, r.Subject, err)
		}
		if r.clustersRe, err = regexp.Compile("^(?:" + firstNonBlank(r.Clusters, ".*") + ")$"); err != nil {
			return nil, fmt.Errorf("%s: rule %d: clusters: %w", path, i+1, err)
		}
		if len(r.Roles) == 0 {
			return nil, fmt.Errorf("%s: rule %d: roles is empty (use [\"*\"] for any)", path, i+1)
		}
	}
	return &a, nil
}

// allows reports whether a rule approves subject holding role on cluster.
func (a *approvedAccess) allows(subject, role, cluster string) bool {
	ok := false
	for _, r := range a.Rules {
		if !r.subjectRe.MatchString(subject) || !r.clustersRe.MatchString(cluster) {
			continue
		}
		for _, x := range r.Roles {
			if x == "*" || x == role {
				r.used, ok = true, true
			}
		}
	}
	return ok
}

// accessGrant is one subject holding one reviewed role.
type accessGrant struct {
	Environment string `json:"environment"`
	Cluster     string `json:"cluster"`
	Subject     string `json:"subject"`
	Role        string `json:"role"`
	Scope       string `json:"scope"` // cluster-wide or namespace:<ns>
	Binding     string `json:"binding"`
	Approved    bool   `json:"approved"`
}

// normSubject turns kind:namespace:name into the form rules match.
func normSubject(s, bindingNS string) string {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return s
	}
	if parts[0] == "ServiceAccount" {
		return "ServiceAccount:" + firstNonBlank(parts[1], bindingNS) + "/" + parts[2]
	}
	return parts[0] + ":" + parts[2]
}

// systemSubject is Kubernetes' and the cloud's own machinery.
func systemSubject(s string) bool {
	return strings.HasPrefix(s, "Group:system:") && s != "Group:system:masters" || strings.HasPrefix(s, "User:system:") ||
		strings.HasPrefix(s, "ServiceAccount:kube-system/")
}

func accessGrants(results []clusterOut, roles map[string]bool, includeSystem bool) ([]accessGrant, []string) {
	var grants []accessGrant
	var unreachable []string
	for _, r := range results {
		if err := r.reachErr(); err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s: %v", firstNonBlank(r.Cluster, r.Where), err))
			continue
		}
		add := func(binding, role, scope, bindingNS, subjects string) {
			if !roles[role] && !roles["*"] {
				return
			}
			for _, s := range strings.Fields(subjects) {
				sub := normSubject(s, bindingNS)
				if !includeSystem && systemSubject(sub) {
					continue
				}
				grants = append(grants, accessGrant{Environment: r.Env, Cluster: r.Cluster, Subject: sub, Role: role, Scope: scope, Binding: binding})
			}
		}
		for _, l := range nonEmptyLines(string(r.Outs[0].Out)) {
			if f := strings.SplitN(l, "\t", 3); len(f) == 3 {
				add("ClusterRoleBinding/"+f[0], f[1], "cluster-wide", "", f[2])
			}
		}
		if len(r.Outs) > 1 && r.Outs[1].Err == nil {
			for _, l := range nonEmptyLines(string(r.Outs[1].Out)) {
				if f := strings.SplitN(l, "\t", 4); len(f) == 4 {
					add("RoleBinding/"+f[0]+"/"+f[1], f[2], "namespace:"+f[0], f[0], f[3])
				}
			}
		}
	}
	sort.SliceStable(grants, func(i, j int) bool {
		a, b := grants[i], grants[j]
		return a.Cluster+a.Subject+a.Role+a.Scope < b.Cluster+b.Subject+b.Role+b.Scope
	})
	return grants, unreachable
}

func cmdAccess(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "review" {
		fmt.Fprintln(stderr, "usage: nedctl access review [--cluster C | --env prod | --aws] [--approved FILE]")
		return ExitUsage
	}
	fs := flag.NewFlagSet("access review", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	approvedPath := fs.String("approved", "", "the approved-access file (default: security.approvedAccess, then access/approved.json)")
	rolesFlag := fs.String("roles", strings.Join(defaultReviewedRoles, ","), "roles to review, comma-separated (* for every role)")
	includeSystem := fs.Bool("include-system", false, "also list Kubernetes' own subjects (system:*, kube-system service accounts)")
	output := addOutputFlag(fs)
	if pos, err := parseInterspersed(fs, args[1:]); err != nil || len(pos) > 0 {
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
	path := firstNonBlank(*approvedPath, cfg.Security.ApprovedAccess, "access/approved.json")
	approved, aerr := loadApproved(path)
	if aerr != nil && (*approvedPath != "" || cfg.Security.ApprovedAccess != "" || !os.IsNotExist(aerr)) {
		fmt.Fprintln(stderr, aerr)
		return ExitFailure
	}
	roles := map[string]bool{}
	for _, r := range strings.Split(*rolesFlag, ",") {
		roles[strings.TrimSpace(r)] = true
	}
	results, code := runProbes(ctx, cfg, sel, accessProbes, stderr)
	if code != ExitOK {
		return code
	}
	grants, unreachable := accessGrants(results, roles, *includeSystem)
	unapproved := 0
	for i := range grants {
		if approved != nil && approved.allows(grants[i].Subject, grants[i].Role, grants[i].Cluster) {
			grants[i].Approved = true
		} else if approved != nil {
			unapproved++
		}
	}
	var unused []*accessRule
	if approved != nil && len(unreachable) == 0 {
		for _, r := range approved.Rules {
			if !r.used {
				unused = append(unused, r)
			}
		}
	}
	azure := false
	for _, r := range results {
		azure = azure || r.Cloud == "azure"
	}
	if *output == "json" {
		rep := map[string]any{"generated": now().UTC().Format("2006-01-02T15:04:05Z"), "approvedFile": path, "grants": orEmpty(grants), "unapproved": unapproved}
		if approved == nil {
			rep["approvedFile"] = nil
		}
		if len(unused) > 0 {
			rep["unusedApprovals"] = unused
		}
		if code := writeJSON(stdout, stderr, rep); code != ExitOK {
			return code
		}
	} else {
		printAccess(stdout, grants, approved != nil, path, unused, azure)
	}
	for _, u := range unreachable {
		fmt.Fprintf(stderr, "warning: %s\n", u)
	}
	if unapproved > 0 || len(unreachable) > 0 {
		return ExitFailure
	}
	return ExitOK
}

func orEmpty(g []accessGrant) []accessGrant {
	if g == nil {
		return []accessGrant{}
	}
	return g
}

func printAccess(w io.Writer, grants []accessGrant, haveList bool, path string, unused []*accessRule, azure bool) {
	st := ui.Style{Color: colorOn(w)}
	tw := newTable(w)
	fmt.Fprintln(tw, "CLUSTER\tSUBJECT\tROLE\tSCOPE\tSTATUS")
	bad := 0
	for _, g := range grants {
		status := "-"
		if haveList {
			status = "approved"
			if !g.Approved {
				status, bad = "unapproved", bad+1
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.Cluster, g.Subject, g.Role, g.Scope, status)
	}
	tw.Flush()
	fmt.Fprintln(w)
	switch {
	case !haveList:
		fmt.Fprintf(w, "%s\n", st.Warn(fmt.Sprintf("no approved list (%s) — every grant above needs reviewing; see docs/security-checks.md", path)))
	case bad > 0:
		fmt.Fprintf(w, "%s\n", st.Fail(fmt.Sprintf("%d grant(s) not on the approved list (%s)", bad, path)))
	default:
		fmt.Fprintf(w, "%s\n", st.OK(fmt.Sprintf("every grant is on the approved list (%s)", path)))
	}
	for _, r := range unused {
		fmt.Fprintf(w, "%s\n", st.Info(fmt.Sprintf("approval no longer used: %s → %s on %s — remove it?", r.Subject, strings.Join(r.Roles, ","), firstNonBlank(r.Clusters, ".*"))))
	}
	if azure {
		fmt.Fprintf(w, "%s\n", st.Hint("AKS clusters also admit their shared local account (clusterUser, in system:masters), which no binding shows — see nedctl azure auth"))
	}
	fmt.Fprintf(w, "%s\n", st.Hint("EKS access entries are reviewed with: nedctl eks access <cluster>"))
}
