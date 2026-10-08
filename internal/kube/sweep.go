package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"nedctl/internal/execx"
	"nedctl/internal/inventory"
)

// Kubeconfig is the subset of `kubectl config view -o json` the sweeper
// needs. It is read through kubectl (not parsed from YAML), keeping nedctl
// dependency-free and always consistent with what kubectl sees; secrets are
// redacted in that view, and none are needed.
type Kubeconfig struct {
	CurrentContext string `json:"current-context"`
	Contexts       []struct {
		Name    string `json:"name"`
		Context struct {
			Cluster string `json:"cluster"`
			User    string `json:"user"`
		} `json:"context"`
	} `json:"contexts"`
	Clusters []struct {
		Name    string `json:"name"`
		Cluster struct {
			Server string `json:"server"`
		} `json:"cluster"`
	} `json:"clusters"`
	Users []struct {
		Name string `json:"name"`
		User struct {
			Exec *struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"exec"`
		} `json:"user"`
	} `json:"users"`
}

// ParseKubeconfig decodes `kubectl config view -o json` output.
func ParseKubeconfig(data []byte) (Kubeconfig, error) {
	var k Kubeconfig
	if err := json.Unmarshal(data, &k); err != nil {
		return Kubeconfig{}, fmt.Errorf("parsing kubeconfig view: %w", err)
	}
	return k, nil
}

// Verdict is what the sweeper decides for one context.
type Verdict string

const (
	// Keep: the context resolves to an inventory cluster.
	Keep Verdict = "keep"
	// Stale: a managed (EKS/AKS) context the inventory proves is gone.
	Stale Verdict = "stale"
	// StaleCurrent: stale, but it is the current context, so it is left
	// alone unless explicitly included.
	StaleCurrent Verdict = "stale-current"
	// Unverifiable: managed, but the inventory does not cover its cloud or
	// account, so absence proves nothing. Kept.
	Unverifiable Verdict = "unverifiable"
	// Unmanaged: not an EKS/AKS context (kind, minikube, on-prem...). Never
	// touched.
	Unmanaged Verdict = "unmanaged"
)

// Removes reports whether the verdict leads to deletion.
func (v Verdict) Removes() bool { return v == Stale }

// ContextPlan is the decision for one context.
type ContextPlan struct {
	Context    string          `json:"context"`
	Cloud      inventory.Cloud `json:"cloud,omitempty"`
	Verdict    Verdict         `json:"verdict"`
	ResolvedTo string          `json:"resolvedTo,omitempty"`
	Reason     string          `json:"reason"`
	// Entries removed along with the context: only when no remaining
	// context still references them.
	DeleteCluster string `json:"deleteCluster,omitempty"`
	DeleteUser    string `json:"deleteUser,omitempty"`
}

// PlanSweep decides, for every context, whether it can be proven stale.
// The rule is conservative: a context is only removed if it is an EKS/AKS
// context, the inventory covers its cloud (and its AWS account, when the
// kubeconfig reveals it), and nothing in the inventory matches it by any of
// the identities the kubeconfig carries.
func PlanSweep(k Kubeconfig, fleet inventory.Fleet, includeCurrent bool) []ContextPlan {
	covered := coverage(fleet)
	refs := k.refs()

	plans := make([]ContextPlan, 0, len(k.Contexts))
	for i, c := range k.Contexts {
		ref := refs[i]
		p := ContextPlan{Context: c.Name, Cloud: ref.cloud()}
		switch {
		case p.Cloud == "":
			p.Verdict, p.Reason = Unmanaged, "not an EKS/AKS context — never touched"
		default:
			if hit, ok := ref.resolve(fleet); ok {
				p.Verdict, p.ResolvedTo, p.Reason = Keep, hit.Name, "in the inventory"
			} else if why, ok := covered.vouches(ref, p.Cloud); !ok {
				p.Verdict, p.Reason = Unverifiable, why+" — kept"
			} else if c.Name == k.CurrentContext && !includeCurrent {
				p.Verdict, p.Reason = StaleCurrent, "not in the inventory, but it is the current context — switch first or pass --include-current"
			} else {
				p.Verdict, p.Reason = Stale, "not in the inventory"
			}
		}
		plans = append(plans, p)
	}
	markOrphans(plans, k)
	return plans
}

// markOrphans sets DeleteCluster/DeleteUser on removed contexts whose entries
// no surviving context references.
func markOrphans(plans []ContextPlan, k Kubeconfig) {
	keptCluster, keptUser := map[string]bool{}, map[string]bool{}
	for i, c := range k.Contexts {
		if !plans[i].Verdict.Removes() {
			keptCluster[c.Context.Cluster] = true
			keptUser[c.Context.User] = true
		}
	}
	doneCluster, doneUser := map[string]bool{}, map[string]bool{}
	for i, c := range k.Contexts {
		if !plans[i].Verdict.Removes() {
			continue
		}
		if cl := c.Context.Cluster; cl != "" && !keptCluster[cl] && !doneCluster[cl] {
			plans[i].DeleteCluster, doneCluster[cl] = cl, true
		}
		if u := c.Context.User; u != "" && !keptUser[u] && !doneUser[u] {
			plans[i].DeleteUser, doneUser[u] = u, true
		}
	}
}

type contextRef struct {
	name, cluster, user, server string
	exec                        []string
}

// refs returns a contextRef for every context, in kubeconfig order.
func (k Kubeconfig) refs() []contextRef {
	servers := map[string]string{}
	for _, c := range k.Clusters {
		servers[c.Name] = c.Cluster.Server
	}
	execs := map[string][]string{}
	for _, u := range k.Users {
		if u.User.Exec != nil {
			execs[u.Name] = append([]string{u.User.Exec.Command}, u.User.Exec.Args...)
		}
	}
	out := make([]contextRef, len(k.Contexts))
	for i, c := range k.Contexts {
		out[i] = contextRef{name: c.Name, cluster: c.Context.Cluster, user: c.Context.User,
			server: servers[c.Context.Cluster], exec: execs[c.Context.User]}
	}
	return out
}

// ref returns the context named name; a name with no entry (a dangling
// current-context) still yields a ref carrying the name alone.
func (k Kubeconfig) ref(name string) contextRef {
	for i, r := range k.refs() {
		if k.Contexts[i].Name == name {
			return r
		}
	}
	return contextRef{name: name}
}

func (r contextRef) host() string {
	u, err := url.Parse(r.server)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func (r contextRef) execIs(bin string) bool {
	return len(r.exec) > 0 && strings.EqualFold(filepath.Base(r.exec[0]), bin)
}

func (r contextRef) execHas(words ...string) bool {
	joined := " " + strings.Join(r.exec, " ") + " "
	for _, w := range words {
		if !strings.Contains(joined, " "+w+" ") {
			return false
		}
	}
	return true
}

func (r contextRef) execFlag(flag string) string {
	for i, a := range r.exec {
		if a == flag && i+1 < len(r.exec) {
			return r.exec[i+1]
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v
		}
	}
	return ""
}

// cloud identifies EKS/AKS contexts by API host, exec plugin, or the names
// the cloud CLIs write; anything else is unmanaged.
func (r contextRef) cloud() inventory.Cloud {
	h := r.host()
	switch {
	case strings.HasSuffix(h, ".eks.amazonaws.com") || strings.HasSuffix(h, ".eks.amazonaws.com.cn"),
		eksARN.MatchString(r.name) || eksARN.MatchString(r.cluster) || eksARN.MatchString(r.user),
		r.execIs("aws") && r.execHas("eks", "get-token"),
		r.execIs("aws-iam-authenticator"):
		return inventory.AWS
	case strings.HasSuffix(h, ".azmk8s.io"),
		r.execIs("kubelogin"),
		hasFold(r.user, "clusterUser_") || hasFold(r.user, "clusterAdmin_"):
		return inventory.Azure
	}
	return ""
}

func hasFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// account returns the AWS account the kubeconfig reveals, if any.
func (r contextRef) account() string {
	for _, s := range []string{r.name, r.cluster, r.user} {
		if m := eksARN.FindStringSubmatch(s); m != nil {
			return m[2]
		}
	}
	if m := accountAlias.FindStringSubmatch(r.name); m != nil {
		return m[1]
	}
	return ""
}

// resolve tries every identity the kubeconfig carries.
func (r contextRef) resolve(fleet inventory.Fleet) (inventory.Cluster, bool) {
	for _, s := range []string{r.name, r.cluster, r.user} {
		if s == "" {
			continue
		}
		if c, ok := Resolve(s, fleet); ok {
			return c, true
		}
	}
	// EKS exec plugin: `aws eks get-token --cluster-name N --region R`.
	if name, region := r.execFlag("--cluster-name"), r.execFlag("--region"); name != "" {
		acct := r.account()
		if c, ok := find(fleet, func(c inventory.Cluster) bool {
			return c.Cloud == inventory.AWS && strings.EqualFold(c.Name, name) &&
				(region == "" || c.Region == region) && (acct == "" || c.Account == acct)
		}); ok {
			return c, true
		}
	}
	// az aks get-credentials writes users named clusterUser_<rg>_<name>.
	return find(fleet, func(c inventory.Cluster) bool {
		if c.Cloud != inventory.Azure {
			return false
		}
		suffix := "_" + c.ResourceGroup + "_" + c.Name
		return strings.EqualFold(r.user, "clusterUser"+suffix) || strings.EqualFold(r.user, "clusterAdmin"+suffix)
	})
}

type inventoryCoverage struct {
	clouds   map[inventory.Cloud]bool
	accounts map[string]bool
}

func coverage(f inventory.Fleet) inventoryCoverage {
	cv := inventoryCoverage{clouds: map[inventory.Cloud]bool{}, accounts: map[string]bool{}}
	for _, c := range f.Clusters {
		cv.clouds[c.Cloud] = true
		if c.Account != "" {
			cv.accounts[c.Account] = true
		}
	}
	return cv
}

// vouches reports whether the inventory is in a position to say this context
// is gone, and if not, why.
func (cv inventoryCoverage) vouches(r contextRef, cloud inventory.Cloud) (string, bool) {
	if !cv.clouds[cloud] {
		return fmt.Sprintf("the inventory lists no %s clusters, so it cannot vouch for this context", cloud), false
	}
	if cloud == inventory.AWS {
		if acct := r.account(); acct != "" && !cv.accounts[acct] {
			return "AWS account " + acct + " is not covered by the inventory", false
		}
	}
	return "", true
}

// SortPlans orders plans for display: removals first, then by name.
func SortPlans(p []ContextPlan) {
	rank := map[Verdict]int{Stale: 0, StaleCurrent: 1, Unverifiable: 2, Keep: 3, Unmanaged: 4}
	sort.SliceStable(p, func(i, j int) bool {
		if rank[p[i].Verdict] != rank[p[j].Verdict] {
			return rank[p[i].Verdict] < rank[p[j].Verdict]
		}
		return p[i].Context < p[j].Context
	})
}

// ViewKubeconfig reads one kubeconfig file through kubectl.
func ViewKubeconfig(ctx context.Context, path string) (Kubeconfig, error) {
	out, err := execx.Output(ctx, localTimeout, "kubectl", "config", "view", "--output", "json", "--kubeconfig", path)
	if err != nil {
		return Kubeconfig{}, err
	}
	return ParseKubeconfig(out)
}

// DeleteEntry removes one context, cluster or user from a kubeconfig file.
func DeleteEntry(ctx context.Context, path, kind, name string) error {
	switch kind {
	case "context", "cluster", "user":
	default:
		return fmt.Errorf("unknown kubeconfig entry kind %q", kind)
	}
	_, err := execx.Output(ctx, localTimeout, "kubectl", "config", "delete-"+kind, name, "--kubeconfig", path)
	return err
}

// UnsetCurrentContext clears current-context in a kubeconfig file.
func UnsetCurrentContext(ctx context.Context, path string) error {
	_, err := execx.Output(ctx, localTimeout, "kubectl", "config", "unset", "current-context", "--kubeconfig", path)
	return err
}
