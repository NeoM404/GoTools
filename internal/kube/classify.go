package kube

import (
	"regexp"
	"strings"

	"github.com/NeoM404/GoTools/internal/inventory"
)

// eksARN matches the context name `aws eks update-kubeconfig` writes by default.
var eksARN = regexp.MustCompile(`^arn:aws[a-z-]*:eks:([a-z0-9-]+):(\d{12}):cluster/(.+)$`)

// accountAlias matches the `<account>.<name>` alias `bankctl kubeconfig` writes.
var accountAlias = regexp.MustCompile(`^(\d{12})\.(.+)$`)

// Resolve maps a kube-context name to the inventory cluster it points at,
// recognising the names the cloud CLIs and bankctl write:
//
//	arn:aws:eks:<region>:<account>:cluster/<name>   aws eks update-kubeconfig
//	<account>.<name>                                bankctl kubeconfig (alias)
//	<name>, <name>-admin                            az aks get-credentials [--admin]
//
// Identity-bearing forms (ARN, alias) must match the account too, so a context
// for a same-named cluster in another account never resolves to this one.
func Resolve(context string, fleet inventory.Fleet) (inventory.Cluster, bool) {
	if m := eksARN.FindStringSubmatch(context); m != nil {
		return find(fleet, func(c inventory.Cluster) bool {
			return c.Cloud == inventory.AWS && c.Region == m[1] && c.Account == m[2] && strings.EqualFold(c.Name, m[3])
		})
	}
	if m := accountAlias.FindStringSubmatch(context); m != nil {
		return find(fleet, func(c inventory.Cluster) bool {
			return c.Cloud == inventory.AWS && c.Account == m[1] && strings.EqualFold(c.Name, m[2])
		})
	}
	if c, ok := find(fleet, func(c inventory.Cluster) bool { return strings.EqualFold(c.Name, context) }); ok {
		return c, true
	}
	if name, ok := strings.CutSuffix(context, "-admin"); ok {
		return find(fleet, func(c inventory.Cluster) bool { return c.Cloud == inventory.Azure && strings.EqualFold(c.Name, name) })
	}
	return inventory.Cluster{}, false
}

func find(f inventory.Fleet, match func(inventory.Cluster) bool) (inventory.Cluster, bool) {
	for _, c := range f.Clusters {
		if match(c) {
			return c, true
		}
	}
	return inventory.Cluster{}, false
}

// Classification explains whether a context is production, and why.
type Classification struct {
	Production  bool     `json:"production"`
	Cluster     string   `json:"cluster,omitempty"`     // resolved inventory cluster
	Environment string   `json:"environment,omitempty"` // its inventory environment
	Reasons     []string `json:"reasons"`
}

// Classify decides whether context is production. It is production if EITHER
// the inventory resolves it to a cluster in a prod environment OR its name
// matches a prod pattern. Using both means adding the inventory can only make
// detection stricter: a prod cluster whose name lacks "prod" is caught, and
// the name patterns still over-warn as before. fleet may be nil (inventory
// unavailable), leaving the patterns alone.
func Classify(context string, fleet *inventory.Fleet, prodEnvs, patterns []string) Classification {
	cl := Classification{Reasons: []string{}}
	if fleet != nil {
		if c, ok := Resolve(context, *fleet); ok {
			cl.Cluster, cl.Environment = c.Name, c.Environment
			if isProdEnv(c.Environment, prodEnvs) {
				cl.Production = true
				cl.Reasons = append(cl.Reasons, "inventory: "+c.Name+" is in environment "+c.Environment)
			}
		}
	}
	if p, ok := matchingPattern(context, patterns); ok {
		cl.Production = true
		cl.Reasons = append(cl.Reasons, "name matches prod pattern "+p)
	}
	return cl
}

func isProdEnv(env string, prodEnvs []string) bool {
	for _, p := range prodEnvs {
		if strings.EqualFold(strings.TrimSpace(env), p) {
			return true
		}
	}
	return false
}

func matchingPattern(name string, patterns []string) (string, bool) {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue // a bad pattern must never make prod look safe, nor crash
		}
		if re.MatchString(name) {
			return p, true
		}
	}
	return "", false
}
