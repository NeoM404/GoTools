package kube

import (
	"context"
	"errors"

	"github.com/NeoM404/GoTools/internal/execx"
	"github.com/NeoM404/GoTools/internal/inventory"
)

// ErrNoCurrentContext reports a kubeconfig with no current-context.
var ErrNoCurrentContext = errors.New("current-context is not set in the kubeconfig")

// ViewCurrent reads the merged kubeconfig kubectl uses ($KUBECONFIG or
// ~/.kube/config) and requires a current context. Secrets are redacted in
// this view; none are needed.
func ViewCurrent(ctx context.Context) (Kubeconfig, error) {
	k, err := View(ctx)
	if err != nil {
		return Kubeconfig{}, err
	}
	if k.CurrentContext == "" {
		return Kubeconfig{}, ErrNoCurrentContext
	}
	return k, nil
}

// View reads the merged kubeconfig kubectl uses.
func View(ctx context.Context) (Kubeconfig, error) {
	out, err := execx.Output(ctx, localTimeout, "kubectl", "config", "view", "--output", "json")
	if err != nil {
		return Kubeconfig{}, err
	}
	return ParseKubeconfig(out)
}

// HostContext is a kube-context already present on the host.
type HostContext struct {
	Name string `json:"name"`
	// User is the kubeconfig user entry the context authenticates as, e.g.
	// clusterUser_<rg>_<cluster> as written by az aks get-credentials.
	User string `json:"user"`
	// Exec is true when the user authenticates through an exec plugin
	// (kubelogin, aws eks get-token) rather than a static certificate/token.
	Exec bool `json:"exec"`
}

// ContextsFor returns every context in k that resolves to cluster c, by any
// identity the kubeconfig carries. On a bastion this is how a cluster from
// the inventory is mapped to the credentials the platform provisioned.
// Contexts are resolved against the whole fleet, so one that better matches
// another cluster is never handed out as c.
func ContextsFor(k Kubeconfig, fleet inventory.Fleet, c inventory.Cluster) []HostContext {
	var out []HostContext
	for _, r := range k.refs() {
		if hit, ok := r.resolve(fleet); ok && hit == c {
			out = append(out, HostContext{Name: r.name, User: r.user, Exec: len(r.exec) > 0})
		}
	}
	return out
}

// UseContext makes name the current context.
func UseContext(ctx context.Context, name string) error {
	_, err := execx.Output(ctx, localTimeout, "kubectl", "config", "use-context", name)
	return err
}

// SharedLocalAccount reports whether h authenticates as an AKS local
// account: the clusterAdmin_<rg>_<name> certificate, or clusterUser_<rg>_<name>
// with a static certificate/token instead of kubelogin (a cluster without
// Entra ID integration). Everyone holding that kubeconfig is the same
// identity to the API server.
func (h HostContext) SharedLocalAccount() bool {
	return hasFold(h.User, "clusterAdmin_") || (hasFold(h.User, "clusterUser_") && !h.Exec)
}
