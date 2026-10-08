// Package cloud wraps the AWS and Azure CLIs to fetch cluster credentials.
// It never handles long-lived secrets itself: it delegates to `aws eks
// update-kubeconfig` and `az aks get-credentials`, which use the operator's
// already-established SSO/federated session. nedctl only orchestrates them.
package cloud

import (
	"context"
	"fmt"
	"io"
	"time"

	"nedctl/internal/execx"
	"nedctl/internal/inventory"
)

// KubeconfigOptions controls where credentials are written.
type KubeconfigOptions struct {
	// File, if set, is passed as --kubeconfig so the merge is isolated from
	// the operator's main ~/.kube/config (safer when juggling many clusters).
	File string
	// DryRun prints the command instead of executing it.
	DryRun bool
	// Stdout/Stderr for command output; defaults to os.Stdout/os.Stderr.
	Stdout io.Writer
	Stderr io.Writer
	// Timeout bounds the cloud CLI call (required; see config.CommandTimeout).
	Timeout time.Duration
}

// UpdateKubeconfig fetches credentials for the cluster using the appropriate
// cloud CLI. It returns the command that was (or would be) run.
func UpdateKubeconfig(ctx context.Context, c inventory.Cluster, opt KubeconfigOptions) ([]string, error) {
	var args []string
	switch c.Cloud {
	case inventory.AWS:
		if c.Region == "" {
			return nil, fmt.Errorf("cluster %q has no region", c.Name)
		}
		args = []string{"aws", "eks", "update-kubeconfig", "--name", c.Name, "--region", c.Region}
		if c.Account != "" {
			args = append(args, "--alias", fmt.Sprintf("%s.%s", c.Account, c.Name))
		}
		if opt.File != "" {
			args = append(args, "--kubeconfig", opt.File)
		}
	case inventory.Azure:
		if c.ResourceGroup == "" {
			return nil, fmt.Errorf("cluster %q has no resourceGroup", c.Name)
		}
		args = []string{"az", "aks", "get-credentials", "--name", c.Name, "--resource-group", c.ResourceGroup, "--only-show-errors"}
		if c.Subscription != "" {
			args = append(args, "--subscription", c.Subscription)
		}
		if opt.File != "" {
			args = append(args, "--file", opt.File)
		}
	default:
		return nil, fmt.Errorf("unsupported cloud %q for cluster %q", c.Cloud, c.Name)
	}

	if opt.DryRun {
		return args, nil
	}
	return args, execx.Run(ctx, execx.Spec{
		Name: args[0], Args: args[1:],
		Stdout: opt.Stdout, Stderr: opt.Stderr, Timeout: opt.Timeout,
	})
}
