// Package cloud wraps the AWS and Azure CLIs to fetch cluster credentials.
// It never handles long-lived secrets itself: it delegates to `aws eks
// update-kubeconfig` and `az aks get-credentials`, which use the operator's
// already-established SSO/federated session. bankctl only orchestrates them.
package cloud

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/NeoM404/GoTools/internal/inventory"
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
}

// UpdateKubeconfig fetches credentials for the cluster using the appropriate
// cloud CLI. It returns the command that was (or would be) run.
func UpdateKubeconfig(c inventory.Cluster, opt KubeconfigOptions) ([]string, error) {
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
	return args, run(args, opt)
}

func run(args []string, opt KubeconfigOptions) error {
	if _, err := exec.LookPath(args[0]); err != nil {
		return fmt.Errorf("required CLI %q not found in PATH — see `bankctl doctor`", args[0])
	}
	stdout := opt.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := opt.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	cmd := exec.Command(args[0], args[1:]...) //nolint:gosec // args built from typed inventory, not free-form user input
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
