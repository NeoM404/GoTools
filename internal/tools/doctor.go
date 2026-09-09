// Package tools implements `bankctl doctor`: it checks that the ecosystem
// CLIs bankctl orchestrates (and the ones the team standardises on) are
// installed. bankctl deliberately does NOT reimplement these — see
// docs/ecosystem-tools.md.
package tools

import (
	"os/exec"
)

// Tool describes an external CLI the team relies on.
type Tool struct {
	Name     string // binary name in PATH
	Purpose  string
	Required bool // required for bankctl's own subcommands to work
	Install  string
}

// Catalog is the set of tools doctor checks for.
func Catalog() []Tool {
	return []Tool{
		{"kubectl", "Kubernetes CLI (bankctl guard/current shell out to it)", true, "brew install kubectl"},
		{"aws", "AWS CLI — EKS kubeconfig + SSO login", true, "brew install awscli"},
		{"az", "Azure CLI — AKS kubeconfig + login", true, "brew install azure-cli"},
		{"helm", "Kubernetes package manager", false, "brew install helm"},
		{"kubectx", "Fast context switching", false, "brew install kubectx"},
		{"kubens", "Fast namespace switching", false, "brew install kubectx"},
		{"kubie", "Isolated per-shell contexts (safer at fleet scale)", false, "brew install kubie"},
		{"k9s", "Terminal UI for clusters", false, "brew install k9s"},
		{"stern", "Multi-pod log tailing", false, "brew install stern"},
		{"argocd", "Argo CD CLI (GitOps fleet)", false, "brew install argocd"},
		{"kubent", "Deprecated-API scanner (pre-upgrade)", false, "sh -c 'curl -sSfL https://git.io/install-kubent | sh'"},
		{"trivy", "Image/IaC/secret scanner", false, "brew install trivy"},
	}
}

// Result is the outcome of checking one tool.
type Result struct {
	Tool
	Found bool
	Path  string
}

// Check resolves each tool in the catalog against the current PATH.
func Check() []Result {
	cat := Catalog()
	out := make([]Result, 0, len(cat))
	for _, t := range cat {
		path, err := exec.LookPath(t.Name)
		out = append(out, Result{Tool: t, Found: err == nil, Path: path})
	}
	return out
}

// MissingRequired returns required tools that are not installed.
func MissingRequired(results []Result) []Result {
	var m []Result
	for _, r := range results {
		if r.Required && !r.Found {
			m = append(m, r)
		}
	}
	return m
}
