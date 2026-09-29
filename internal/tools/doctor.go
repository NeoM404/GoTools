// Package tools implements `bankctl doctor`: it checks that the ecosystem
// CLIs bankctl orchestrates (and the ones the team standardises on) are
// installed and, where a floor is defined, recent enough. bankctl deliberately
// does NOT reimplement these — see docs/ecosystem-tools.md.
package tools

import (
	"bytes"
	"context"
	"os/exec"
	"sync"
	"time"

	"github.com/NeoM404/GoTools/internal/execx"
)

// probeTimeout bounds each `<tool> --version` call. Generous because some
// CLIs (az) do slow first-run work, but finite so doctor always finishes.
const probeTimeout = 20 * time.Second

// Tool describes an external CLI the team relies on.
type Tool struct {
	Name     string // binary name in PATH
	Purpose  string
	Required bool // required for bankctl's own subcommands to work
	Install  string

	// MinVersion is the floor bankctl warns below (empty = presence-only).
	MinVersion string
	// VersionArgs is how to ask the tool its version (empty = no version probe).
	VersionArgs []string
}

// Catalog is the set of tools doctor checks for. Floors are conservative — set
// to surface genuinely stale CLIs, not to nag. Override per-tool in config via
// "minVersions": {"kubectl": "1.29"}.
func Catalog() []Tool {
	return []Tool{
		{Name: "kubectl", Purpose: "Kubernetes CLI (bankctl guard/current shell out to it)", Required: true,
			Install: "brew install kubectl", MinVersion: "1.28", VersionArgs: []string{"version", "--client"}},
		{Name: "aws", Purpose: "AWS CLI — EKS kubeconfig + SSO login", Required: true,
			Install: "brew install awscli", MinVersion: "2.13", VersionArgs: []string{"--version"}},
		{Name: "az", Purpose: "Azure CLI — AKS kubeconfig + login", Required: true,
			Install: "brew install azure-cli", MinVersion: "2.55", VersionArgs: []string{"version", "-o", "json"}},
		{Name: "helm", Purpose: "Kubernetes package manager", Install: "brew install helm",
			MinVersion: "3.12", VersionArgs: []string{"version", "--short"}},
		{Name: "kubectx", Purpose: "Fast context switching", Install: "brew install kubectx"},
		{Name: "kubens", Purpose: "Fast namespace switching", Install: "brew install kubectx"},
		{Name: "kubie", Purpose: "Isolated per-shell contexts (safer at fleet scale)", Install: "brew install kubie"},
		{Name: "k9s", Purpose: "Terminal UI for clusters", Install: "brew install k9s"},
		{Name: "stern", Purpose: "Multi-pod log tailing", Install: "brew install stern"},
		{Name: "argocd", Purpose: "Argo CD CLI (GitOps fleet)", Install: "brew install argocd"},
		{Name: "kubent", Purpose: "Deprecated-API scanner (pre-upgrade)", Install: "sh -c 'curl -sSfL https://git.io/install-kubent | sh'"},
		{Name: "trivy", Purpose: "Image/IaC/secret scanner", Install: "brew install trivy"},
	}
}

// Result is the outcome of checking one tool.
type Result struct {
	Tool
	Found    bool
	Path     string
	Detected string // parsed version, "" if not probed or unparseable
	Outdated bool   // Found && MinVersion set && Detected < MinVersion
}

// probeVersion runs a tool's version command and extracts a SemVer string.
// Returns "" if the tool has no probe or the output can't be parsed.
func probeVersion(ctx context.Context, t Tool) string {
	if len(t.VersionArgs) == 0 {
		return ""
	}
	// Combined output, and a non-zero exit tolerated when something was
	// printed: some CLIs report their version on stderr or exit oddly.
	// exec serialises writes when Stdout and Stderr are the same writer.
	var out bytes.Buffer
	err := execx.Run(ctx, execx.Spec{Name: t.Name, Args: t.VersionArgs, Stdout: &out, Stderr: &out, Timeout: probeTimeout})
	if err != nil && out.Len() == 0 {
		return ""
	}
	v, ok := ParseSemVer(out.String())
	if !ok {
		return ""
	}
	return versionString(v)
}

func versionString(v SemVer) string {
	return itoa(v.Major) + "." + itoa(v.Minor) + "." + itoa(v.Patch)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Inspect resolves each catalog tool in PATH and, where a floor applies, probes
// its version and flags it outdated. overrides replaces catalog floors by tool
// name (from config "minVersions"). Probes run concurrently — each is an
// independent subprocess — and results keep catalog order.
func Inspect(ctx context.Context, overrides map[string]string) []Result {
	cat := Catalog()
	out := make([]Result, len(cat))
	var wg sync.WaitGroup
	for i, t := range cat {
		if ov, ok := overrides[t.Name]; ok {
			t.MinVersion = ov
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = inspectOne(ctx, t)
		}()
	}
	wg.Wait()
	return out
}

func inspectOne(ctx context.Context, t Tool) Result {
	path, err := exec.LookPath(t.Name)
	r := Result{Tool: t, Found: err == nil, Path: path}
	if !r.Found || t.MinVersion == "" {
		return r
	}
	r.Detected = probeVersion(ctx, t)
	if r.Detected == "" {
		return r
	}
	got, _ := ParseSemVer(r.Detected)
	if min, ok := ParseSemVer(t.MinVersion); ok && got.Below(min) {
		r.Outdated = true
	}
	return r
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

// OutdatedRequired returns required tools that are installed but below floor.
func OutdatedRequired(results []Result) []Result {
	var o []Result
	for _, r := range results {
		if r.Required && r.Outdated {
			o = append(o, r)
		}
	}
	return o
}

// AnyOutdated returns every tool (required or not) below its floor.
func AnyOutdated(results []Result) []Result {
	var o []Result
	for _, r := range results {
		if r.Outdated {
			o = append(o, r)
		}
	}
	return o
}
