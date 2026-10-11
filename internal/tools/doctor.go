// Package tools implements `nedctl doctor`: it checks that the ecosystem
// CLIs nedctl orchestrates (and the ones the team standardises on) are
// installed and, where a floor is defined, recent enough. nedctl deliberately
// does NOT reimplement these — see docs/ecosystem-tools.md.
package tools

import (
	"bytes"
	"context"
	"os/exec"
	"sync"
	"time"

	"nedctl/internal/execx"
)

// probeTimeout bounds each `<tool> --version` call. Generous because some
// CLIs (az) do slow first-run work, but finite so doctor always finishes.
const probeTimeout = 20 * time.Second

// Tool describes an external CLI the team relies on.
type Tool struct {
	Name     string // binary name in PATH
	Purpose  string
	Required bool // required for nedctl's own subcommands to work
	// Install is how to get the tool on macOS (Homebrew); InstallLinux on
	// Ubuntu and WSL, InstallWindows on Windows. Empty: see the docs.
	Install, InstallLinux, InstallWindows string

	// MinVersion is the floor nedctl warns below (empty = presence-only).
	MinVersion string
	// VersionArgs is how to ask the tool its version (empty = no version probe).
	VersionArgs []string
}

// Catalog is the set of tools doctor checks for. Floors are conservative — set
// to surface genuinely stale CLIs, not to nag. Override per-tool in config via
// "minVersions": {"kubectl": "1.29"}.
func Catalog() []Tool {
	const more = "see docs/ecosystem-tools.md"
	return []Tool{
		{Name: "kubectl", Purpose: "Kubernetes CLI (nedctl guard/current shell out to it)", Required: true,
			Install:        "brew install kubectl",
			InstallLinux:   `curl -sSLo kubectl "https://dl.k8s.io/release/$(curl -sSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install -m 0755 kubectl /usr/local/bin/kubectl`,
			InstallWindows: "winget install Kubernetes.kubectl",
			MinVersion:     "1.28", VersionArgs: []string{"version", "--client"}},
		{Name: "aws", Purpose: "AWS CLI — EKS kubeconfig + SSO login", Required: true,
			Install:        "brew install awscli",
			InstallLinux:   "curl -sSo awscliv2.zip https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip && unzip -q awscliv2.zip && sudo ./aws/install --update",
			InstallWindows: "winget install Amazon.AWSCLI",
			MinVersion:     "2.13", VersionArgs: []string{"--version"}},
		{Name: "az", Purpose: "Azure CLI — AKS kubeconfig + login", Required: true,
			Install:        "brew install azure-cli",
			InstallLinux:   "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash",
			InstallWindows: "winget install Microsoft.AzureCLI",
			MinVersion:     "2.55", VersionArgs: []string{"version", "-o", "json"}},
		{Name: "session-manager-plugin", Purpose: "AWS Session Manager plugin — nedctl shell/connect",
			Install:        "brew install --cask session-manager-plugin",
			InstallLinux:   "curl -sSo session-manager-plugin.deb https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb && sudo dpkg -i session-manager-plugin.deb",
			InstallWindows: "winget install Amazon.SessionManagerPlugin",
			VersionArgs:    []string{"--version"}},
		{Name: "ssh", Purpose: "OpenSSH client — nedctl azure kube/shell",
			Install:        "built into macOS",
			InstallLinux:   "sudo apt install openssh-client",
			InstallWindows: "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 (PowerShell as administrator; built into Windows 10 and 11)",
			VersionArgs:    []string{"-V"}},
		{Name: "helm", Purpose: "Kubernetes package manager", Install: "brew install helm",
			InstallLinux: "curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash", InstallWindows: "winget install Helm.Helm",
			MinVersion: "3.12", VersionArgs: []string{"version", "--short"}},
		{Name: "kubectx", Purpose: "Fast context switching", Install: "brew install kubectx", InstallLinux: more, InstallWindows: more},
		{Name: "kubens", Purpose: "Fast namespace switching", Install: "brew install kubectx", InstallLinux: more, InstallWindows: more},
		{Name: "kubie", Purpose: "Isolated per-shell contexts (safer at fleet scale)", Install: "brew install kubie", InstallLinux: more, InstallWindows: more},
		{Name: "k9s", Purpose: "Terminal UI for clusters", Install: "brew install k9s", InstallLinux: more, InstallWindows: "winget install Derailed.k9s"},
		{Name: "stern", Purpose: "Multi-pod log tailing", Install: "brew install stern", InstallLinux: more, InstallWindows: more},
		{Name: "argocd", Purpose: "Argo CD CLI (GitOps fleet)", Install: "brew install argocd", InstallLinux: more, InstallWindows: more},
		{Name: "kubent", Purpose: "Deprecated-API scanner (pre-upgrade)", Install: "sh -c 'curl -sSfL https://git.io/install-kubent | sh'",
			InstallLinux: "sh -c 'curl -sSfL https://git.io/install-kubent | sh'", InstallWindows: more},
		{Name: "trivy", Purpose: "Image/IaC/secret scanner", Install: "brew install trivy", InstallLinux: more, InstallWindows: more},
	}
}

// InstallHint is how to install the tool on goos ("darwin", "linux",
// "windows"): what someone on that machine can actually run.
func (t Tool) InstallHint(goos string) string {
	switch goos {
	case "linux":
		if t.InstallLinux != "" {
			return t.InstallLinux
		}
	case "windows":
		if t.InstallWindows != "" {
			return t.InstallWindows
		}
	}
	return t.Install
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
// name (from config "minVersions"); notRequired demotes required tools that
// this host does not need (a bastion has no aws/az). Probes run concurrently
// — each is an independent subprocess — and results keep catalog order.
func Inspect(ctx context.Context, overrides map[string]string, notRequired ...string) []Result {
	cat := Catalog()
	out := make([]Result, len(cat))
	var wg sync.WaitGroup
	for i, t := range cat {
		if ov, ok := overrides[t.Name]; ok {
			t.MinVersion = ov
		}
		for _, n := range notRequired {
			if t.Name == n {
				t.Required = false
			}
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
