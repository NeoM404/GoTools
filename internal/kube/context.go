// Package kube inspects the local kubeconfig and classifies the current
// context for the production safety guard. It shells out to `kubectl` rather
// than parsing kubeconfig YAML, keeping this dependency-free and always
// consistent with whatever kubectl itself sees.
package kube

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// CurrentContext returns the active kube-context name.
func CurrentContext() (string, error) {
	out, err := exec.Command("kubectl", "config", "current-context").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ExecAuthAPIVersion returns the client-go exec credential plugin apiVersion
// for the CURRENT context in the given kubeconfig (empty file => default
// kubeconfig). Empty string means the current context does not use an exec
// auth plugin (e.g. token/cert auth). It shells out to kubectl so it always
// agrees with what kubectl itself sees.
func ExecAuthAPIVersion(kubeconfigFile string) (string, error) {
	cmd := exec.Command("kubectl", "config", "view", "--minify", "--output", "json")
	if kubeconfigFile != "" {
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfigFile)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return parseExecAPIVersion(out)
}

// parseExecAPIVersion extracts the first exec-plugin apiVersion from a
// `kubectl config view -o json` document. Kept pure for testing.
func parseExecAPIVersion(data []byte) (string, error) {
	var doc struct {
		Users []struct {
			User struct {
				Exec struct {
					APIVersion string `json:"apiVersion"`
				} `json:"exec"`
			} `json:"user"`
		} `json:"users"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	for _, u := range doc.Users {
		if u.User.Exec.APIVersion != "" {
			return u.User.Exec.APIVersion, nil
		}
	}
	return "", nil
}

// IsDeprecatedExecAPIVersion reports whether v is a removed/deprecated client-go
// exec auth apiVersion. v1alpha1 was removed in Kubernetes 1.24 — a kubeconfig
// still carrying it (written by an old aws/az CLI) will fail against a modern
// cluster, so it is the concrete "CLI drift" signal to warn on.
func IsDeprecatedExecAPIVersion(v string) bool {
	return strings.Contains(v, "v1alpha1")
}

// IsProd reports whether name matches any of the supplied production regexps.
// Invalid patterns are skipped (a bad pattern must never make a prod context
// look safe, nor crash the guard).
func IsProd(name string, patterns []string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(name) {
			return true
		}
	}
	return false
}
