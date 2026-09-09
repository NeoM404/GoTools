// Package kube inspects the local kubeconfig and classifies the current
// context for the production safety guard. It shells out to `kubectl` rather
// than parsing kubeconfig YAML, keeping this dependency-free and always
// consistent with whatever kubectl itself sees.
package kube

import (
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
