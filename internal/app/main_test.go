package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// TestMain points the audit log and every config file at a throwaway
// directory, so tests never read or write the developer's real files.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nedctl-test-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Every test starts from an empty home: no developer config, AWS config,
	// SSO cache or kubeconfig leaks in, so tests pass (or fail) the same on a
	// laptop and on a CI agent. Tests that need state create it.
	os.Setenv("XDG_STATE_HOME", dir)
	os.Setenv("HOME", dir)
	os.Setenv("USERPROFILE", dir)
	os.Setenv("XDG_CONFIG_HOME", dir+"/config")
	os.Setenv("AWS_CONFIG_FILE", dir+"/aws-config")
	os.Setenv("KUBECONFIG", dir+"/kubeconfig")
	for _, k := range []string{"NEDCTL_CONFIG", "AWS_PROFILE", "AWS_CA_BUNDLE", "HTTPS_PROXY", "https_proxy", "WT_SESSION", "WSL_DISTRO_NAME", "WSL_INTEROP", "NEDCTL_KUBECONFIG", "NEDCTL_SHELL_HOOK"} {
		os.Unsetenv(k)
	}
	// Tests never read the developer's terminal; those that need a picker
	// feed it explicitly.
	stdinIsTerminal = func() bool { return false }
	childStdin = func() io.Reader { return strings.NewReader("") }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
