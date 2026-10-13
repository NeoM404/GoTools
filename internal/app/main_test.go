package app

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain points the audit log and every config file at a throwaway
// directory, so tests never read or write the developer's real files.
func TestMain(m *testing.M) {
	// The fake Session Manager plugin runs this binary as a port forwarder.
	if fw := os.Getenv("NEDCTL_TEST_FORWARD"); fw != "" {
		testForward(fw)
		return
	}
	// nedctl mcp runs each tool as nedctl itself: in tests, this binary.
	if os.Getenv("NEDCTL_TEST_AS_NEDCTL") == "1" {
		os.Exit(Exec(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Setenv("NEDCTL_TEST_BIN", os.Args[0])
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
	tunnelWatch = 50 * time.Millisecond
	// doctor's Session Manager check reaches a local stand-in, never AWS.
	ssm := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	ssmProbe = func(string) (*http.Client, string) { return ssm.Client(), ssm.URL + "/" }
	code := m.Run()
	ssm.Close()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testForward listens on the first port and passes each connection to the
// second, until killed: the fake Session Manager port-forward.
func testForward(spec string) {
	from, to, _ := strings.Cut(spec, ":")
	ln, err := net.Listen("tcp", "127.0.0.1:"+from)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			up, err := net.Dial("tcp", "127.0.0.1:"+to)
			if err != nil {
				return
			}
			defer up.Close()
			go io.Copy(up, c)
			io.Copy(c, up)
		}()
	}
}
