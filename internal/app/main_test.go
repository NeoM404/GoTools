package app

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points the audit log at a throwaway state directory, so tests never
// write to the developer's real ~/.local/state.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bankctl-test-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("XDG_STATE_HOME", dir)
	// Tests never read the developer's terminal; those that need a picker
	// feed it explicitly.
	stdinIsTerminal = func() bool { return false }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
