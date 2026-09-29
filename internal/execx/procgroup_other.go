//go:build !unix

package execx

import "os/exec"

// isolateProcessGroup is a no-op off unix; cancellation kills the direct child
// and WaitDelay bounds the wait for any descendants holding our pipes.
func isolateProcessGroup(*exec.Cmd) {}
