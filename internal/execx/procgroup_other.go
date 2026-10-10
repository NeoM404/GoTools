//go:build !unix

package execx

import "os/exec"

// isolateProcessGroup is a no-op off unix; cancellation kills the direct child
// and WaitDelay bounds the wait for any descendants holding our pipes.
func isolateProcessGroup(*exec.Cmd) {}

// terminateGroup ends the command; off unix there is no group signal.
func terminateGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
