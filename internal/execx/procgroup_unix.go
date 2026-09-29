//go:build unix

package execx

import (
	"os/exec"
	"syscall"
)

// isolateProcessGroup starts the command as the leader of a new process group
// and makes cancellation kill the whole group. Killing only the direct child
// is not enough: az is a shell wrapper around python, so on timeout the python
// process would survive — orphaned, still calling cloud APIs.
//
// Safe for these CLIs because stdin is never attached (it reads /dev/null):
// a background process group only stops (SIGTTIN) if it reads the terminal.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// A negative pid signals every process in the group.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
