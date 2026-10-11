//go:build !windows

package app

import (
	"errors"
	"os"
	"syscall"
)

// pidAlive reports whether a process with this ID is running.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
