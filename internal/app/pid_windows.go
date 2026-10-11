//go:build windows

package app

import "os"

// pidAlive reports whether a process with this ID is running: on Windows
// FindProcess opens the process, which fails once it has gone.
func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}
