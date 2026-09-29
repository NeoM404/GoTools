//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lock takes an exclusive advisory lock, serialising appends across
// processes (several terminals running bankctl at once).
func lock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }

func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
