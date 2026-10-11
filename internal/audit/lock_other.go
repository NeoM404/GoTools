//go:build !unix && !windows

package audit

import "os"

// lock is a no-op where neither flock (lock_unix.go) nor LockFileEx
// (lock_windows.go) is available.
func lock(*os.File) error { return nil }

func unlock(*os.File) {}
