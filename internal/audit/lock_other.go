//go:build !unix

package audit

import "os"

// lock is a no-op off unix; bankctl ships for macOS and Linux only.
func lock(*os.File) error { return nil }

func unlock(*os.File) {}
