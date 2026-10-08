//go:build !unix

package audit

import "os"

// lock is a no-op off unix; nedctl ships for macOS and Linux only.
func lock(*os.File) error { return nil }

func unlock(*os.File) {}
