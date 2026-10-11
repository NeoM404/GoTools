//go:build !windows

package app

import "os"

func consoleColor(*os.File) bool { return true }
