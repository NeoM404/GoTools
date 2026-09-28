// Command bankctl is the banking Kubernetes fleet CLI: one command to see every
// EKS/AKS cluster across the group, pull credentials for any of them, report
// version drift, and stay out of production by accident.
//
// This entrypoint is deliberately thin. All flag parsing, dispatch and command
// logic lives in internal/app, which takes its I/O as parameters and returns an
// exit code rather than calling os.Exit — that is what makes the whole CLI
// testable without spawning a process. Keep it that way: new commands go in
// internal/app, not here.
//
// See docs/bankctl.md for the full command reference.
package main

import (
	"os"

	"github.com/NeoM404/GoTools/internal/app"
)

func main() {
	// os.Args[1:] drops the program name; app.Exec owns every exit code.
	os.Exit(app.Exec(os.Args[1:], os.Stdout, os.Stderr))
}
