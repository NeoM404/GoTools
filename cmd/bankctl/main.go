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
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/NeoM404/GoTools/internal/app"
)

func main() {
	// SIGINT/SIGTERM cancel the context, which stops any running cloud CLI
	// rather than orphaning it; app.ExecContext then exits 130. A second
	// signal falls through to the default handler and kills us immediately.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop() // restore default handling so a second signal is not swallowed
	}()
	code := app.ExecContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
