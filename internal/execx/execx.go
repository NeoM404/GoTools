// Package execx runs the external CLIs nedctl orchestrates (kubectl, aws, az
// and the tools doctor probes). Every subprocess nedctl starts goes through
// here, so three guarantees hold everywhere:
//
//   - Bounded: every command has a deadline. A hung cloud CLI (an SSO prompt
//     nobody answers, a stalled network call) fails with a TimeoutError
//     instead of hanging nedctl, a CI job or a shell prompt indefinitely.
//   - Cancellable: the caller's context is honoured, so Ctrl-C / SIGTERM stops
//     the child process instead of orphaning it.
//   - Diagnosable: a failing command's stderr is carried in the error, so the
//     operator sees "current-context is not set" rather than "exit status 1".
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"
)

// waitDelay bounds how long we wait for a killed command's I/O to drain.
// Without it, a CLI that spawns children holding our pipes (az is a shell
// wrapper around python) can keep Wait blocked after the deadline fires.
// A variable only so tests can shorten it.
var waitDelay = 5 * time.Second

// maxStderrInError caps how much of a failing command's stderr is quoted in
// the returned error, so one noisy CLI cannot flood a terminal or log line.
const maxStderrInError = 512

// Spec describes one command invocation.
type Spec struct {
	Name string
	Args []string
	// Env entries are appended to the inherited environment (later wins).
	Env []string
	// Stdout/Stderr stream the command's output. When Stderr is nil it is
	// captured and quoted in the error on failure instead.
	Stdout io.Writer
	Stderr io.Writer
	// Timeout is required: a zero or negative value is a programming error,
	// because an unbounded subprocess is exactly what this package prevents.
	Timeout time.Duration
}

// TimeoutError reports a command that exceeded its deadline.
type TimeoutError struct {
	Name  string
	After time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("%s did not finish within %s", e.Name, e.After)
}

// ErrInterrupted is returned when the caller's context was cancelled (e.g. the
// operator pressed Ctrl-C) before the command finished.
var ErrInterrupted = errors.New("interrupted")

// NotFoundError reports a CLI that is not installed or not on PATH.
type NotFoundError struct{ Name string }

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("required CLI %q not found in PATH — run `nedctl doctor`", e.Name)
}

// Interactive runs a command attached to the operator's terminal — an SSO
// sign-in, a Session Manager shell — streaming to spec.Stdout/Stderr (default
// the process's own) and reading os.Stdin. It differs from Run in three ways
// an interactive child needs:
//
//   - it stays in nedctl's process group, so it may read the terminal;
//   - Ctrl-C belongs to the child (a remote shell's Ctrl-C must interrupt the
//     remote command, not end the session), so nedctl swallows SIGINT while
//     the child runs and the caller's cancellation does not kill it;
//   - the deadline still applies: a session left open past spec.Timeout ends.
func Interactive(ctx context.Context, spec Spec) error {
	if spec.Timeout <= 0 {
		return fmt.Errorf("execx: %s started without a timeout", spec.Name)
	}
	path, err := exec.LookPath(spec.Name)
	if err != nil {
		return &NotFoundError{Name: spec.Name}
	}
	swallow := make(chan os.Signal, 1)
	signal.Notify(swallow, os.Interrupt)
	defer signal.Stop(swallow)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), spec.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, spec.Args...) //nolint:gosec // callers pass typed, validated arguments
	cmd.WaitDelay = waitDelay
	cmd.Stdin = os.Stdin
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if spec.Stdout != nil {
		cmd.Stdout = spec.Stdout
	}
	if spec.Stderr != nil {
		cmd.Stderr = spec.Stderr
	}
	if len(spec.Env) > 0 {
		cmd.Env = append(os.Environ(), spec.Env...)
	}
	runErr := cmd.Run()
	switch {
	case runErr == nil:
		return nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return &TimeoutError{Name: spec.Name, After: spec.Timeout}
	}
	return fmt.Errorf("%s: %w", spec.Name, runErr)
}

// Run executes spec, streaming to spec.Stdout/Stderr.
func Run(ctx context.Context, spec Spec) error {
	_, err := run(ctx, spec, false)
	return err
}

// Output executes a command and returns its stdout.
func Output(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return run(ctx, Spec{Name: name, Args: args, Timeout: timeout}, true)
}

// OutputEnv is Output with extra environment entries.
func OutputEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) ([]byte, error) {
	return run(ctx, Spec{Name: name, Args: args, Env: env, Timeout: timeout}, true)
}

func run(parent context.Context, spec Spec, capture bool) ([]byte, error) {
	if spec.Timeout <= 0 {
		return nil, fmt.Errorf("execx: %s started without a timeout", spec.Name)
	}
	path, err := exec.LookPath(spec.Name)
	if err != nil {
		return nil, &NotFoundError{Name: spec.Name}
	}

	ctx, cancel := context.WithTimeout(parent, spec.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, spec.Args...) //nolint:gosec // callers pass typed, validated arguments
	// WaitDelay is a backstop in case a descendant escapes the process group.
	cmd.WaitDelay = waitDelay
	isolateProcessGroup(cmd)
	if len(spec.Env) > 0 {
		cmd.Env = append(os.Environ(), spec.Env...)
	}

	var stdout, stderr bytes.Buffer
	switch {
	case capture:
		cmd.Stdout = &stdout
	case spec.Stdout != nil:
		cmd.Stdout = spec.Stdout
	default:
		cmd.Stdout = os.Stdout
	}
	if spec.Stderr != nil {
		cmd.Stderr = spec.Stderr
	} else {
		cmd.Stderr = &stderr
	}

	runErr := cmd.Run()
	switch {
	case runErr == nil:
		return stdout.Bytes(), nil
	case parent.Err() != nil:
		// The caller cancelled; that outranks our own deadline.
		return nil, fmt.Errorf("%s: %w", spec.Name, ErrInterrupted)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, &TimeoutError{Name: spec.Name, After: spec.Timeout}
	}
	if msg := summarize(stderr.Bytes()); msg != "" {
		return nil, fmt.Errorf("%s: %s (%w)", spec.Name, msg, runErr)
	}
	return nil, fmt.Errorf("%s: %w", spec.Name, runErr)
}

// summarize turns captured stderr into a single bounded line for an error.
func summarize(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > maxStderrInError {
		cut := maxStderrInError
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut-- // never split a multi-byte character
		}
		s = s[:cut] + "…"
	}
	return s
}
