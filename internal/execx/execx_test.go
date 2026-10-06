package execx

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestOutputReturnsStdout(t *testing.T) {
	out, err := Output(context.Background(), 5*time.Second, "sh", "-c", "printf hello")
	if err != nil || string(out) != "hello" {
		t.Fatalf("got %q err=%v", out, err)
	}
}

func TestTimeoutKillsHungCommand(t *testing.T) {
	start := time.Now()
	_, err := Output(context.Background(), 100*time.Millisecond, "sh", "-c", "sleep 30")
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout took %s — command was not killed promptly", elapsed)
	}
	if !strings.Contains(err.Error(), "did not finish within 100ms") {
		t.Fatalf("unhelpful message: %v", err)
	}
}

func TestTimeoutWithOrphanHoldingPipe(t *testing.T) {
	// The grandchild inherits stdout and outlives the killed shell. Without
	// WaitDelay, Wait would block until the grandchild exits (30s).
	defer func(d time.Duration) { waitDelay = d }(waitDelay)
	waitDelay = 300 * time.Millisecond
	start := time.Now()
	_, err := Output(context.Background(), 100*time.Millisecond, "sh", "-c", "sleep 30 & wait")
	if err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > waitDelay+3*time.Second {
		t.Fatalf("Wait blocked for %s despite WaitDelay", elapsed)
	}
}

func TestParentCancellationIsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := Output(ctx, time.Minute, "sh", "-c", "sleep 30")
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("want ErrInterrupted, got %v", err)
	}
}

func TestStderrSurfacedOnFailure(t *testing.T) {
	_, err := Output(context.Background(), 5*time.Second, "sh", "-c", "echo 'error: current-context is not set' >&2; exit 1")
	if err == nil || !strings.Contains(err.Error(), "current-context is not set") {
		t.Fatalf("stderr not surfaced: %v", err)
	}
}

func TestMissingBinary(t *testing.T) {
	_, err := Output(context.Background(), time.Second, "definitely-not-a-real-cli-xyz")
	var nf *NotFoundError
	if !errors.As(err, &nf) || !strings.Contains(err.Error(), "bankctl doctor") {
		t.Fatalf("want NotFoundError with doctor hint, got %v", err)
	}
}

func TestZeroTimeoutRefused(t *testing.T) {
	if _, err := Output(context.Background(), 0, "sh", "-c", "true"); err == nil {
		t.Fatal("a command without a timeout must be refused")
	}
}

func TestRunStreamsAndEnv(t *testing.T) {
	var out bytes.Buffer
	err := Run(context.Background(), Spec{
		Name: "sh", Args: []string{"-c", "printf %s \"$BANKCTL_TEST\""},
		Env: []string{"BANKCTL_TEST=streamed"}, Stdout: &out, Timeout: 5 * time.Second,
	})
	if err != nil || out.String() != "streamed" {
		t.Fatalf("got %q err=%v", out.String(), err)
	}
}

func TestSummarizeBoundedAndRuneSafe(t *testing.T) {
	s := summarize([]byte(strings.Repeat("é", maxStderrInError)))
	if !utf8.ValidString(s) {
		t.Fatal("truncation split a multi-byte character")
	}
	if len(s) > maxStderrInError+len("…") {
		t.Fatalf("not bounded: %d bytes", len(s))
	}
	if got := summarize([]byte("  line one\n\tline two  \n")); got != "line one line two" {
		t.Fatalf("whitespace not collapsed: %q", got)
	}
}

func TestInteractiveIgnoresCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the operator pressed Ctrl-C: it belongs to the child, not to us
	var out bytes.Buffer
	if err := Interactive(ctx, Spec{Name: "sh", Args: []string{"-c", "printf done"}, Stdout: &out, Timeout: 5 * time.Second}); err != nil || out.String() != "done" {
		t.Fatalf("out=%q err=%v", out.String(), err)
	}
}

func TestInteractiveStillHasADeadline(t *testing.T) {
	err := Interactive(context.Background(), Spec{Name: "sh", Args: []string{"-c", "sleep 30"}, Timeout: 100 * time.Millisecond})
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %v", err)
	}
	if err := Interactive(context.Background(), Spec{Name: "sh"}); err == nil {
		t.Fatal("an interactive command without a timeout must be refused")
	}
}
