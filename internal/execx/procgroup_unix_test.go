//go:build unix

package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A timed-out CLI must not leave descendants running (the az → python case).
func TestTimeoutKillsWholeProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	start := time.Now()
	_, err := Output(context.Background(), 200*time.Millisecond,
		"sh", "-c", "sleep 30 & echo $! > "+pidFile+"; wait")
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("want TimeoutError, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %s: descendants held the pipes until WaitDelay", elapsed)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	// Give the kernel a moment to reap, then the grandchild must be gone.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild %d survived the timeout (orphaned process)", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
