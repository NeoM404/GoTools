package app

import (
	"strings"
	"testing"

	"nedctl/internal/ui"
)

func TestRolloutProgressReadsKubectl(t *testing.T) {
	r := &rolloutState{}
	st := ui.Style{}
	if f := r.render(st, 0); !strings.Contains(f, "waiting for the first update") {
		t.Fatalf("before: %q", f)
	}
	r.Write([]byte("Waiting for deployment \"api\" rollout to finish: 1 out of 3 new replicas have been updated...\n"))
	if f := r.render(st, 1); !strings.Contains(f, "1/3 new replicas updated") {
		t.Fatalf("updating: %q", f)
	}
	r.Write([]byte("Waiting for deployment \"api\" rollout to finish: 1 old replicas are pending termination...\n"))
	if f := r.render(st, 2); !strings.Contains(f, "3/3") || !strings.Contains(f, "1 old terminating") {
		t.Fatalf("old: %q", f)
	}
	r.Write([]byte("Waiting for deployment \"api\" rollout to finish: 2 of 3 updated replicas are available...\n"))
	if f := r.render(st, 3); !strings.Contains(f, "2/3 new replicas") || strings.Contains(f, "old terminating") {
		t.Fatalf("available: %q", f)
	}
	r.Write([]byte("deployment \"api\" successfully rolled out\n"))
	if f := r.render(st, 4); !strings.Contains(f, "3/3") || !strings.Contains(r.buf.String(), "successfully rolled out") {
		t.Fatalf("done: %q", f)
	}
}
