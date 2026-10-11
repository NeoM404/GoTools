package app

import (
	"strings"
	"testing"

	"nedctl/internal/ui"
)

func TestRouteLineMovesThePacketAlongThePath(t *testing.T) {
	st := ui.Style{}
	hops := []string{"payments-devops", "⎈ payments-eks-prod"}
	var seen []int
	for frame := 0; frame < 2*routeSeg; frame++ {
		l := routeLine(st, hops, frame)
		i := strings.Index(l, "●")
		if i < 0 || !strings.HasPrefix(l, "you ") || !strings.HasSuffix(l, "▶ ⎈ payments-eks-prod") || strings.Count(l, "▶") != 2 {
			t.Fatalf("frame %d: %q", frame, l)
		}
		seen = append(seen, i)
	}
	if seen[0] >= seen[routeSeg+1] {
		t.Fatalf("the packet must travel forward: %v", seen)
	}
	if done := routeLine(st, hops, -1); strings.Contains(done, "●") || !strings.Contains(done, "━━━━━━━▶ payments-devops ━━━━━━━▶ ⎈ payments-eks-prod") {
		t.Fatalf("connected: %q", done)
	}
}
