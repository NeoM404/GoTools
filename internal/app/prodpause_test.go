package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"nedctl/internal/config"
)

func TestProductionPauseCountsDownAndCanBeCancelled(t *testing.T) {
	oldOn, oldTick, oldTTY := pauseOn, pauseTick, stdinIsTerminal
	t.Cleanup(func() { pauseOn, pauseTick, stdinIsTerminal = oldOn, oldTick, oldTTY })
	pauseOn = func(io.Writer) bool { return true }
	stdinIsTerminal = func() bool { return true }
	pauseTick = 5 * time.Millisecond
	cfg := config.Config{}

	var b bytes.Buffer
	if !productionPause(context.Background(), cfg, true, "payments-eks-prod", false, &b) {
		t.Fatal("an uninterrupted countdown lets the session open")
	}
	if out := plain(b.String()); !strings.Contains(out, "PRODUCTION") || !strings.Contains(out, "payments-eks-prod in 3") || !strings.Contains(out, "in 1") {
		t.Fatalf("countdown: %q", out)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.Reset()
	if productionPause(ctx, cfg, true, "payments-eks-prod", false, &b) || !strings.Contains(b.String(), "nothing was opened") {
		t.Fatalf("Ctrl-C must cancel: %q", b.String())
	}

	zero := 0
	for name, c := range map[string]struct {
		cfg  config.Config
		prod bool
		yes  bool
	}{"not production": {cfg, false, false}, "--yes": {cfg, true, true}, "turned off": {config.Config{ProductionPause: &zero}, true, false}} {
		b.Reset()
		if !productionPause(ctx, c.cfg, c.prod, "x", c.yes, &b) || b.Len() != 0 {
			t.Errorf("%s: no pause expected, got %q", name, b.String())
		}
	}
}
