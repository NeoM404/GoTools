package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// productionPause counts down in red before a production session opens —
// a moment for "this is prod" to register — and returns false when Ctrl-C
// cancels it. It only runs at a terminal without --yes. It never reads
// the keyboard: a read left waiting would swallow the first line typed
// into the session that follows.
var (
	pauseTick = time.Second
	pauseOn   = colorOn // a seam for tests: the countdown needs a terminal
)

func productionPause(ctx context.Context, cfg config.Config, prod bool, target string, yes bool, stderr io.Writer) bool {
	secs := cfg.PauseSeconds()
	st := ui.Style{Color: pauseOn(stderr)}
	if !prod || yes || secs <= 0 || !st.Color || !stdinIsTerminal() {
		return true
	}
	for left := secs; left > 0; left-- {
		bar := strings.Repeat("█", left) + strings.Repeat("░", secs-left)
		fmt.Fprintf(stderr, "\r\x1b[2K%s %s in %s %s",
			st.BoldFg(ui.Red, "▌PRODUCTION▐"), st.Bold(target), st.BoldFg(ui.Red, fmt.Sprintf("%d", left)), st.Fg(ui.Red, bar)+st.Dim("  Ctrl-C cancels"))
		select {
		case <-ctx.Done():
			fmt.Fprintf(stderr, "\r\x1b[2K%s\n", st.Fail("cancelled — nothing was opened"))
			return false
		case <-time.After(pauseTick):
		}
	}
	fmt.Fprint(stderr, "\r\x1b[2K")
	return true
}
