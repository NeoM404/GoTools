package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// A runbook's `kubectl rollout status` step can wait minutes; on a terminal
// it shows how far the rollout has got instead of a silent wait:
//
//	⠹ rollout  ██████████░░░░░  2/3 new replicas ready · 1 old terminating

var (
	rolloutAvail   = regexp.MustCompile(`(\d+) of (\d+) updated replicas are available`)
	rolloutUpdated = regexp.MustCompile(`(\d+) out of (\d+) new replicas have been updated`)
	rolloutOld     = regexp.MustCompile(`(\d+) old replicas are pending termination`)
)

type rolloutState struct {
	mu                sync.Mutex
	ready, total, old int
	updated           bool
	buf               bytes.Buffer
	partial           []byte
}

func (r *rolloutState) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(b)
	r.partial = append(r.partial, b...)
	for {
		i := bytes.IndexByte(r.partial, '\n')
		if i < 0 {
			return len(b), nil
		}
		r.line(string(r.partial[:i]))
		r.partial = r.partial[i+1:]
	}
}

func (r *rolloutState) line(l string) {
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch {
	case rolloutAvail.MatchString(l):
		m := rolloutAvail.FindStringSubmatch(l)
		r.ready, r.total, r.old = atoi(m[1]), atoi(m[2]), 0
	case rolloutUpdated.MatchString(l):
		m := rolloutUpdated.FindStringSubmatch(l)
		r.ready, r.total = atoi(m[1]), atoi(m[2])
		r.updated = true
	case rolloutOld.MatchString(l):
		m := rolloutOld.FindStringSubmatch(l)
		r.old = atoi(m[1])
		if r.total > 0 {
			r.ready = r.total
		}
	case strings.Contains(l, "successfully rolled out"):
		if r.total > 0 {
			r.ready = r.total
		}
		r.old = 0
	}
}

func (r *rolloutState) render(st ui.Style, frame int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[frame%10]
	if r.total == 0 {
		return fmt.Sprintf("  %s %s", st.Fg(ui.Blue, spin), st.Dim("rollout: waiting for the first update…"))
	}
	width := 20
	filled := min(width, r.ready*width/r.total)
	what := "new replicas ready"
	if r.updated {
		what = "new replicas updated"
	}
	s := fmt.Sprintf("  %s rollout  %s%s  %d/%d %s", st.Fg(ui.Blue, spin), st.Fg(ui.Green, strings.Repeat("█", filled)), st.Dim(strings.Repeat("░", width-filled)), r.ready, r.total, what)
	if r.old > 0 {
		s += st.Dim(fmt.Sprintf(" · %d old terminating", r.old))
	}
	return s
}

// rolloutWithProgress runs the rollout status step, drawing its progress;
// it returns kubectl's output like s.output does.
func rolloutWithProgress(ctx context.Context, s *kubeSession, args []string, stderr io.Writer) ([]byte, error) {
	st := ui.Style{Color: colorOn(stderr)}
	state := &rolloutState{}
	sp := st.Animate(stderr, func(frame int) string { return state.render(st, frame) })
	var errb bytes.Buffer
	err := s.kubectl(ctx, args, strings.NewReader(""), state, &errb, false)
	sp.Stop()
	out := safetext.Bytes(state.buf.Bytes())
	if err != nil {
		if msg := strings.TrimSpace(safetext.Text(errb.String())); msg != "" {
			return out, fmt.Errorf("%s", msg)
		}
	}
	return out, err
}
