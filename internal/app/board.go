package app

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// The fleet board is `health --board`: every cluster on one screen, drawn
// at once and filled in as each cluster's results arrive over the bastion
// connection — the status letters flip into place like a departures board,
// counters climb, and with --watch a cluster whose status changes flips
// again and is marked. It draws only on a terminal; NEDCTL_REDUCED_MOTION
// keeps the updates and drops the flipping.

const (
	flapFor     = 520 * time.Millisecond
	flapStagger = 55 * time.Millisecond
	boardTick   = 70 * time.Millisecond
	statusWidth = len("UNREACHABLE")
)

type boardRow struct {
	env, cluster string
	h            *clusterHealth
	flapStart    time.Time
	change       string // "▲" better, "▼" worse, since the last round
}

type fleetBoard struct {
	mu       sync.Mutex
	w        io.Writer
	cfg      config.Config
	st       ui.Style
	motion   bool
	title    string
	rows     []*boardRow
	index    map[string]*boardRow
	lines    int // lines drawn last frame, to move back over
	frame    int
	updated  time.Time
	nextAt   time.Time // --watch: the next round
	round    int
	since    time.Time // when the current round started
	cols     func() int
	stopOnce sync.Once
	done     chan struct{}
	finished chan struct{}
}

func reducedMotion() bool { return os.Getenv("NEDCTL_REDUCED_MOTION") != "" }

func newFleetBoard(w io.Writer, cfg config.Config, title string) *fleetBoard {
	b := &fleetBoard{w: w, cfg: cfg, st: ui.Style{Color: true}, motion: !reducedMotion(), title: title,
		index: map[string]*boardRow{}, done: make(chan struct{}), finished: make(chan struct{})}
	b.cols = func() int {
		if f, ok := asFile(w); ok {
			if c, _ := termSize(f); c > 0 {
				return c
			}
		}
		return 120
	}
	return b
}

func boardKey(env, cluster string) string { return env + "\x00" + cluster }

// add lays out rows for clusters about to be read (kept from earlier
// rounds when already there).
func (b *fleetBoard) add(env string, clusters []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range clusters {
		if _, ok := b.index[boardKey(env, c)]; ok {
			continue
		}
		r := &boardRow{env: env, cluster: c}
		b.index[boardKey(env, c)] = r
		b.rows = append(b.rows, r)
	}
}

var statusRank = map[string]int{"ok": 0, "warn": 1, "fail": 2, "unreachable": 3}

// set fills in a cluster's result, flipping its status when it is new or
// different.
func (b *fleetBoard) set(h clusterHealth) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.index[boardKey(h.Environment, h.Cluster)]
	if !ok {
		r = &boardRow{env: h.Environment, cluster: h.Cluster}
		b.index[boardKey(h.Environment, h.Cluster)] = r
		b.rows = append(b.rows, r)
	}
	r.change = ""
	if r.h != nil && r.h.Status != h.Status {
		r.change = "▲"
		if statusRank[h.Status] > statusRank[r.h.Status] {
			r.change = "▼"
		}
	}
	if r.h == nil || r.h.Status != h.Status {
		r.flapStart = now()
	}
	hc := h
	r.h = &hc
	b.updated = now()
}

// newRound marks every row as being read again (--watch), keeping what it
// showed until its new result arrives.
func (b *fleetBoard) newRound(next time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.round++
	b.nextAt = next
	b.since = next // the next round starts then
}

func (b *fleetBoard) start() {
	b.mu.Lock()
	b.since = now()
	b.mu.Unlock()
	fmt.Fprint(b.w, "\x1b[?25l") // hide the cursor while drawing
	go func() {
		defer close(b.finished)
		t := time.NewTicker(boardTick)
		defer t.Stop()
		for {
			b.draw()
			select {
			case <-b.done:
				b.draw()
				return
			case <-t.C:
			}
		}
	}()
}

// stop draws the final frame and gives the cursor back.
func (b *fleetBoard) stop() {
	b.stopOnce.Do(func() {
		close(b.done)
		<-b.finished
		fmt.Fprint(b.w, "\x1b[?25h")
	})
}

func (b *fleetBoard) statusColor(s string) string {
	switch s {
	case "ok":
		return ui.Green
	case "warn":
		return ui.Amber
	case "fail":
		return ui.Red
	}
	return ui.Grey
}

// statusCell is the status as shown this frame: settled, flipping (letters
// settle left to right, the rest spin through the alphabet), or waiting
// (a dim scanning dot).
func (b *fleetBoard) statusCell(r *boardRow, t time.Time) string {
	if r.h == nil {
		dots := []rune(strings.Repeat("·", 5))
		if b.motion {
			dots[b.frame/2%len(dots)] = '•'
		}
		waited := t.Sub(b.since)
		switch {
		case b.since.IsZero() || waited < 5*time.Second:
			return b.st.Dim(fmt.Sprintf("%-*s", statusWidth, string(dots)))
		case waited < 30*time.Second:
			return b.st.Dim(fmt.Sprintf("%-*s", statusWidth, fmt.Sprintf("%s %ds", string(dots), int(waited.Seconds()))))
		}
		return b.st.Fg(ui.Amber, fmt.Sprintf("%-*s", statusWidth, fmt.Sprintf("slow %ds", int(waited.Seconds()))))
	}
	word := strings.ToUpper(r.h.Status)
	col := b.statusColor(r.h.Status)
	since := t.Sub(r.flapStart)
	if !b.motion || since >= flapFor+time.Duration(len(word))*flapStagger {
		return b.st.BoldFg(col, fmt.Sprintf("%-*s", statusWidth, word))
	}
	out := make([]rune, statusWidth)
	for i := range out {
		settle := flapFor + time.Duration(i)*flapStagger
		switch {
		case since >= settle && i < len(word):
			out[i] = rune(word[i])
		case since >= settle:
			out[i] = ' '
		default:
			out[i] = rune('A' + rand.IntN(26)) //nolint:gosec // a visual effect, not security
		}
	}
	return b.st.BoldFg(col, string(out))
}

func (b *fleetBoard) counts() (map[string]int, int) {
	c := map[string]int{}
	waiting := 0
	for _, r := range b.rows {
		if r.h == nil {
			waiting++
			continue
		}
		c[r.h.Status]++
	}
	return c, waiting
}

// render builds this frame's lines.
func (b *fleetBoard) render(t time.Time) []string {
	st := b.st
	var lines []string
	counts, waiting := b.counts()
	when := "reading…"
	if !b.updated.IsZero() {
		when = "updated " + b.updated.Local().Format("15:04:05")
	}
	lines = append(lines, st.BoldFg(ui.Blue, "▌NEDCTL FLEET BOARD")+"  "+st.Bold(b.title)+"  "+st.Dim(when))
	spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[b.frame%10]
	summary := fmt.Sprintf("%s %d ok   %s %d warn   %s %d fail   %s %d unreachable",
		st.Fg(ui.Green, "●"), counts["ok"], st.Fg(ui.Amber, "●"), counts["warn"], st.Fg(ui.Red, "●"), counts["fail"], st.Fg(ui.Grey, "●"), counts["unreachable"])
	if waiting > 0 {
		summary += fmt.Sprintf("   %s %d reading", st.Fg(ui.Blue, spin), waiting)
	}
	lines = append(lines, summary, "")

	cw := len("CLUSTER")
	ew := len("ENV")
	for _, r := range b.rows {
		cw = max(cw, len(r.cluster))
		ew = max(ew, len(r.env))
	}
	header := []string{fmt.Sprintf("%-*s", ew, "ENV"), fmt.Sprintf("%-*s", cw, "CLUSTER"), fmt.Sprintf("%-*s", statusWidth, "STATUS"), "  ", fmt.Sprintf("%-13s", "NODES"), fmt.Sprintf("%-15s", "PODS"), fmt.Sprintf("%-14s", "WORKLOADS"), "VERSION"}
	lines = append(lines, b.fit(header, true))
	for _, r := range b.rows {
		nodes, pods, wls, ver := "", "", "", ""
		if r.h != nil {
			nodes, pods, wls, ver = r.h.Nodes, r.h.Pods, r.h.Workloads, strings.TrimSpace(r.h.Version+" "+r.h.Support)
		}
		change := "  "
		switch r.change {
		case "▲":
			change = st.Fg(ui.Green, "▲ ")
		case "▼":
			change = st.Fg(ui.Red, "▼ ")
		}
		env := st.BoldFg(b.cfg.ColorFor(r.env), fmt.Sprintf("%-*s", ew, strings.ToUpper(r.env)))
		cells := []string{env, fmt.Sprintf("%-*s", cw, r.cluster), b.statusCell(r, t), change,
			fmt.Sprintf("%-13s", nodes), fmt.Sprintf("%-15s", pods), fmt.Sprintf("%-14s", wls), ver}
		lines = append(lines, b.fit(cells, false))
	}
	lines = append(lines, "")
	switch {
	case !b.nextAt.IsZero() && waiting == 0:
		left := max(0, int(time.Until(b.nextAt).Seconds()+0.5))
		lines = append(lines, st.Dim(fmt.Sprintf("round %d · next in %ds · ▲ better ▼ worse since the last round · Ctrl-C to stop", b.round, left)))
	case !b.nextAt.IsZero():
		lines = append(lines, st.Dim(fmt.Sprintf("round %d · reading… · Ctrl-C to stop", b.round)))
	case waiting > 0:
		lines = append(lines, st.Dim("a cluster that does not answer is marked unreachable after 20s; none takes more than 90s"))
	}
	return lines
}

// fit joins cells, dropping the last columns until the line fits the
// terminal (a wrapped line would break the redraw).
func (b *fleetBoard) fit(cells []string, header bool) string {
	limit := b.cols() - 1
	for n := len(cells); n > 3; n-- {
		line := strings.Join(cells[:n], "  ")
		if ui.Width(line) <= limit {
			if header {
				return b.st.Dim(line)
			}
			return line
		}
	}
	line := strings.Join(cells[:3], "  ")
	if header {
		return b.st.Dim(line)
	}
	return line
}

func (b *fleetBoard) draw() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.frame++
	lines := b.render(now())
	var buf strings.Builder
	if b.lines > 0 {
		fmt.Fprintf(&buf, "\x1b[%dA\r", b.lines)
	}
	for _, l := range lines {
		buf.WriteString("\x1b[2K" + l + "\n")
	}
	for i := len(lines); i < b.lines; i++ { // the board shrank: clear what is left
		buf.WriteString("\x1b[2K\n")
	}
	if extra := b.lines - len(lines); extra > 0 {
		fmt.Fprintf(&buf, "\x1b[%dA", extra)
	}
	b.lines = len(lines)
	io.WriteString(b.w, buf.String())
}
