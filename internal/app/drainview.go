package app

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// drainView turns kubectl drain's output into a live picture: a bar of
// pods moved off the node, the pods being evicted now, and the ones a
// disruption budget is holding (amber, with the reason). What kubectl says
// that is not about a pod is printed afterwards.

var (
	drainEvicting = regexp.MustCompile(`evicting pod (\S+)/(\S+)`)
	drainEvicted  = regexp.MustCompile(`pod/(\S+) evicted`)
	drainBlocked  = regexp.MustCompile(`error when evicting pods/"([^"]+)" -n "([^"]+)".*?(disruption budget|Too Many Requests)`)
	drainNodeLine = regexp.MustCompile(`^node/\S+ (cordoned|already cordoned|drained)`)
)

type drainView struct {
	mu        sync.Mutex
	w         io.Writer
	st        ui.Style
	node      string
	total     int
	moving    map[string]time.Time // ns/name → since
	blocked   map[string]string    // ns/name → why
	moved     []string
	other     []string
	partial   []byte
	lines     int
	frame     int
	done      chan struct{}
	finished  chan struct{}
	stopOnce  sync.Once
	nameIndex map[string]string // pod name → ns/name (evicted lines have no namespace)
}

func newDrainView(w io.Writer, node string, total int) *drainView {
	v := &drainView{w: w, st: ui.Style{Color: true}, node: node, total: total, moving: map[string]time.Time{}, blocked: map[string]string{},
		nameIndex: map[string]string{}, done: make(chan struct{}), finished: make(chan struct{})}
	go func() {
		defer close(v.finished)
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			v.draw()
			select {
			case <-v.done:
				v.draw()
				return
			case <-t.C:
			}
		}
	}()
	return v
}

func (v *drainView) Write(b []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.partial = append(v.partial, b...)
	for {
		i := strings.IndexByte(string(v.partial), '\n')
		if i < 0 {
			return len(b), nil
		}
		v.line(safetext.Text(string(v.partial[:i])))
		v.partial = v.partial[i+1:]
	}
}

func (v *drainView) line(l string) {
	l = strings.TrimSpace(l)
	switch {
	case l == "":
	case drainNodeLine.MatchString(l):
	case drainBlocked.MatchString(l):
		m := drainBlocked.FindStringSubmatch(l)
		key := m[2] + "/" + m[1]
		v.blocked[key] = "waiting for its disruption budget"
		v.nameIndex[m[1]] = key
	case drainEvicting.MatchString(l):
		m := drainEvicting.FindStringSubmatch(l)
		key := m[1] + "/" + m[2]
		if _, ok := v.moving[key]; !ok {
			v.moving[key] = now()
		}
		v.nameIndex[m[2]] = key
	case drainEvicted.MatchString(l):
		name := drainEvicted.FindStringSubmatch(l)[1]
		key := firstNonBlank(v.nameIndex[name], name)
		delete(v.moving, key)
		delete(v.blocked, key)
		v.moved = append(v.moved, key)
	default:
		v.other = append(v.other, l)
	}
}

func (v *drainView) render() []string {
	st := v.st
	total := max(v.total, len(v.moved)+len(v.moving))
	width := 30
	filled := 0
	if total > 0 {
		filled = len(v.moved) * width / total
	}
	bar := st.Fg(ui.Green, strings.Repeat("█", filled)) + st.Dim(strings.Repeat("░", width-filled))
	spin := []string{"◐", "◓", "◑", "◒"}[v.frame%4]
	lines := []string{fmt.Sprintf("%s %s  %s  %d/%d pods moved", st.Fg(ui.Blue, spin), st.Bold("draining "+v.node), bar, len(v.moved), total)}
	var keys []string
	for k := range v.moving {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 6 {
			lines = append(lines, st.Dim(fmt.Sprintf("    … and %d more being moved", len(keys)-6)))
			break
		}
		why, held := v.blocked[k]
		secs := int(now().Sub(v.moving[k]).Seconds())
		if held {
			lines = append(lines, fmt.Sprintf("  %s %s %s", st.Fg(ui.Amber, "⏸"), k, st.Fg(ui.Amber, fmt.Sprintf("%s (%ds)", why, secs))))
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s %s %s", st.Fg(ui.Blue, "→"), k, st.Dim(fmt.Sprintf("moving (%ds)", secs))))
	}
	return lines
}

func (v *drainView) draw() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.frame++
	lines := v.render()
	var b strings.Builder
	if v.lines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA\r", v.lines)
	}
	for _, l := range lines {
		b.WriteString("\x1b[2K" + l + "\n")
	}
	for i := len(lines); i < v.lines; i++ {
		b.WriteString("\x1b[2K\n")
	}
	if extra := v.lines - len(lines); extra > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", extra)
	}
	v.lines = len(lines)
	io.WriteString(v.w, b.String())
}

// stop leaves the last frame and prints what kubectl said besides pods.
func (v *drainView) stop() {
	v.stopOnce.Do(func() {
		close(v.done)
		<-v.finished
		v.mu.Lock()
		defer v.mu.Unlock()
		if len(v.partial) > 0 {
			v.line(safetext.Text(string(v.partial)))
		}
		for _, l := range v.other {
			fmt.Fprintln(v.w, "  "+l)
		}
	})
}
