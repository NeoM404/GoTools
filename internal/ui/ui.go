// Package ui renders nedctl's terminal output consistently: styled text,
// status marks and tables that stay aligned when cells are coloured. Every
// style degrades to plain text when colour is off (not a terminal, or
// NO_COLOR), so output still reads — and scripts still parse — without it.
package ui

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nedctl/internal/picker"
)

// Palette. Mid-tones that read on dark and light terminal themes.
const (
	Green  = "#22c55e"
	Amber  = "#f59e0b"
	Red    = "#ef4444"
	Blue   = "#3b82f6"
	Orange = "#f08a24"
	Grey   = "#8b95a5"
)

// Style applies colour only when Color is set.
type Style struct{ Color bool }

func (s Style) sgr(code, t string) string {
	if !s.Color || t == "" {
		return t
	}
	return "\x1b[" + code + "m" + t + "\x1b[0m"
}

func (s Style) Bold(t string) string { return s.sgr("1", t) }
func (s Style) Dim(t string) string  { return s.sgr("2", t) }

// Fg paints t in a #rrggbb colour.
func (s Style) Fg(hex, t string) string {
	if !s.Color {
		return t
	}
	return picker.Paint(hex, t)
}

// BoldFg is bold text in a colour.
func (s Style) BoldFg(hex, t string) string { return s.Bold(s.Fg(hex, t)) }

// Heading is a section title: bold capitals.
func (s Style) Heading(t string) string { return s.BoldFg(Blue, strings.ToUpper(t)) }

// Status marks.
func (s Style) OK(t string) string   { return s.Fg(Green, "✔ ") + t }
func (s Style) Warn(t string) string { return s.Fg(Amber, "⚠ ") + t }
func (s Style) Fail(t string) string { return s.Fg(Red, "✖ ") + t }
func (s Style) Info(t string) string { return s.Fg(Grey, "• ") + t }
func (s Style) Hint(t string) string { return s.Dim("→ " + t) }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Width is the number of columns t takes, ignoring colour codes.
func Width(t string) int { return utf8.RuneCountInString(ansiRe.ReplaceAllString(t, "")) }

// Pad right-pads t to w visible columns.
func Pad(t string, w int) string {
	if n := Width(t); n < w {
		return t + strings.Repeat(" ", w-n)
	}
	return t
}

// Table prints rows under a bold header with a dim rule, two spaces between
// columns, aligned by visible width so coloured cells line up. The last
// column is not padded.
func (s Style) Table(w io.Writer, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = Width(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && Width(c) > widths[i] {
				widths[i] = Width(c)
			}
		}
	}
	line := func(cells []string, style func(string) string) {
		parts := make([]string, len(widths))
		for i := range widths {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			if style != nil {
				c = style(c)
			}
			if i < len(widths)-1 {
				c = Pad(c, widths[i])
			}
			parts[i] = c
		}
		fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	line(header, s.Bold)
	rule := make([]string, len(widths))
	for i, n := range widths {
		rule[i] = strings.Repeat("─", n)
	}
	fmt.Fprintln(w, s.Dim(strings.Join(rule, "  ")))
	for _, r := range rows {
		line(r, nil)
	}
}

// Progress shows an animated "⠋ msg" on w until the returned stop is
// called, then clears the line. It draws only when s.Color is set (a
// terminal), so logs and pipes never get spinner noise.
func (s Style) Progress(w io.Writer, msg string) (stop func()) {
	if !s.Color {
		return func() {}
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(90 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(w, "\r%s %s", s.Fg(Blue, frames[i%len(frames)]), s.Dim(msg))
			select {
			case <-done:
				fmt.Fprint(w, "\r\x1b[K")
				return
			case <-t.C:
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); <-finished }) }
}
