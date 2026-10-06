// Package picker is a terminal chooser that works the same in Windows
// Terminal, WSL, macOS and Linux: a numbered table, type to filter, a number
// to select. It reads whole lines, so it needs no raw terminal mode and no
// third-party library, and it is scriptable (pipe the answer in).
package picker

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrCancelled means the operator quit (q) or input ended.
var ErrCancelled = errors.New("selection cancelled")

// Row is one choice. Color, when set (#rrggbb), tints cell ColorCol.
type Row struct {
	Cells    []string
	Color    string
	ColorCol int
}

// Picker lists Rows under Header and returns the chosen row's index.
type Picker struct {
	Title  string
	Header []string
	Rows   []Row
	In     io.Reader
	Out    io.Writer
	// Color enables ANSI 24-bit colour; callers turn it off when Out is not
	// a terminal or NO_COLOR is set.
	Color bool
	// MaxShown caps rows printed at once (default 40); filter to see more.
	MaxShown int
}

// Pick runs the dialogue until a row is chosen, the operator quits, or input
// ends.
func (p Picker) Pick() (int, error) {
	if len(p.Rows) == 0 {
		return -1, errors.New("nothing to choose from")
	}
	in := bufio.NewReader(p.In)
	view := p.filter("")
	filter := ""
	for {
		p.render(view, filter)
		fmt.Fprint(p.Out, "Number to select, text to filter, empty to clear, q to quit: ")
		line, err := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			fmt.Fprintln(p.Out)
			return -1, ErrCancelled
		}
		switch {
		case line == "q" || line == "Q":
			return -1, ErrCancelled
		case line == "":
			filter, view = "", p.filter("")
		default:
			if n, convErr := strconv.Atoi(line); convErr == nil {
				if n >= 1 && n <= len(view) && n <= p.maxShown() {
					return view[n-1], nil
				}
				fmt.Fprintf(p.Out, "no row %d\n", n)
				continue
			}
			next := p.filter(line)
			if len(next) == 0 {
				fmt.Fprintf(p.Out, "nothing matches %q\n", line)
				continue
			}
			filter, view = line, next
		}
	}
}

func (p Picker) maxShown() int {
	if p.MaxShown > 0 {
		return p.MaxShown
	}
	return 40
}

// filter returns indexes of rows where every term matches some cell,
// case-insensitively.
func (p Picker) filter(text string) []int {
	terms := strings.Fields(strings.ToLower(text))
	var out []int
	for i, r := range p.Rows {
		hay := strings.ToLower(strings.Join(r.Cells, " "))
		ok := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, i)
		}
	}
	return out
}

func (p Picker) render(view []int, filter string) {
	if p.Title != "" {
		fmt.Fprintln(p.Out, p.Title)
	}
	shown := view
	if len(shown) > p.maxShown() {
		shown = shown[:p.maxShown()]
	}
	widths := make([]int, len(p.Header))
	for i, h := range p.Header {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, idx := range shown {
		for i, c := range p.Rows[idx].Cells {
			if i < len(widths) && utf8.RuneCountInString(c) > widths[i] {
				widths[i] = utf8.RuneCountInString(c)
			}
		}
	}
	num := len(strconv.Itoa(len(shown)))
	fmt.Fprintf(p.Out, "  %*s  %s\n", num, "#", p.line(p.Header, widths, "", -1))
	for n, idx := range shown {
		r := p.Rows[idx]
		fmt.Fprintf(p.Out, "  %*d  %s\n", num, n+1, p.line(r.Cells, widths, r.Color, r.ColorCol))
	}
	if more := len(view) - len(shown); more > 0 {
		fmt.Fprintf(p.Out, "  … %d more — type to filter\n", more)
	}
	if filter != "" {
		fmt.Fprintf(p.Out, "  filter: %q (%d of %d)\n", filter, len(view), len(p.Rows))
	}
}

func (p Picker) line(cells []string, widths []int, color string, colorCol int) string {
	parts := make([]string, len(widths))
	for i := range widths {
		c := ""
		if i < len(cells) {
			c = cells[i]
		}
		pad := c + strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c))
		if i == colorCol && p.Color {
			pad = Paint(color, pad)
		}
		parts[i] = pad
	}
	return strings.TrimRight(strings.Join(parts, "  "), " ")
}

// Paint wraps s in an ANSI 24-bit foreground colour; an invalid colour
// leaves s unchanged.
func Paint(hex, s string) string {
	r, g, b, ok := RGB(hex)
	if !ok {
		return s
	}
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, s)
}

// RGB parses #rrggbb.
func RGB(hex string) (r, g, b int, ok bool) {
	if len(hex) != 7 || hex[0] != '#' {
		return 0, 0, 0, false
	}
	v, err := strconv.ParseUint(hex[1:], 16, 32)
	if err != nil {
		return 0, 0, 0, false
	}
	return int(v >> 16 & 0xff), int(v >> 8 & 0xff), int(v & 0xff), true
}
