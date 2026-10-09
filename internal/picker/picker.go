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
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrCancelled means the operator quit (q) or input ended.
var ErrCancelled = errors.New("selection cancelled")

// Row is one choice.
type Row struct {
	Cells []string
	// Color (#rrggbb) tints cell ColorCol: as a badge when the picker's
	// Badge is set, else as text.
	Color    string
	ColorCol int
	// CellColor tints individual cells' text (e.g. an elevated role).
	CellColor map[int]string
}

// Picker lists Rows under Header and returns the chosen row's index.
type Picker struct {
	Title  string
	Header []string
	Rows   []Row
	In     io.Reader
	Out    io.Writer
	// Color enables ANSI 24-bit colour and styling; callers turn it off when
	// Out is not a terminal or NO_COLOR is set. Everything still reads in
	// plain text.
	Color bool
	// Badge renders each row's ColorCol cell as a coloured badge.
	Badge bool
	// Legend, when set, is printed under the table.
	Legend string
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
		fmt.Fprint(p.Out, p.style("2", "Number to select · text to filter · Enter to clear · q to quit")+" "+p.style("1", "›")+" ")
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

// style wraps s in an SGR code when colour is on.
func (p Picker) style(code, s string) string {
	if !p.Color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p Picker) render(view []int, filter string) {
	fmt.Fprintln(p.Out)
	if p.Title != "" {
		fmt.Fprintln(p.Out, "  "+p.style("1", p.Title))
		fmt.Fprintln(p.Out)
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
	badgeCol := -1
	if p.Badge && len(p.Rows) > 0 {
		badgeCol = p.Rows[0].ColorCol
		if badgeCol >= 0 && badgeCol < len(widths) {
			widths[badgeCol] += 2 // a badge pads its text by one space each side
		}
	}
	num := len(strconv.Itoa(len(shown)))
	if num < 1 {
		num = 1
	}
	head := make([]string, len(widths))
	rule := make([]string, len(widths))
	for i, h := range p.Header {
		head[i] = pad(h, widths[i])
		rule[i] = strings.Repeat("─", widths[i])
	}
	fmt.Fprintf(p.Out, "  %s  %s\n", p.style("2", pad("#", num)), p.style("1", strings.TrimRight(strings.Join(head, "  "), " ")))
	fmt.Fprintf(p.Out, "  %s  %s\n", p.style("2", strings.Repeat("─", num)), p.style("2", strings.Join(rule, "  ")))
	for n, idx := range shown {
		r := p.Rows[idx]
		parts := make([]string, len(widths))
		for i := range widths {
			c := ""
			if i < len(r.Cells) {
				c = r.Cells[i]
			}
			switch {
			case i == badgeCol:
				parts[i] = p.badge(r.Color, c, widths[i])
			case i == r.ColorCol && !p.Badge && p.Color:
				parts[i] = Paint(r.Color, pad(c, widths[i]))
			case r.CellColor[i] != "" && p.Color:
				parts[i] = Paint(r.CellColor[i], pad(c, widths[i]))
			default:
				parts[i] = pad(c, widths[i])
			}
		}
		fmt.Fprintf(p.Out, "  %s  %s\n", p.style("2", fmt.Sprintf("%*d", num, n+1)), strings.TrimRight(strings.Join(parts, "  "), " "))
	}
	if more := len(view) - len(shown); more > 0 {
		fmt.Fprintf(p.Out, "  %s\n", p.style("2", fmt.Sprintf("… %d more — type to filter", more)))
	}
	fmt.Fprintln(p.Out)
	if filter != "" {
		fmt.Fprintf(p.Out, "  filter: %q (%d of %d)\n", filter, len(view), len(p.Rows))
	}
	if p.Legend != "" {
		fmt.Fprintln(p.Out, "  "+p.Legend)
	}
}

// badge renders text as a coloured block of width w; without colour it is
// the text, padded, so columns still line up.
func (p Picker) badge(hex, text string, w int) string {
	label := " " + strings.ToUpper(text) + " "
	if !p.Color || text == "" {
		return pad(" "+strings.ToUpper(text), w)
	}
	return Badge(hex, label) + strings.Repeat(" ", w-utf8.RuneCountInString(label))
}

func pad(s string, w int) string {
	return s + strings.Repeat(" ", max(0, w-utf8.RuneCountInString(s)))
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

// Badge renders s on a background of hex, with black or white text,
// whichever reads better on it; an invalid colour leaves s unchanged.
func Badge(hex, s string) string {
	r, g, b, ok := RGB(hex)
	if !ok {
		return s
	}
	// Whichever of near-black and white has the higher WCAG contrast ratio
	// against the background.
	bg := luminance(r, g, b)
	fg := "255;255;255"
	if (bg+0.05)/(luminance(15, 27, 45)+0.05) >= (1.05)/(bg+0.05) {
		fg = "15;27;45"
	}
	return fmt.Sprintf("\x1b[1;48;2;%d;%d;%d;38;2;%sm%s\x1b[0m", r, g, b, fg, s)
}

// luminance is WCAG 2 relative luminance of an sRGB colour.
func luminance(r, g, b int) float64 {
	lin := func(c int) float64 {
		v := float64(c) / 255
		if v <= 0.04045 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(r) + 0.7152*lin(g) + 0.0722*lin(b)
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
