package app

import (
	"fmt"
	"io"
	"os"

	"nedctl/internal/picker"
)

// Windows Terminal has no command to recolour a running tab, but it
// implements DECAC (CSI 2 ; fg ; bg , |): "assign colour item 2" — the
// window frame, which Windows Terminal draws as the tab — to entries of the
// 256-colour palette. nedctl picks the xterm palette entry nearest the
// environment's colour, so no palette entry is redefined and nothing else
// on screen changes colour. A tab opened with an explicit --tabColor (as
// `--tab` does) keeps that colour; Windows Terminal gives it precedence.

// xterm256 returns the colour of xterm palette entry i (16–255): the 6×6×6
// cube, then 24 greys. Windows Terminal uses these standard values.
func xterm256(i int) (r, g, b int) {
	if i >= 232 {
		v := 8 + 10*(i-232)
		return v, v, v
	}
	level := func(n int) int {
		if n == 0 {
			return 0
		}
		return 55 + 40*n
	}
	i -= 16
	return level(i / 36), level(i / 6 % 6), level(i % 6)
}

// nearestXterm256 is the palette entry (16–255) closest to #rrggbb.
func nearestXterm256(hex string) (int, bool) {
	r, g, b, ok := picker.RGB(hex)
	if !ok {
		return 0, false
	}
	best, bestD := 16, 1<<31-1
	for i := 16; i < 256; i++ {
		pr, pg, pb := xterm256(i)
		if d := (pr-r)*(pr-r) + (pg-g)*(pg-g) + (pb-b)*(pb-b); d < bestD {
			best, bestD = i, d
		}
	}
	return best, true
}

// tabColorSeq is the escape that colours the Windows Terminal tab, or ""
// outside Windows Terminal or for an invalid colour. Foreground is white
// (15); Windows Terminal picks a readable tab text colour itself.
func tabColorSeq(hex string) string {
	if os.Getenv("WT_SESSION") == "" {
		return ""
	}
	idx, ok := nearestXterm256(hex)
	if !ok {
		return ""
	}
	return fmt.Sprintf("\x1b[2;15;%d,|", idx)
}

// colorTab colours this terminal's tab now, when w is a Windows Terminal.
func colorTab(w io.Writer, hex string) {
	if seq := tabColorSeq(hex); seq != "" && colorOn(w) {
		fmt.Fprint(w, seq)
	}
}
