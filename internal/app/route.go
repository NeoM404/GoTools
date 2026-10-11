package app

import (
	"fmt"
	"io"
	"strings"

	"nedctl/internal/ui"
)

// While a tunnel opens, the path is drawn and a packet travels it:
//
//	you ──────●─▶ payments-devops ────────▶ ⎈ payments-eks-prod
//
// and once open the line turns solid green, so you see which way you are
// connected (through which instance, reusing a tunnel, or direct). Off a
// terminal, or with NEDCTL_REDUCED_MOTION, it is the plain message.

const routeSeg = 8

// routeLine draws the hops; packet is the packet's position along the
// whole path, or -1 for the solid, connected line.
func routeLine(st ui.Style, hops []string, packet int) string {
	var b strings.Builder
	b.WriteString(st.Bold("you") + " ")
	for i, h := range hops {
		seg := []rune(strings.Repeat("─", routeSeg-1) + "▶")
		switch {
		case packet < 0:
			b.WriteString(st.Fg(ui.Green, strings.Repeat("━", routeSeg-1)+"▶"))
		case packet/routeSeg == i:
			pos := packet % routeSeg
			if pos == routeSeg-1 {
				pos-- // keep the arrow head
			}
			b.WriteString(st.Dim(string(seg[:pos])) + st.BoldFg(ui.Blue, "●") + st.Dim(string(seg[pos+1:])))
		default:
			b.WriteString(st.Dim(string(seg)))
		}
		b.WriteString(" " + h)
		if i < len(hops)-1 {
			b.WriteString(" ")
		}
	}
	return b.String()
}

// routeAnim shows the route while a tunnel opens; done says how it ended.
type routeAnim struct {
	w    io.Writer
	st   ui.Style
	hops []string
	sp   *ui.Spinner
}

func showRoute(w io.Writer, msg string, hops ...string) *routeAnim {
	st := ui.Style{Color: colorOn(w)}
	r := &routeAnim{w: w, st: st, hops: hops}
	if !st.Color || reducedMotion() {
		r.sp = working(w, msg)
		return r
	}
	n := len(hops) * routeSeg
	r.sp = st.Animate(w, func(frame int) string {
		return routeLine(st, hops, frame%n) + "  " + st.Dim(msg)
	})
	return r
}

// done stops the animation and, on a terminal, leaves the connected route
// with a note.
func (r *routeAnim) done(ok bool, note string) {
	r.sp.Stop()
	if ok && r.st.Color {
		fmt.Fprintf(r.w, "%s  %s\n", routeLine(r.st, r.hops, -1), r.st.Fg(ui.Green, note))
	}
}

// printRoute shows a connection that needs no opening.
func printRoute(w io.Writer, note string, hops ...string) {
	st := ui.Style{Color: colorOn(w)}
	if st.Color {
		fmt.Fprintf(w, "%s  %s\n", routeLine(st, hops, -1), st.Fg(ui.Green, note))
	}
}
