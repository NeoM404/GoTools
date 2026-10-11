package ui

import (
	"bytes"
	"strings"
	"testing"
)

func TestPlainStylesAreUnchanged(t *testing.T) {
	s := Style{}
	if s.Bold("x") != "x" || s.Fg(Red, "x") != "x" || s.OK("done") != "✔ done" || s.Hint("run it") != "→ run it" {
		t.Fatal("styles must be plain without colour")
	}
}

func TestTableAlignsColouredCells(t *testing.T) {
	var b bytes.Buffer
	s := Style{Color: true}
	s.Table(&b, []string{"NAME", "ENV", "NOTE"}, [][]string{
		{"payments", s.Fg(Red, "PROD"), "x"},
		{"lending-long-name", s.Fg(Green, "dev"), "y"},
	})
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%q", b.String())
	}
	// NOTE starts in the same column on every row.
	col := Width(lines[0][:strings.Index(lines[0], "NOTE")])
	for _, l := range lines[2:] {
		plain := ansiRe.ReplaceAllString(l, "")
		if got := Width(plain[:strings.LastIndex(plain, " ")+1]); got != col {
			t.Fatalf("misaligned: %d vs %d\n%s", got, col, b.String())
		}
	}
}
