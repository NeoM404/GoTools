package ui

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestSpinnerShowsTheLatestMessageAndClears(t *testing.T) {
	var mu sync.Mutex
	var b bytes.Buffer
	w := lockedWriter{&mu, &b}
	sp := Style{Color: true}.Spinner(w, "1/3 done")
	time.Sleep(120 * time.Millisecond)
	sp.Set("2/3 done")
	time.Sleep(200 * time.Millisecond)
	sp.Stop()
	sp.Stop() // twice is fine
	mu.Lock()
	out := b.String()
	mu.Unlock()
	if !strings.Contains(out, "1/3 done") || !strings.Contains(out, "2/3 done") || !strings.HasSuffix(out, "\r\x1b[K") {
		t.Errorf("spinner output = %q", out)
	}
	var none bytes.Buffer
	sp = Style{}.Spinner(&none, "x")
	sp.Set("y")
	sp.Stop()
	if none.Len() != 0 {
		t.Errorf("no terminal, no drawing: %q", none.String())
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
