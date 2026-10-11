package app

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"nedctl/internal/ui"
)

func TestTablePlainIsUnchangedAndStyledIsMarked(t *testing.T) {
	var plain bytes.Buffer
	tw := newTable(&plain) // not a terminal
	fmt.Fprintln(tw, "NAME\tENV\tSTATUS")
	fmt.Fprintln(tw, "payments\tprod\tok")
	tw.Flush()
	if plain.String() != "NAME      ENV   STATUS\npayments  prod  ok\n" {
		t.Fatalf("plain output must stay exactly as before: %q", plain.String())
	}

	var styled bytes.Buffer
	st := &table{out: &styled, style: ui.Style{Color: true}}
	fmt.Fprintln(st, "NAME\tENV\tSTATUS")
	fmt.Fprintln(st, "payments\tprod\tok")
	fmt.Fprintln(st, "lending\tdev\tmissing")
	fmt.Fprintln(st, "a note without tabs")
	st.Flush()
	out := styled.String()
	for _, want := range []string{"─", "✔ ok", "✖ missing", "a note without tabs", "\x1b[1m"} {
		if !strings.Contains(out, want) {
			t.Fatalf("styled lacks %q:\n%s", want, out)
		}
	}
}
