package picker

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func rows() []Row {
	return []Row{
		{Cells: []string{"payments", "dev", "pay-dev", "Platform-Admin"}, Color: "#22c55e", ColorCol: 1},
		{Cells: []string{"payments", "prod", "pay-prod", "Platform-ReadOnly"}, Color: "#ef4444", ColorCol: 1},
		{Cells: []string{"lending", "ete", "lend-ete", "Platform-Admin"}, Color: "#f97316", ColorCol: 1},
	}
}

func pick(t *testing.T, input string, color bool) (int, string, error) {
	t.Helper()
	var out bytes.Buffer
	i, err := Picker{Header: []string{"SQUAD", "ENV", "ACCOUNT", "ROLE"}, Rows: rows(), In: strings.NewReader(input), Out: &out, Color: color}.Pick()
	return i, out.String(), err
}

func TestPickByNumber(t *testing.T) {
	if i, _, err := pick(t, "2\n", false); i != 1 || err != nil {
		t.Fatalf("i=%d err=%v", i, err)
	}
}

func TestFilterThenNumberIsWithinTheFilteredView(t *testing.T) {
	i, out, err := pick(t, "payments prod\n1\n", false)
	if i != 1 || err != nil {
		t.Fatalf("i=%d err=%v\n%s", i, err, out)
	}
	if !strings.Contains(out, `filter: "payments prod" (1 of 3)`) {
		t.Fatalf("filter state not shown:\n%s", out)
	}
}

func TestNoMatchAndBadNumberKeepAsking(t *testing.T) {
	i, out, err := pick(t, "zzz\n9\nlending\n1\n", false)
	if i != 2 || err != nil || !strings.Contains(out, `nothing matches "zzz"`) || !strings.Contains(out, "no row 9") {
		t.Fatalf("i=%d err=%v\n%s", i, err, out)
	}
}

func TestQuitAndEOFCancel(t *testing.T) {
	for _, in := range []string{"q\n", ""} {
		if _, _, err := pick(t, in, false); !errors.Is(err, ErrCancelled) {
			t.Fatalf("%q: %v", in, err)
		}
	}
}

func lineWith(t *testing.T, out, sub string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	t.Fatalf("no line contains %q:\n%s", sub, out)
	return ""
}

func TestColourOnlyWhenEnabledAndAligned(t *testing.T) {
	_, plain, _ := pick(t, "q\n", false)
	if strings.Contains(plain, "\x1b[") {
		t.Fatal("colour must be off when disabled")
	}
	_, coloured, _ := pick(t, "q\n", true)
	if !strings.Contains(coloured, "\x1b[38;2;239;68;68mprod") {
		t.Fatalf("prod not painted red:\n%q", coloured)
	}
	// Columns line up in plain mode: ACCOUNT starts at the same offset on
	// the header and on every row.
	col := strings.Index(lineWith(t, plain, "ACCOUNT"), "ACCOUNT")
	for _, v := range []string{"pay-dev", "pay-prod", "lend-ete"} {
		if got := strings.Index(lineWith(t, plain, v), v); col < 0 || got != col {
			t.Fatalf("%s at %d, ACCOUNT at %d:\n%s", v, got, col, plain)
		}
	}
}

func TestBadgesLegendAndCellColour(t *testing.T) {
	rs := rows()
	rs[1].CellColor = map[int]string{3: "#f08a24"}
	var out bytes.Buffer
	_, _ = Picker{Title: "Pick", Header: []string{"SQUAD", "ENV", "ACCOUNT", "ROLE"}, Rows: rs, In: strings.NewReader("q\n"),
		Out: &out, Color: true, Badge: true, Legend: "▲ elevated"}.Pick()
	s := out.String()
	// Text colour is whichever contrasts more: dark on the default palette.
	if !strings.Contains(s, "\x1b[1;48;2;239;68;68;38;2;15;27;45m PROD \x1b[0m") {
		t.Fatalf("prod badge:\n%q", s)
	}
	if !strings.Contains(s, "\x1b[1;48;2;34;197;94;38;2;15;27;45m DEV \x1b[0m") {
		t.Fatalf("dev badge:\n%q", s)
	}
	if !strings.Contains(s, "\x1b[38;2;240;138;36mPlatform-ReadOnly") || !strings.Contains(s, "▲ elevated") {
		t.Fatalf("cell colour or legend missing:\n%q", s)
	}
	// Plain mode keeps badges readable and aligned without escapes.
	var plain bytes.Buffer
	_, _ = Picker{Header: []string{"SQUAD", "ENV", "ACCOUNT", "ROLE"}, Rows: rows(), In: strings.NewReader("q\n"), Out: &plain, Badge: true}.Pick()
	if strings.Contains(plain.String(), "\x1b[") || !strings.Contains(plain.String(), " PROD") {
		t.Fatalf("plain badges:\n%s", plain.String())
	}
	col := strings.Index(lineWith(t, plain.String(), "ACCOUNT"), "ACCOUNT")
	if got := strings.Index(lineWith(t, plain.String(), "lend-ete"), "lend-ete"); got != col {
		t.Fatalf("badge column misaligned: %d vs %d\n%s", got, col, plain.String())
	}
}

func TestBadgeTextContrast(t *testing.T) {
	// A dark background must get white text, a light one dark text.
	if !strings.Contains(Badge("#0f1b2d", "x"), "38;2;255;255;255m") || !strings.Contains(Badge("#fde68a", "x"), "38;2;15;27;45m") {
		t.Fatalf("%q %q", Badge("#0f1b2d", "x"), Badge("#fde68a", "x"))
	}
}

func TestRGB(t *testing.T) {
	if r, g, b, ok := RGB("#ef4444"); !ok || r != 239 || g != 68 || b != 68 {
		t.Fatal(r, g, b, ok)
	}
	if _, _, _, ok := RGB("red"); ok {
		t.Fatal("named colours are not accepted")
	}
}
