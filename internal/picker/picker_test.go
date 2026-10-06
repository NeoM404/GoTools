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

func TestColourOnlyWhenEnabledAndAligned(t *testing.T) {
	_, plain, _ := pick(t, "q\n", false)
	if strings.Contains(plain, "\x1b[") {
		t.Fatal("colour must be off when disabled")
	}
	_, coloured, _ := pick(t, "q\n", true)
	if !strings.Contains(coloured, "\x1b[38;2;239;68;68mprod") {
		t.Fatalf("prod not painted red:\n%q", coloured)
	}
	// Columns line up in plain mode: ACCOUNT starts at the same offset.
	lines := strings.Split(plain, "\n")
	col := strings.Index(lines[0], "ACCOUNT")
	if strings.Index(lines[1], "pay-dev") != col || strings.Index(lines[3], "lend-ete") != col {
		t.Fatalf("misaligned:\n%s", plain)
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
