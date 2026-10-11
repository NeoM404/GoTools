package app

import (
	"bytes"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"nedctl/internal/config"
	"nedctl/internal/ui"
)

// table is what every tabular command writes to: tab-separated lines, then
// Flush. At a terminal it renders a bold header, a dim rule and coloured
// cells — status words with a mark, environments in their colour. Anywhere
// else (a pipe, a file, a script, a test) the output is exactly the plain
// aligned text it has always been, so nothing that parses it breaks.
type table struct {
	out   io.Writer
	buf   bytes.Buffer
	style ui.Style
	plain *tabwriter.Writer
}

func newTable(w io.Writer) *table {
	t := &table{out: w, style: ui.Style{Color: colorOn(w)}}
	if !t.style.Color {
		t.plain = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	}
	return t
}

func (t *table) Write(p []byte) (int, error) {
	if t.plain != nil {
		return t.plain.Write(p)
	}
	return t.buf.Write(p)
}

// Flush renders what was written. A line without tabs ends a block and is
// printed as it is; a block's first row is its header when it is all
// capitals.
func (t *table) Flush() error {
	if t.plain != nil {
		return t.plain.Flush()
	}
	var block [][]string
	render := func() {
		if len(block) == 0 {
			return
		}
		var header []string
		rows := block
		if isHeader(block[0]) {
			header, rows = block[0], block[1:]
		}
		styled := make([][]string, len(rows))
		for i, r := range rows {
			styled[i] = make([]string, len(r))
			for j, c := range r {
				col := ""
				if header != nil && j < len(header) {
					col = header[j]
				}
				styled[i][j] = t.cell(col, c)
			}
		}
		if header != nil {
			t.style.Table(t.out, header, styled)
		} else {
			t.style.Table(t.out, make([]string, maxCols(styled)), styled)
		}
		block = nil
	}
	for _, line := range strings.Split(strings.TrimRight(t.buf.String(), "\n"), "\n") {
		if !strings.Contains(line, "\t") {
			render()
			io.WriteString(t.out, line+"\n")
			continue
		}
		block = append(block, strings.Split(line, "\t"))
	}
	render()
	t.buf.Reset()
	return nil
}

func maxCols(rows [][]string) int {
	n := 0
	for _, r := range rows {
		n = max(n, len(r))
	}
	return n
}

func isHeader(cells []string) bool {
	letters := false
	for _, c := range cells {
		for _, r := range c {
			if unicode.IsLower(r) {
				return false
			}
			letters = letters || unicode.IsLetter(r)
		}
	}
	return letters
}

var defaultColors = config.Config{}

// cell colours one value by its column: status columns get a mark and a
// colour, environment columns their environment's colour.
func (t *table) cell(column, v string) string {
	s := t.style
	switch column {
	case "STATUS", "RESULT", "OUTCOME", "STATE", "DRIFT", "RISK", "ACTION":
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "ok", "success", "current", "running", "in sync", "valid", "api", "supported":
			return s.Fg(ui.Green, "✔ "+v)
		case "missing", "fail", "failed", "failure", "refused", "stale", "at risk", "expired", "eol", "drifted", "shadow", "stopped", "config_map", "move to api_and_config_map":
			return s.Fg(ui.Red, "✖ "+v)
		case "warn", "outdated", "behind", "extended", "pending", "stopping", "api_and_config_map", "incomplete":
			return s.Fg(ui.Amber, "⚠ "+v)
		case "info", "":
			if v == "" {
				return v
			}
			return s.Fg(ui.Grey, "• "+v)
		}
	case "ENV", "ENVIRONMENT":
		if col := defaultColors.ColorFor(v); col != "" {
			return s.Fg(col, v)
		}
	case "REQUIRED":
		return s.Bold(v)
	}
	return v
}
