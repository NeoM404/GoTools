// Package safetext keeps text from clusters and clouds from acting on the
// terminal.
package safetext

import (
	"bytes"
	"io"
	"regexp"
	"strings"
)

// Text that comes from a cluster — log lines, event messages, annotations,
// names a webhook let through — is data, and must never act on the
// terminal. Escape sequences in it can retitle the window, hide or rewrite
// what is shown, plant a link whose text and target differ (OSC 8) or, on
// some terminals, put a command on the clipboard (OSC 52). Text removes
// them before anything is printed; nedctl adds its own colours afterwards.

var (
	// escSeq is one escape sequence: CSI (ESC [ … final), OSC/DCS/APC/PM/SOS
	// strings (ending in BEL or ESC \, or unterminated), or a two-byte escape.
	escSeq = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]?|\x1b[\]PX^_][^\x07\x1b]*(\x07|\x1b\\)?|\x1b[^\[\]PX^_]?|\x9b[0-?]*[ -/]*[@-~]?|[\x9d\x90\x98\x9e\x9f][^\x07\x1b\x9c]*(\x07|\x1b\\|\x9c)?`)
	// jsonCtl is a JSON escape that decodes to a control or bidi character.
	jsonCtl = regexp.MustCompile(`\\u(00[01][0-9a-fA-F]|007[fF]|00[89][0-9a-fA-F]|200[e-fE-F]|202[a-eA-E]|206[6-9])`)
)

// unsafeRune reports a character that is not printable text: C0 and C1
// controls (tab and newline aside) and the bidirectional overrides that
// make text read differently from what it is.
func unsafeRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
		return true
	}
	return false
}

// Text returns s with escape sequences removed and other control
// characters shown as �, keeping tabs and newlines.
func Text(s string) string {
	if !needsCleaning(s) {
		return s
	}
	s = escSeq.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return '�'
		}
		return r
	}, s)
}

func needsCleaning(s string) bool {
	for _, r := range s {
		if unsafeRune(r) {
			return true
		}
	}
	return false
}

// Bytes is Text for kubectl output; JSON escapes that would decode to
// control characters (\u001b…) are neutralised too, so values decoded from
// it are clean as well.
func Bytes(b []byte) []byte {
	if bytes.Contains(b, []byte(`\u`)) {
		b = jsonCtl.ReplaceAll(b, []byte(`�`))
	}
	s := string(b)
	if !needsCleaning(s) {
		return b
	}
	return []byte(Text(s))
}

// Writer cleans a stream line by line before it reaches w.
func Writer(w io.Writer) io.Writer { return &safeWriter{w: w} }

type safeWriter struct {
	w   io.Writer
	buf []byte
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	i := bytes.LastIndexByte(s.buf, '\n')
	if i < 0 {
		if len(s.buf) < 64<<10 {
			return len(p), nil
		}
		i = len(s.buf) - 1 // an endless line: clean what there is
	}
	out := Text(string(s.buf[:i+1]))
	s.buf = append(s.buf[:0], s.buf[i+1:]...)
	if _, err := io.WriteString(s.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Flush writes what remains of an unfinished last line.
func (s *safeWriter) Flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	out := Text(string(s.buf))
	s.buf = s.buf[:0]
	_, err := io.WriteString(s.w, out)
	return err
}
