package safetext

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSafeRemovesTerminalControl(t *testing.T) {
	cases := map[string]string{
		"plain line\twith tab\n":                                     "plain line\twith tab\n",
		"\x1b[31mred\x1b[0m text":                                    "red text",
		"title\x1b]0;pwned\x07after":                                 "titleafter",
		"clip\x1b]52;c;cm0gLXJmIH4=\x07board":                        "clipboard",
		"link \x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\": "link click",
		"cursor\x1b[2Aup\x1b[Kclear":                                 "cursorupclear",
		"carriage\rover":                                             "carriage�over",
		"bell\x07":                                                   "bell�",
		"c1 \u009b31mred":                                            "c1 red",
		"bidi \u202egnp.exe":                                              "bidi �gnp.exe",
		"unterminated \x1b]0;title":                                  "unterminated ",
		"lone esc \x1b":                                              "lone esc ",
		"zażółć ⎈ ✔ 日本":                                              "zażółć ⎈ ✔ 日本",
	}
	for in, want := range cases {
		if got := Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSafeBytesNeutralisesJSONEscapes(t *testing.T) {
	in := []byte(`{"message":"Back-off \u001b]52;c;ZWNobyBoaQ==\u0007 restarting","ok":"café ✓"}`)
	var v struct{ Message, Ok string }
	if err := json.Unmarshal(Bytes(in), &v); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(v.Message, "\x1b\x07") || !strings.Contains(v.Message, "restarting") {
		t.Fatalf("decoded message still controls the terminal: %q", v.Message)
	}
	if v.Ok != "café ✓" {
		t.Fatalf("ordinary escapes must survive: %q", v.Ok)
	}
}

func TestSafeWriterCleansAcrossWrites(t *testing.T) {
	var b bytes.Buffer
	w := Writer(&b).(*safeWriter)
	for _, chunk := range []string{"one \x1b]0;", "pwned\x07two\nthree \x1b[", "31mfour"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "one two\nthree four" {
		t.Fatalf("got %q", got)
	}
}
