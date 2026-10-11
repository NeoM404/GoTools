package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestProbeProgressCountsDoneLinesAndKeepsTheRest(t *testing.T) {
	var w bytes.Buffer
	p := &probeProgress{w: &w, total: 4}
	// Lines arrive split across writes, mixed with SSH's own messages.
	for _, chunk := range []string{probeDone + " aks-a 0\n" + probeDone + " ak", "s-b 2\nWarning: Permanently added host\n",
		probeDone + " aks-c 0\n", probeDone + " aks-d 0\n"} {
		if _, err := p.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	p.finish()
	if p.done != 4 || p.failed != 1 {
		t.Fatalf("done %d failed %d, want 4 and 1", p.done, p.failed)
	}
	out := w.String()
	for _, want := range []string{"1/4 clusters read", "4/4 clusters read (1 with errors)"} {
		if !strings.Contains(out, want) {
			t.Errorf("progress missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\r") {
		t.Errorf("no carriage returns when not a terminal:\n%q", out)
	}
	if got := p.other.String(); got != "Warning: Permanently added host\n" {
		t.Errorf("other = %q", got)
	}
}
