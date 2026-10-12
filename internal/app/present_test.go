package app

import (
	"strings"
	"testing"
)

func TestPresentMaskHidesIdentifiers(t *testing.T) {
	in := "acct 123456789012 arn:aws:iam::210987654321:role/x ip 10.243.1.2 by neo.m@bank.example user nb000001 ok"
	got := presentMask(in, []string{"nb000001"})
	for _, leak := range []string{"123456789012", "210987654321", "10.243.1.2", "neo.m@bank.example", "nb000001"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q still shows %q", got, leak)
		}
	}
	if !strings.Contains(got, "••••••••9012") || !strings.Contains(got, "‹ip›") || !strings.Contains(got, "‹email›") || !strings.Contains(got, "‹user›") {
		t.Fatalf("got %q", got)
	}
	if presentMask("version 1.30.4 took 1234ms", nil) != "version 1.30.4 took 1234ms" {
		t.Fatal("ordinary text is untouched")
	}
}

func TestPresenterModeWrapsAllOutput(t *testing.T) {
	w := newAzureWorld(t, `,"azure":{"user":"nb000001","bastions":{"qa":"aks-qa","dev":"nb000001@10.0.0.4"}}`)
	t.Setenv("NEDCTL_PRESENT", "1")
	_, out, errb := run("--config", w.cfg, "azure", "hosts")
	if strings.Contains(out+errb, "10.0.0.4") || strings.Contains(out+errb, "nb000001") {
		t.Fatalf("presenter mode leaks: out=%q err=%q", out, errb)
	}
}
