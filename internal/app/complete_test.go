package app

import (
	"strings"
	"testing"
	"time"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
)

func complete(t *testing.T, cfg string, words ...string) []string {
	t.Helper()
	args := []string{"__complete"}
	if cfg != "" {
		args = []string{"--config", cfg, "__complete"}
	}
	_, out, _ := run(append(args, words...)...)
	return strings.Fields(out)
}

func has(list []string, want ...string) bool {
	set := map[string]bool{}
	for _, v := range list {
		set[v] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestCompletionCommandsFlagsAndValues(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"ku"}, []string{"kube", "kubeconfig"}},
		{[]string{"aws", ""}, []string{"login", "whoami", "env"}},
		{[]string{"kube", "--v"}, []string{"--via", "--via-instance"}},
		{[]string{"kube", "--via", ""}, []string{"auto", "direct", "bastion"}},
		{[]string{"shell", "--via", ""}, []string{"aws", "legacy"}},
		{[]string{"doctor", "-"}, []string{"-o", "--offline", "--strict"}},
		{[]string{"prompt", "init", ""}, []string{"bash", "zsh"}},
		{[]string{"--config", ""}, []string{"__files__"}},
	} {
		if got := complete(t, "", c.words...); !has(got, c.want...) {
			t.Errorf("%q: got %v, want %v", c.words, got, c.want)
		}
	}
	// Only candidates matching what is typed.
	if got := complete(t, "", "aws", "w"); len(got) != 1 || got[0] != "whoami" {
		t.Errorf("aws w: %v", got)
	}
}

func TestCompletionOffersWhatNedctlHasSeen(t *testing.T) {
	w := newEC2World(t, "dev", "")
	// Nothing listed yet: nothing to offer, and no network call.
	if got := complete(t, w.cfg, "shell", ""); len(got) != 0 {
		t.Fatalf("before any listing: %v", got)
	}
	// Listing instances (here, to start one) teaches completion their names.
	if code, _, errb := run("--config", w.cfg, "ec2", "start", "payments-batch", "--yes"); code != ExitOK {
		t.Fatalf("ec2 start: code=%d err=%q", code, errb)
	}
	before := w.awsCalls(t)
	if got := complete(t, w.cfg, "shell", "pay"); !has(got, "payments-batch") {
		t.Fatalf("shell pay<TAB>: %v", got)
	}
	if got := complete(t, w.cfg, "ec2", "stop", ""); !has(got, "payments-batch") {
		t.Fatalf("ec2 stop <TAB>: %v", got)
	}
	if w.awsCalls(t) != before {
		t.Fatal("completion must never call AWS")
	}
	// The sign-in's account list feeds `aws login` words and --profile.
	cfg, _, _ := config.Load(w.cfg)
	saveAssignments(cfg, awssso.Token{ExpiresAt: time.Now()}, []awssso.Assignment{
		{AccountID: "222222222222", AccountName: "payments-dev", Role: "Platform-Admin"},
	})
	if got := complete(t, w.cfg, "aws", "login", ""); !has(got, "payments", "dev", "platform-admin") {
		t.Fatalf("aws login <TAB>: %v", got)
	}
	if got := complete(t, w.cfg, "shell", "--profile", ""); !has(got, "nedctl.payments-dev.Platform-Admin") {
		t.Fatalf("--profile <TAB>: %v", got)
	}
}
