package app

import (
	"strings"
	"testing"
)

func TestHelpOverviewIsGroupedDailyFirst(t *testing.T) {
	_, out, _ := run("help")
	everyday, fleet := strings.Index(out, "EVERYDAY"), strings.Index(out, "FLEET AND INVENTORY")
	if everyday < 0 || fleet < 0 || everyday > fleet || !strings.Contains(out, "kube [eks-cluster]") || !strings.Contains(out, "nedctl help <command>") {
		t.Fatalf("overview:\n%s", out)
	}
}

func TestCommandHelpHasExamplesAndRealFlags(t *testing.T) {
	for _, args := range [][]string{{"help", "kube"}, {"kube", "--help"}, {"kube", "-h"}} {
		code, out, _ := run(args...)
		for _, want := range []string{"nedctl kube [eks-cluster] [flags]", "EXAMPLES", "nedctl kube payments-eks-dev", "FLAGS", "--via MODE", "--profile NAME", "--all-regions"} {
			if code != ExitOK || !strings.Contains(out, want) {
				t.Fatalf("%v: code=%d lacks %q:\n%s", args, code, want, out)
			}
		}
		if strings.Contains(out, "nedctl aws login`") || strings.Contains(out, "-profile nedctl") {
			t.Fatalf("%v: Go's backtick value-name leaked:\n%s", args, out)
		}
	}
	// A --help meant for the program after -- is not nedctl's.
	if _, out, _ := run("kube", "c1", "--", "kubectl", "--help"); strings.Contains(out, "EXAMPLES") {
		t.Fatal("--help after -- belongs to the child command")
	}
	if _, out, _ := run("help", "aws", "login"); !strings.Contains(out, "nedctl aws login lms dev") || !strings.Contains(out, "--device-code") {
		t.Fatalf("aws login help:\n%s", out)
	}
}

func TestBareCommandGroupListsItsSubcommands(t *testing.T) {
	code, _, errb := run("aws")
	if code != ExitUsage || !strings.Contains(errb, "aws whoami") || !strings.Contains(errb, "Who you act as") {
		t.Fatalf("code=%d\n%s", code, errb)
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	for typed, want := range map[string]string{"whoami": "nedctl aws whoami", "kubee": "nedctl kube", "sell": "nedctl shell", "ssh": "nedctl shell"} {
		code, _, errb := run(typed)
		if code != ExitUsage || !strings.Contains(errb, "did you mean: "+want) {
			t.Errorf("%s: code=%d %q", typed, code, errb)
		}
	}
	if _, _, errb := run("zzzzzzzz"); strings.Contains(errb, "did you mean") || !strings.Contains(errb, "nedctl help") {
		t.Errorf("nothing close: %q", errb)
	}
}

func TestStatusScreen(t *testing.T) {
	setupHome(t)
	if _, out, _ := run("status"); !strings.Contains(out, "Start with nedctl setup") {
		t.Fatalf("unconfigured:\n%s", out)
	}
	w := newEC2World(t, "prod", "")
	_, out, _ := run("--config", w.cfg, "status")
	for _, want := range []string{"aws:payments[PROD]", "Platform-Admin", "▲ elevated", "nedctl kube", "nedctl console"} {
		if !strings.Contains(out, want) {
			t.Fatalf("signed in: lacks %q:\n%s", want, out)
		}
	}
}
