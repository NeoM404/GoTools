package app

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nedctl/internal/config"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;;[^\x07]*\x07`)

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

func TestBoardFillsInAndFlipsStatus(t *testing.T) {
	clock := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	old := now
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = old })
	var buf bytes.Buffer
	b := newFleetBoard(&buf, config.Config{}, "QA")
	b.cols = func() int { return 200 }
	b.add("qa", []string{"acm-k8s-qa-cluster", "pay-k8s-qa-cluster"})

	frame := func() string {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.frame++
		return plain(strings.Join(b.render(now()), "\n"))
	}
	f := frame()
	for _, want := range []string{"NEDCTL FLEET BOARD", "QA", "0 ok", "2 reading", "acm-k8s-qa-cluster", "pay-k8s-qa-cluster", "·"} {
		if !strings.Contains(f, want) {
			t.Fatalf("waiting board lacks %q:\n%s", want, f)
		}
	}

	b.set(clusterHealth{Environment: "qa", Cluster: "acm-k8s-qa-cluster", Status: "ok", Nodes: "3/3 ready", Version: "1.30.4"})
	clock = clock.Add(100 * time.Millisecond) // mid-flip: not settled yet
	if f = frame(); strings.Contains(f, "acm-k8s-qa-cluster  OK ") {
		t.Fatalf("the status should still be flipping:\n%s", f)
	}
	clock = clock.Add(2 * time.Second)
	f = frame()
	if !regexp.MustCompile(`QA\s+acm-k8s-qa-cluster\s+OK\s+3/3 ready`).MatchString(f) || !strings.Contains(f, "1 ok") || !strings.Contains(f, "1 reading") {
		t.Fatalf("settled board:\n%s", f)
	}

	// Next round: a change is marked, worse in red.
	b.newRound(clock.Add(time.Minute))
	b.set(clusterHealth{Environment: "qa", Cluster: "acm-k8s-qa-cluster", Status: "fail"})
	b.set(clusterHealth{Environment: "qa", Cluster: "pay-k8s-qa-cluster", Status: "warn"})
	clock = clock.Add(2 * time.Second)
	f = frame()
	if !regexp.MustCompile(`acm-k8s-qa-cluster\s+FAIL\s+▼`).MatchString(f) || strings.Contains(f, "pay-k8s-qa-cluster  WARN         ▲") || !strings.Contains(f, "round 1 · next in") {
		t.Fatalf("second round:\n%s", f)
	}
}

func TestBoardWithReducedMotionDoesNotFlip(t *testing.T) {
	t.Setenv("NEDCTL_REDUCED_MOTION", "1")
	var buf bytes.Buffer
	b := newFleetBoard(&buf, config.Config{}, "QA")
	b.cols = func() int { return 200 }
	b.set(clusterHealth{Environment: "qa", Cluster: "c1", Status: "warn"})
	b.mu.Lock()
	f := plain(strings.Join(b.render(now()), "\n"))
	b.mu.Unlock()
	if !strings.Contains(f, "WARN") {
		t.Fatalf("no flipping, straight to the status:\n%s", f)
	}
}

func TestBoardDropsColumnsToFitNarrowTerminals(t *testing.T) {
	var buf bytes.Buffer
	b := newFleetBoard(&buf, config.Config{}, "QA")
	b.cols = func() int { return 60 }
	b.set(clusterHealth{Environment: "qa", Cluster: "acm-k8s-qa-cluster", Status: "ok", Nodes: "3/3 ready", Pods: "40, 0 failing", Workloads: "12, 0 short", Version: "1.30.4 ok"})
	b.mu.Lock()
	lines := b.render(now())
	b.mu.Unlock()
	for _, l := range lines {
		if w := len([]rune(plain(l))); w > 59 && strings.Contains(l, "acm") {
			t.Fatalf("line wider than the terminal (%d): %q", w, plain(l))
		}
	}
}

func TestProbeResultsStreamPerClusterAsTheyFinish(t *testing.T) {
	f := newClusterFixture(t, "", "a-k8s-qa-cluster", "b-k8s-qa-cluster", "c-k8s-qa-cluster")
	for _, c := range []string{"a-k8s-qa-cluster", "b-k8s-qa-cluster", "c-k8s-qa-cluster"} {
		f.answer(t, c, strings.Join(healthProbes[0], " "), `{"gitVersion":"v1.30.4"}`)
	}
	cfg, _, err := config.Load(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var started []string
	got := map[string]clusterOut{}
	sel := clusterSel{env: "qa", sink: &probeSink{
		start:  func(_, _ string, cs []string) { started = append(started, cs...) },
		result: func(co clusterOut) { mu.Lock(); got[co.Cluster] = co; mu.Unlock() },
	}}
	results, code := runProbes(t.Context(), cfg, sel, healthProbes, &bytes.Buffer{})
	if code != ExitOK || len(results) != 3 || len(started) != 3 || len(got) != 3 {
		t.Fatalf("code=%d results=%d started=%v streamed=%d", code, len(results), started, len(got))
	}
	for _, r := range results {
		s := got[r.Cluster]
		if string(s.Outs[0].Out) != string(r.Outs[0].Out) || (s.Outs[1].Err == nil) != (r.Outs[1].Err == nil) {
			t.Fatalf("%s: streamed %+v, final %+v", r.Cluster, s, r)
		}
	}
}

func TestHealthBoardNeedsATerminal(t *testing.T) {
	f := newClusterFixture(t, "", "a-k8s-qa-cluster")
	if code, _, errb := run("--config", f.cfg, "health", "--env", "qa", "--board"); code != ExitUsage || !strings.Contains(errb, "needs a terminal") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	if code, _, errb := run("--config", f.cfg, "health", "--env", "qa", "--watch", "5s"); code != ExitUsage || !strings.Contains(errb, "at least 30s") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
