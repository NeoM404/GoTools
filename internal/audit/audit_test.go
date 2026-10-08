package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func ev(cluster string) Event {
	return Event{ID: NewID(), Phase: PhaseStart, Time: time.Now().UTC().Format(time.RFC3339Nano),
		Action: "credentials", Tool: "nedctl", User: "neo", Host: "laptop", Cluster: cluster, Production: true}
}

func logWith(t *testing.T, n int) Log {
	t.Helper()
	l := Log{Path: filepath.Join(t.TempDir(), "state", "audit.jsonl")}
	for i := 0; i < n; i++ {
		if _, err := l.Append(ev("c" + string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func rewrite(t *testing.T, path string, ls []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChainAppendsAndVerifies(t *testing.T) {
	l := logWith(t, 5)
	res, err := Verify(l.Path)
	if err != nil || !res.OK || res.Events != 5 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var first, second Event
	ls := lines(t, l.Path)
	_ = json.Unmarshal([]byte(ls[0]), &first)
	_ = json.Unmarshal([]byte(ls[1]), &second)
	if first.PrevHash != "" || second.PrevHash != first.Hash {
		t.Fatal("events must chain: genesis has no prev, each next points at its predecessor")
	}
	info, _ := os.Stat(l.Path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("audit log must be private, got %o", info.Mode().Perm())
	}
}

func TestVerifyDetectsModification(t *testing.T) {
	l := logWith(t, 4)
	ls := lines(t, l.Path)
	ls[2] = strings.Replace(ls[2], `"cluster":"cc"`, `"cluster":"innocent"`, 1)
	rewrite(t, l.Path, ls)
	res, _ := Verify(l.Path)
	if res.OK || res.Line != 3 || !strings.Contains(res.Problem, "modified") {
		t.Fatalf("got %+v", res)
	}
}

func TestVerifyDetectsRemovalAndReordering(t *testing.T) {
	l := logWith(t, 4)
	ls := lines(t, l.Path)
	rewrite(t, l.Path, append(ls[:1:1], ls[2:]...)) // drop line 2
	if res, _ := Verify(l.Path); res.OK || res.Line != 2 || !strings.Contains(res.Problem, "chain broken") {
		t.Fatalf("removal: %+v", res)
	}
	rewrite(t, l.Path, []string{ls[0], ls[2], ls[1], ls[3]})
	if res, _ := Verify(l.Path); res.OK || res.Line != 2 {
		t.Fatalf("reordering: %+v", res)
	}
}

func TestAppendRefusesCorruptTail(t *testing.T) {
	l := logWith(t, 2)
	f, _ := os.OpenFile(l.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"id":"torn","pha`) // a torn write, no newline
	f.Close()
	if _, err := l.Append(ev("x")); err != ErrCorruptTail {
		t.Fatalf("want ErrCorruptTail, got %v", err)
	}
}

func TestConcurrentAppendsKeepChainIntact(t *testing.T) {
	l := logWith(t, 0)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := l.Append(ev("concurrent")); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	res, err := Verify(l.Path)
	if err != nil || !res.OK || res.Events != 200 {
		t.Fatalf("concurrent appends forked or lost events: %+v err=%v", res, err)
	}
}

func TestForwarderSplunkHEC(t *testing.T) {
	var got struct {
		auth string
		body map[string]any
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got.body)
	}))
	defer srv.Close()
	f := &Forwarder{URL: srv.URL, Token: "hec-token", Scheme: "Splunk", Format: "splunk-hec", client: srv.Client()}
	if err := f.Send(context.Background(), ev("pay-prod")); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Splunk hec-token" || got.body["sourcetype"] != "nedctl:audit" {
		t.Fatalf("auth=%q body=%v", got.auth, got.body)
	}
	if inner, _ := got.body["event"].(map[string]any); inner["cluster"] != "pay-prod" {
		t.Fatalf("event envelope: %v", got.body)
	}
}

func TestRecorderKeepsLocalRecordWhenSIEMDown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	var warn bytes.Buffer
	l := logWith(t, 0)
	r := &Recorder{Log: l, Forward: &Forwarder{URL: srv.URL, Format: "json", client: srv.Client()}, Warn: &warn}
	if _, err := r.Record(context.Background(), ev("pay-prod")); err != nil {
		t.Fatalf("a SIEM outage must not fail the record: %v", err)
	}
	if res, _ := Verify(l.Path); res.Events != 1 {
		t.Fatal("local record missing")
	}
	if !strings.Contains(warn.String(), "503") {
		t.Fatalf("forward failure must be reported: %q", warn.String())
	}
}
