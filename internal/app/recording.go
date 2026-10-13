package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/redact"
	"nedctl/internal/safetext"
	"nedctl/internal/ui"
)

// Recorded sessions. An interactive session inside a workload or node
// (exec, debug pod, debug node, debug attach) in production is recorded:
// everything the session shows — what was typed, as the remote terminal
// echoes it, and what came back — with secrets and personal data redacted
// line by line (passwords typed at a prompt are never echoed, so never
// recorded). The recording is an asciicast v2 file (owner-only, never
// overwritten); its SHA-256 goes into the audit trail's end event, so a
// changed or swapped file is detected (`nedctl audit replay`).
//
// kubectl keeps the real terminal for input (raw mode, Ctrl-C, tab
// completion work as always); its output reaches both the screen and the
// recording. The remote shell starts at the window's size; resizing during
// a recorded session does not reach it.

// recordingMax bounds one recording; beyond it the session continues and
// the recording notes where it stopped.
const recordingMax = 64 << 20

type sessionRecorder struct {
	mu      sync.Mutex
	f       *os.File
	sum     hash.Hash
	w       io.Writer
	start   time.Time
	partial []byte
	written int64
	full    bool
	path    string
}

// recordingDir is where recordings go.
func recordingDir(cfg config.Config) (string, error) {
	if cfg.Recording.Dir != "" {
		return cfg.Recording.Dir, nil
	}
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(log), "sessions"), nil
}

func startRecording(cfg config.Config, id string, meta map[string]any) (*sessionRecorder, error) {
	dir, err := recordingDir(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, now().UTC().Format("20060102T150405Z")+"-"+id+".cast")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	r := &sessionRecorder{f: f, sum: sha256.New(), start: time.Now(), path: path}
	r.w = io.MultiWriter(f, r.sum)
	width, height := 80, 24
	if c, h := termSize(os.Stdout); c > 0 && h > 0 {
		width, height = c, h
	}
	head := map[string]any{"version": 2, "width": width, "height": height, "timestamp": r.start.Unix(), "nedctl": meta}
	b, _ := json.Marshal(head)
	if _, err := r.w.Write(append(b, '\n')); err != nil {
		f.Close()
		return nil, err
	}
	return r, nil
}

// Write records output: complete lines, redacted; a long line without an
// end (a prompt, typing) goes out in 4 KB pieces.
func (r *sessionRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.partial = append(r.partial, p...)
	for {
		i := strings.IndexByte(string(r.partial), '\n')
		if i < 0 {
			if len(r.partial) >= 4<<10 {
				r.event(string(r.partial))
				r.partial = r.partial[:0]
			}
			return len(p), nil
		}
		r.event(string(r.partial[:i+1]))
		r.partial = r.partial[i+1:]
	}
}

func (r *sessionRecorder) event(s string) {
	if r.full || s == "" {
		return
	}
	if clean, changed := redact.Line(s); changed {
		s = clean
	}
	if r.written+int64(len(s)) > recordingMax {
		s, r.full = "\r\n[nedctl: recording stopped at its size limit; the session went on]\r\n", true
	}
	b, _ := json.Marshal([]any{float64(time.Since(r.start).Milliseconds()) / 1000, "o", s})
	n, _ := r.w.Write(append(b, '\n'))
	r.written += int64(n)
}

// Close flushes and returns the file and its SHA-256.
func (r *sessionRecorder) Close() (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.partial) > 0 {
		r.event(string(r.partial))
		r.partial = nil
	}
	err := r.f.Close()
	return r.path, hex.EncodeToString(r.sum.Sum(nil)), err
}

// errNotRecorded: a session that must be recorded could not be.
var errNotRecorded = errors.New("refusing: production sessions are recorded")

// recordSession runs an interactive kubectl, recorded when the
// environment calls for it, and returns what to append to the audit
// detail. A recording that cannot be started stops the session: a
// production session is recorded or does not happen.
func recordSession(ctx context.Context, cfg config.Config, s *kubeSession, prod bool, meta map[string]any, stderr io.Writer, args ...string) (string, error) {
	if !cfg.Recording.Records(prod) {
		return "", s.interactive(ctx, args...)
	}
	id := audit.NewID()
	meta["id"], meta["cluster"], meta["environment"], meta["user"], meta["command"] = id, s.cluster, s.env, currentUser(), "kubectl "+strings.Join(args, " ")
	rec, err := startRecording(cfg, id, meta)
	if err != nil {
		return "", fmt.Errorf("cannot start the session recording (%v) — %w", err, errNotRecorded)
	}
	st := ui.Style{Color: colorOn(stderr)}
	fmt.Fprintf(stderr, "%s %s\n", st.Fail("●"), st.Bold("This session is recorded")+st.Dim(" (redacted; "+rec.path+")"))
	out, errw := io.MultiWriter(os.Stdout, rec), io.MultiWriter(os.Stderr, rec)
	kerr := s.kubectl(ctx, args, childStdin(), out, errw, true)
	path, sum, cerr := rec.Close()
	note := fmt.Sprintf("; recorded %s sha256 %s", filepath.Base(path), sum)
	if cerr != nil {
		note += " (closing the recording failed: " + cerr.Error() + ")"
	}
	fmt.Fprintf(stderr, "%s %s\n", st.Dim("●"), st.Dim("recording saved: "+path))
	return note, kerr
}

// sizedShell is the remote shell command, started at this window's size
// (kubectl cannot pass resizes through a recorded session).
func sizedShell() string {
	shell := "command -v bash >/dev/null 2>&1 && exec bash || exec sh"
	if c, h := termSize(os.Stdout); c > 0 && h > 0 {
		return fmt.Sprintf("stty cols %d rows %d 2>/dev/null; %s", c, h, shell)
	}
	return shell
}

// cmdAuditReplay plays a recording back, after checking it against the
// audit trail.
func cmdAuditReplay(cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	speed := fs.Float64("speed", 1, "playback speed (pauses are capped at 2s)")
	fast := fs.Bool("fast", false, "print it all at once")
	verifyOnly := fs.Bool("verify", false, "only check the recording against the audit trail")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 || *speed <= 0 {
		fmt.Fprintln(stderr, "usage: nedctl audit replay FILE.cast [--speed 2 | --fast] [--verify]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	st := ui.Style{Color: colorOn(stdout)}
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])
	recorded, verr := recordingInTrail(cfg, filepath.Base(pos[0]), hexSum)
	switch {
	case verr != nil:
		fmt.Fprintln(stderr, st.Fail("✖ "+verr.Error()))
		if *verifyOnly {
			return ExitFailure
		}
	default:
		fmt.Fprintln(stderr, st.OK("✔ matches the audit trail: ")+recorded)
	}
	if *verifyOnly {
		return ExitOK
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	if !sc.Scan() {
		fmt.Fprintln(stderr, "not a recording")
		return ExitFailure
	}
	var head struct {
		Timestamp int64          `json:"timestamp"`
		Meta      map[string]any `json:"nedctl"`
	}
	if json.Unmarshal(sc.Bytes(), &head) != nil {
		fmt.Fprintln(stderr, "not a recording")
		return ExitFailure
	}
	fmt.Fprintf(stdout, "%s %v · %v · %v · %s\n%s\n\n", st.Bold("Session"), head.Meta["user"], head.Meta["environment"], head.Meta["cluster"],
		time.Unix(head.Timestamp, 0).UTC().Format("2006-01-02 15:04 UTC"), st.Dim(fmt.Sprint(head.Meta["command"])))
	last := 0.0
	for sc.Scan() {
		var ev []any
		if json.Unmarshal(sc.Bytes(), &ev) != nil || len(ev) != 3 {
			continue
		}
		at, _ := ev[0].(float64)
		text, _ := ev[2].(string)
		if !*fast {
			time.Sleep(time.Duration(min(at-last, 2) / *speed * float64(time.Second)))
		}
		last = at
		// What the session printed is data: cleaned, so a recording cannot
		// act on the reviewer's terminal.
		fmt.Fprint(stdout, safetext.Text(text))
	}
	fmt.Fprintln(stdout)
	return ExitOK
}

// recordingInTrail finds the audit event naming the recording and checks
// its SHA-256.
func recordingInTrail(cfg config.Config, name, sum string) (string, error) {
	path, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	events, _, err := audit.Read(path)
	if err != nil {
		return "", err
	}
	for _, e := range events {
		if !strings.Contains(e.Detail, "recorded "+name+" sha256 ") {
			continue
		}
		if !strings.Contains(e.Detail, "sha256 "+sum) {
			return "", errors.New("the recording does NOT match the SHA-256 in the audit trail: it was changed after the session")
		}
		return fmt.Sprintf("%s by %s on %s at %s", e.Action, e.User, e.Cluster, e.Time), nil
	}
	return "", errors.New("no audit event names this recording (it may come from another machine's trail)")
}
