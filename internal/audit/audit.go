// Package audit records who fetched credentials for which cluster, when,
// under which change record — the attribution trail auditors ask for.
//
// Events go to an append-only JSON Lines file, one event per line. Each event
// carries the hash of the previous one (a hash chain), so editing, removing
// or reordering past events is detectable with Verify. An exclusive file lock
// serialises appends, so concurrent nedctl runs cannot fork the chain.
//
// Honest limits: a user who controls the file can rewrite the whole chain,
// and deleting the most recent events leaves a valid (shorter) chain. The
// chain proves internal consistency; forwarding each event to a SIEM as it is
// written is what makes the record independent of the laptop.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Event is one audit record. An access is two events sharing an ID: "start",
// written before credentials are fetched, and "end", with the outcome. A start
// without an end means the process died or was killed mid-access.
type Event struct {
	ID               string `json:"id"`
	Phase            string `json:"phase"` // start | end
	Time             string `json:"time"`  // RFC 3339, UTC
	Action           string `json:"action"`
	Outcome          string `json:"outcome,omitempty"` // end only: success | failure | refused
	Tool             string `json:"tool"`
	Version          string `json:"version"`
	User             string `json:"user"`
	Host             string `json:"host"`
	Principal        string `json:"principal,omitempty"` // cloud identity acting
	Cluster          string `json:"cluster,omitempty"`
	Cloud            string `json:"cloud,omitempty"`
	Account          string `json:"account,omitempty"`
	Subscription     string `json:"subscription,omitempty"`
	Environment      string `json:"environment,omitempty"`
	Production       bool   `json:"production"`
	ChangeRecord     string `json:"changeRecord,omitempty"`
	ChangeVerified   bool   `json:"changeVerified,omitempty"`
	BreakGlass       bool   `json:"breakGlass,omitempty"`
	BreakGlassReason string `json:"breakGlassReason,omitempty"`
	Detail           string `json:"detail,omitempty"`
	PrevHash         string `json:"prevHash"`
	Hash             string `json:"hash"`
}

// Phases and outcomes.
const (
	PhaseStart     = "start"
	PhaseEnd       = "end"
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeRefused = "refused"
)

// NewID returns a random 128-bit event ID.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("audit: crypto/rand failed: " + err.Error()) // no safe fallback for IDs
	}
	return hex.EncodeToString(b[:])
}

// hash is sha256 over the event's JSON with Hash empty. PrevHash is inside
// that JSON, which is what chains each event to its predecessor.
func hash(e Event) string {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		panic("audit: marshal failed: " + err.Error()) // a plain struct of strings cannot fail
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Log is an append-only, hash-chained audit file.
type Log struct {
	Path string
}

// ErrCorruptTail means the last line of the log is not a valid event, so the
// chain cannot be extended safely.
var ErrCorruptTail = errors.New("audit log tail is corrupt — refusing to append; inspect it with `nedctl audit verify`")

// Append chains e onto the log and writes it durably (fsync) under an
// exclusive lock. It returns the event as written, with its hashes.
func (l Log) Append(e Event) (Event, error) {
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return Event{}, err
	}
	f, err := os.OpenFile(l.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return Event{}, err
	}
	defer f.Close()
	if err := lock(f); err != nil {
		return Event{}, fmt.Errorf("locking audit log: %w", err)
	}
	defer unlock(f)

	prev, err := lastHash(f)
	if err != nil {
		return Event{}, err
	}
	e.PrevHash = prev
	e.Hash = hash(e)
	line, err := json.Marshal(e)
	if err != nil {
		return Event{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Event{}, err
	}
	if err := f.Sync(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// lastHash reads the hash of the final event ("" for an empty log).
func lastHash(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	if size == 0 {
		return "", nil
	}
	const maxTail = 1 << 20 // an event is ~1 KiB; 1 MiB is generous
	n := min(size, maxTail)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if buf[len(buf)-1] != '\n' {
		return "", ErrCorruptTail // a torn final write
	}
	body := buf[:len(buf)-1]
	if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
		body = body[i+1:]
	}
	var e Event
	if err := json.Unmarshal(body, &e); err != nil || e.Hash == "" || e.Hash != hash(e) {
		return "", ErrCorruptTail
	}
	return e.Hash, nil
}

// VerifyResult describes a chain check.
type VerifyResult struct {
	Events   int    `json:"events"`
	OK       bool   `json:"ok"`
	Line     int    `json:"line,omitempty"` // first bad line (1-based)
	Problem  string `json:"problem,omitempty"`
	LastHash string `json:"lastHash,omitempty"`
}

// Verify checks every event's hash and its link to the previous event.
func Verify(path string) (VerifyResult, error) {
	_, res, err := readChecked(path)
	return res, err
}

// Read returns all events after verifying the chain; the VerifyResult says
// whether the chain was intact (events up to the first bad line are returned).
func Read(path string) ([]Event, VerifyResult, error) {
	return readChecked(path)
}

func readChecked(path string) ([]Event, VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, VerifyResult{}, err
	}
	defer f.Close()
	var (
		events []Event
		res    = VerifyResult{OK: true}
		prev   string
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		var e Event
		switch {
		case json.Unmarshal(sc.Bytes(), &e) != nil:
			res.OK, res.Line, res.Problem = false, line, "not a valid event"
		case e.PrevHash != prev:
			res.OK, res.Line, res.Problem = false, line, "chain broken: an event before this line was removed, inserted or reordered"
		case e.Hash != hash(e):
			res.OK, res.Line, res.Problem = false, line, "hash mismatch: this event was modified"
		}
		if !res.OK {
			return events, res, nil
		}
		events = append(events, e)
		prev = e.Hash
		res.Events++
		res.LastHash = e.Hash
	}
	if err := sc.Err(); err != nil {
		return events, res, err
	}
	return events, res, nil
}
