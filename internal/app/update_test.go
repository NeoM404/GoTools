package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nedctl/internal/release"
)

// releaseWorld serves a signed release of a fake nedctl v9.9.9 over TLS.
type releaseWorld struct {
	cfg, self string
	files     map[string][]byte
	priv      ed25519.PrivateKey
}

func newReleaseWorld(t *testing.T) *releaseWorld {
	t.Helper()
	if goos == "windows" {
		t.Skip("the fake release binary is a shell script")
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	w := &releaseWorld{files: map[string][]byte{}, priv: priv}
	bin := []byte("#!/bin/sh\necho 'nedctl v9.9.9'\n")
	w.files[releaseAsset()] = bin
	h := sha256.Sum256(bin)
	w.files["SHA256SUMS"] = []byte(hex.EncodeToString(h[:]) + "  " + releaseAsset() + "\n")
	w.files["SHA256SUMS.sig"] = release.Sign(priv, w.files["SHA256SUMS"])
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.json" {
			fmt.Fprintf(rw, `{"version": "v9.9.9", "download": "%s/v9.9.9/", "notes": "signed updates"}`, srv.URL)
			return
		}
		data, ok := w.files[strings.TrimPrefix(r.URL.Path, "/v9.9.9/")]
		if !ok {
			http.NotFound(rw, r)
			return
		}
		rw.Write(data)
	}))
	t.Cleanup(srv.Close)
	oldClient, oldKeys, oldSelf, oldV := releaseClient, trustedKeys, selfPath, Version
	t.Cleanup(func() { releaseClient, trustedKeys, selfPath, Version = oldClient, oldKeys, oldSelf, oldV })
	releaseClient = srv.Client
	trustedKeys = func() ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{pub}, nil }
	Version = "v1.2.0"
	dir := t.TempDir()
	w.self = filepath.Join(dir, "nedctl")
	os.WriteFile(w.self, []byte("#!/bin/sh\necho 'nedctl v1.2.0'\n"), 0o755)
	selfPath = func() (string, error) { return w.self, nil }
	w.cfg = filepath.Join(dir, "c.json")
	os.WriteFile(w.cfg, []byte(`{"releaseUrl": "`+srv.URL+`/latest.json", "audit": {"logPath": "`+filepath.Join(dir, "audit.jsonl")+`"}}`), 0o600)
	return w
}

func TestUpdateInstallsASignedRelease(t *testing.T) {
	w := newReleaseWorld(t)
	code, out, errb := run("--config", w.cfg, "update")
	if code != ExitOK || !strings.Contains(out, "v1.2.0 → v9.9.9 — signed updates") || !strings.Contains(errb, "signature and checksum verified") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	if got, _ := os.ReadFile(w.self); string(got) != string(w.files[releaseAsset()]) {
		t.Fatalf("installed: %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(w.self), ".nedctl-update-*")); len(left) != 0 {
		t.Fatalf("download left behind: %v", left)
	}
}

func TestUpdateRefusesWhatIsNotSignedByTheBank(t *testing.T) {
	cases := map[string]func(w *releaseWorld){
		"binary changed after signing": func(w *releaseWorld) {
			w.files[releaseAsset()] = []byte("#!/bin/sh\necho 'nedctl v9.9.9'; curl evil\n")
		},
		"checksums re-signed by another key": func(w *releaseWorld) {
			_, other, _ := ed25519.GenerateKey(nil)
			w.files["SHA256SUMS.sig"] = release.Sign(other, w.files["SHA256SUMS"])
		},
		"no signature": func(w *releaseWorld) { delete(w.files, "SHA256SUMS.sig") },
		"wrong version inside": func(w *releaseWorld) {
			bin := []byte("#!/bin/sh\necho 'nedctl v0.0.1'\n")
			w.files[releaseAsset()] = bin
			h := sha256.Sum256(bin)
			w.files["SHA256SUMS"] = []byte(hex.EncodeToString(h[:]) + "  " + releaseAsset() + "\n")
			w.files["SHA256SUMS.sig"] = release.Sign(w.priv, w.files["SHA256SUMS"])
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			w := newReleaseWorld(t)
			spoil(w)
			before, _ := os.ReadFile(w.self)
			code, _, errb := run("--config", w.cfg, "update")
			if code != ExitFailure {
				t.Fatalf("code=%d err=%q", code, errb)
			}
			if after, _ := os.ReadFile(w.self); string(after) != string(before) {
				t.Fatal("the installed nedctl must be untouched")
			}
		})
	}
}

func TestUpdateWithoutKeysOrWhenCurrent(t *testing.T) {
	w := newReleaseWorld(t)
	trustedKeys = func() ([]ed25519.PublicKey, error) { return nil, nil }
	if code, _, errb := run("--config", w.cfg, "update"); code != ExitFailure || !strings.Contains(errb, "no release signing key") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	Version = "v9.9.9"
	if code, out, _ := run("--config", w.cfg, "update"); code != ExitOK || !strings.Contains(out, "up to date") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	Version = "v1.0.0"
	if code, out, _ := run("--config", w.cfg, "update", "--check"); code != ExitOK || !strings.Contains(out, "→ v9.9.9") {
		t.Fatalf("check: code=%d out=%q", code, out)
	}
}

func TestVerifyADownload(t *testing.T) {
	w := newReleaseWorld(t)
	dir := t.TempDir()
	for name, data := range w.files {
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	file := filepath.Join(dir, releaseAsset())
	if code, out, errb := run("verify", file); code != ExitOK || !strings.Contains(out, "signed by the bank's release key") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
	os.WriteFile(file, []byte("tampered"), 0o755)
	if code, _, errb := run("verify", file); code != ExitFailure || !strings.Contains(errb, "does not match its signed checksum") {
		t.Fatalf("tampered: code=%d err=%q", code, errb)
	}
	os.Remove(filepath.Join(dir, "SHA256SUMS.sig"))
	if code, _, errb := run("verify", file); code != ExitUsage || !strings.Contains(errb, "unsigned release must not be installed") {
		t.Fatalf("unsigned: code=%d err=%q", code, errb)
	}
}

func TestSetupStopsOnABinaryThatFailsVerification(t *testing.T) {
	w := newReleaseWorld(t)
	dir := t.TempDir()
	for name, data := range w.files {
		os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
	self := filepath.Join(dir, releaseAsset())
	selfPath = func() (string, error) { return self, nil }
	if note, err := selfVerification(); err != nil || note != "signature and checksum verified" {
		t.Fatalf("good: %q %v", note, err)
	}
	os.WriteFile(self, []byte("tampered"), 0o755)
	if _, err := selfVerification(); err == nil {
		t.Fatal("a tampered binary must fail")
	}
	code, _, errb := run("--config", w.cfg, "setup", "--yes", "--no-install", "--no-shell")
	if code != ExitFailure || !strings.Contains(errb, "failed verification") {
		t.Fatalf("setup: code=%d err=%q", code, errb)
	}
}
