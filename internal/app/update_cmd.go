package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/release"
	"nedctl/internal/ui"
)

// `nedctl update` replaces this nedctl with the latest release, but only
// with a binary whose checksum is in a SHA256SUMS signed by a key this
// build trusts; `nedctl verify FILE` checks a downloaded binary the same
// way (from SHA256SUMS and SHA256SUMS.sig next to it), and setup checks
// itself when they are there. A tampered or unsigned binary is refused.

// Limits on what is downloaded.
const (
	maxSumsBytes   = 64 << 10
	maxBinaryBytes = 256 << 20
)

// noReleaseURL is what update and version --check say when the build does
// not know where releases are published.
const noReleaseURL = `This nedctl does not know where releases are published (no releaseUrl in its built-in settings),
so it cannot check for or install updates by itself. To update now:
  1. download the release (the binary with SHA256SUMS and SHA256SUMS.sig)
  2. nedctl verify ./nedctl-linux-amd64      (checks the bank's signature)
  3. ./nedctl-linux-amd64 setup
Maintainers: publishing releases for nedctl update — docs/maintainers/azure-devops.md, "Updates".
`

// releaseAsset is this platform's file in a release.
func releaseAsset() string {
	name := "nedctl-" + goos + "-" + runtime.GOARCH
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// trustedKeys and selfPath are seams for tests.
var (
	trustedKeys = release.Keys
	selfPath    = os.Executable
)

func download(ctx context.Context, rawURL string, limit int64, w io.Writer) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s: releases are only downloaded over https", rawURL)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := releaseClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", rawURL, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("%s: %w", rawURL, err)
	}
	if n > limit {
		return fmt.Errorf("%s: larger than %s — refusing", rawURL, byteSize(limit))
	}
	return nil
}

// verifyRelease checks sig over sums with the built-in keys, and that the
// binary's SHA-256 is the one sums lists for name.
func verifyRelease(sums, sig []byte, name string, binary io.Reader) error {
	keys, err := trustedKeys()
	if err != nil {
		return err
	}
	if err := release.Verify(keys, sums, sig); err != nil {
		return err
	}
	want, err := release.SumFor(sums, name)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, binary); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return fmt.Errorf("%s does not match its signed checksum — it was changed after release; do not run it", name)
	}
	return nil
}

func cmdUpdate(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "only say whether a newer release is out")
	force := fs.Bool("force", false, "install the latest release even when this one is as new")
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(stderr, "usage: nedctl update [--check] [--force]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if cfg.ReleaseURL == "" {
		fmt.Fprint(stderr, noReleaseURL)
		return ExitFailure
	}
	st := ui.Style{Color: colorOn(stderr)}
	sp := spinning(stderr, "Checking for a newer nedctl…")
	rel, err := fetchLatest(ctx, cfg.ReleaseURL)
	sp.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "checking for updates: %v\n%s", err, networkHint(err))
		return ExitFailure
	}
	if !newer(rel.Version, Version) && !*force {
		fmt.Fprintf(stdout, "nedctl %s is up to date\n", Version)
		return ExitOK
	}
	fmt.Fprintf(stdout, "nedctl %s → %s%s\n", Version, rel.Version, ifNonBlank(" — ", rel.Notes))
	if *check {
		return ExitOK
	}
	base := rel.Download
	if base == "" {
		fmt.Fprintln(stderr, "latest.json names no download location — download the release and run its setup")
		return ExitFailure
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	if keys, err := trustedKeys(); err != nil || len(keys) == 0 {
		if err != nil {
			fmt.Fprintln(stderr, err)
			return ExitFailure
		}
		fmt.Fprintln(stderr, release.ErrNoKeys.Error()+" — download the release and run its setup")
		return ExitFailure
	}

	self, err := selfPath()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		fmt.Fprintf(stderr, "finding this nedctl: %v\n", err)
		return ExitFailure
	}
	name := releaseAsset()
	var sums, sig strings.Builder
	sp = working(stderr, "Downloading nedctl "+rel.Version+" ("+name+")…")
	tmp, err := os.CreateTemp(filepath.Dir(self), ".nedctl-update-*")
	if err != nil {
		sp.Stop()
		fmt.Fprintf(stderr, "cannot write next to %s: %v\n", self, err)
		return ExitFailure
	}
	defer os.Remove(tmp.Name())
	err = firstErr(download(ctx, base+"SHA256SUMS", maxSumsBytes, &sums), download(ctx, base+"SHA256SUMS.sig", maxSumsBytes, &sig))
	if err == nil {
		err = download(ctx, base+name, maxBinaryBytes, tmp)
	}
	sp.Stop()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintf(stderr, "downloading: %v\n%s", err, networkHint(err))
		return ExitFailure
	}
	f, err := os.Open(tmp.Name())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	err = verifyRelease([]byte(sums.String()), []byte(sig.String()), name, f)
	f.Close()
	if err != nil {
		fmt.Fprintf(stderr, "%s %v\n", st.Fail("refusing the update:"), err)
		return ExitFailure
	}
	fmt.Fprintln(stderr, st.OK("signature and checksum verified"))
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	// The new binary must run and be the version announced before it
	// replaces this one.
	out, err := exec.CommandContext(ctx, tmp.Name(), "version").Output() //nolint:gosec // the verified release binary
	if err != nil || strings.TrimSpace(string(out)) != "nedctl "+rel.Version {
		fmt.Fprintf(stderr, "%s it reports %q, not nedctl %s\n", st.Fail("refusing the update:"), strings.TrimSpace(string(out)), rel.Version)
		return ExitFailure
	}
	ev := audit.Event{Action: "update", Detail: fmt.Sprintf("nedctl %s → %s (%s, signature verified)", Version, rel.Version, self)}
	tr, err := beginAuditEvent(ctx, cfg, ev, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
		return ExitFailure
	}
	if err := replaceBinary(tmp.Name(), self); err != nil {
		tr.end(ctx, audit.OutcomeFailure, "", err.Error(), stderr)
		fmt.Fprintf(stderr, "installing: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, "", ev.Detail, stderr)
	fmt.Fprintln(stderr, st.OK("nedctl "+rel.Version+" installed at "+self))
	return ExitOK
}

// replaceBinary moves the verified new binary over the running one. A
// running program cannot be overwritten on Windows, but it can be renamed
// out of the way first.
func replaceBinary(newPath, self string) error {
	if goos == "windows" {
		old := self + ".old"
		_ = os.Remove(old)
		if err := os.Rename(self, old); err != nil {
			return err
		}
		if err := os.Rename(newPath, self); err != nil {
			_ = os.Rename(old, self)
			return err
		}
		return nil
	}
	return os.Rename(newPath, self)
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: nedctl verify FILE   (SHA256SUMS and SHA256SUMS.sig must be next to FILE)")
		return ExitUsage
	}
	code, err := verifyFile(args[0])
	st := ui.Style{Color: colorOn(stdout)}
	if err != nil {
		fmt.Fprintln(stderr, st.Fail(err.Error()))
		return code
	}
	fmt.Fprintln(stdout, st.OK(filepath.Base(args[0])+": signed by the bank's release key, checksum matches"))
	return ExitOK
}

// verifyFile checks a downloaded release file against the signed
// SHA256SUMS beside it.
func verifyFile(path string) (int, error) {
	dir := filepath.Dir(path)
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return ExitUsage, fmt.Errorf("no SHA256SUMS next to %s — download it with the release", path)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		return ExitUsage, fmt.Errorf("no SHA256SUMS.sig next to %s — an unsigned release must not be installed", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return ExitFailure, err
	}
	defer f.Close()
	if err := verifyRelease(sums, sig, filepath.Base(path), f); err != nil {
		return ExitFailure, err
	}
	return ExitOK, nil
}

// selfVerification is what setup says about the binary it is installing:
// checked when the signed checksums are next to it (a failure stops setup).
func selfVerification() (string, error) {
	self, err := selfPath()
	if err != nil {
		return "", nil
	}
	dir := filepath.Dir(self)
	if _, err := os.Stat(filepath.Join(dir, "SHA256SUMS.sig")); err != nil {
		return "not checked (no SHA256SUMS.sig next to it)", nil
	}
	if sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS")); err == nil {
		if _, err := release.SumFor(sums, filepath.Base(self)); err != nil {
			return "not checked (renamed from its release name)", nil
		}
	}
	if _, err := verifyFile(self); err != nil {
		if errors.Is(err, release.ErrNoKeys) {
			return "not checked (development build)", nil
		}
		return "", err
	}
	return "signature and checksum verified", nil
}
