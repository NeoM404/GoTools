package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/httpx"
)

// latestRelease is what the release pipeline publishes as latest.json next
// to the binaries, at the organisation's releaseUrl.
type latestRelease struct {
	Version  string `json:"version"`
	Download string `json:"download,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// releaseClient fetches latest.json; a seam for tests.
var releaseClient = func() *http.Client { return httpx.Client(8*time.Second, nil) }

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// semver parses the leading vX.Y.Z of a version (git describe adds
// -N-gHASH after it).
func semver(v string) ([3]int, bool) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

func newer(latest, current string) bool {
	l, okL := semver(latest)
	c, okC := semver(current)
	if !okL || !okC {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

func fetchLatest(ctx context.Context, url string) (latestRelease, error) {
	var rel latestRelease
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return rel, err
	}
	resp, err := releaseClient().Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("%s: %s", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rel); err != nil {
		return rel, fmt.Errorf("%s: %w", url, err)
	}
	if _, ok := semver(rel.Version); !ok {
		return rel, fmt.Errorf("%s: version %q is not vX.Y.Z", url, rel.Version)
	}
	return rel, nil
}

func cmdVersion(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "also check the organisation's release location for a newer nedctl")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	fmt.Fprintf(stdout, "nedctl %s\n", Version)
	if checkShadow(stderr) {
		if note := shadowNote(ctx); note != "" {
			fmt.Fprintln(stderr, note)
		}
	}
	if !*check {
		return ExitOK
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
	rel, err := fetchLatest(ctx, cfg.ReleaseURL)
	if err != nil {
		fmt.Fprintf(stderr, "checking for updates: %v\n%s", err, networkHint(err))
		return ExitFailure
	}
	switch {
	case newer(rel.Version, Version):
		fmt.Fprintf(stdout, "nedctl %s is available", rel.Version)
		if rel.Notes != "" {
			fmt.Fprintf(stdout, " — %s", rel.Notes)
		}
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "update with:  nedctl update   (it installs only a release signed by the bank)")
		if rel.Download != "" {
			fmt.Fprintf(stdout, "or download: %s, check it with  nedctl verify FILE,  then run its  setup\n", rel.Download)
		}
	case func() bool { _, ok := semver(Version); return !ok }():
		fmt.Fprintf(stdout, "development build; the latest release is %s\n", rel.Version)
	default:
		fmt.Fprintln(stdout, "up to date")
	}
	return ExitOK
}

// checkShadow turns shadowNote on: at a terminal, or in tests.
var checkShadow = func(stderr io.Writer) bool { return colorOn(stderr) }

// shadowNote says when the nedctl that is running is not the one on PATH —
// typically an older shell function or alias (from a hand-added
// `prompt init` line) still calling a dev build after setup installed a
// release. It names both and their versions.
func shadowNote(ctx context.Context) string {
	if os.Getenv("NEDCTL_NO_SHADOW_CHECK") != "" {
		return ""
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	self, _ = filepath.EvalSymlinks(self)
	onPath, err := exec.LookPath("nedctl")
	if err != nil {
		return ""
	}
	real, _ := filepath.EvalSymlinks(onPath)
	if real == "" || real == self {
		return ""
	}
	other := "unknown version"
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, real, "version") //nolint:gosec // the nedctl on PATH, asked only its version
	cmd.Env = append(os.Environ(), "NEDCTL_NO_SHADOW_CHECK=1")
	if out, err := cmd.Output(); err == nil {
		other = strings.TrimPrefix(strings.TrimSpace(string(out)), "nedctl ")
	}
	return fmt.Sprintf("⚠ the nedctl on your PATH is %s (%s), but this is %s (%s).\n"+
		"  Something — usually an older `prompt init` line in ~/.bashrc, or a terminal opened before setup — runs this one instead.\n"+
		"  Open a new terminal; if it persists, run setup again (it offers to disable old lines) or check ~/.bashrc.",
		real, other, self, Version)
}
