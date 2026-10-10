package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
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
	if !*check {
		return ExitOK
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	if cfg.ReleaseURL == "" {
		fmt.Fprintln(stderr, "no releaseUrl configured: this build cannot check for updates")
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
		if rel.Download != "" {
			fmt.Fprintf(stdout, "download: %s\nthen run its  setup  to install it\n", rel.Download)
		}
	case func() bool { _, ok := semver(Version); return !ok }():
		fmt.Fprintf(stdout, "development build; the latest release is %s\n", rel.Version)
	default:
		fmt.Fprintln(stdout, "up to date")
	}
	return ExitOK
}
