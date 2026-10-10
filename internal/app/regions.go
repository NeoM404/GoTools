package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/httpx"
)

// Accounts keep their clusters and instances in whatever region the squad
// chose, which is rarely the Identity Center region a profile defaults to.
// Commands therefore search regions instead of trusting the profile:
//
//   - --region R           only R
//   - aws.regions in config only those
//   - otherwise            the account's enabled regions (ec2 describe-regions),
//     narrowed to the regions where something was found last time, so the
//     common case is one or two calls. If the remembered regions turn up
//     nothing, every enabled region is searched again; --all-regions forces it.
//
// What was found where is remembered per account for regionCacheTTL.

const regionCacheTTL = 24 * time.Hour

var awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// regionCache is per account. Active is kept per kind of resource
// ("ec2", "eks"), so finding clusters never narrows where instances are
// looked for.
type regionCache struct {
	Enabled   []string             `json:"enabled"`
	EnabledAt time.Time            `json:"enabledAt"`
	Active    map[string][]string  `json:"active"`
	ActiveAt  map[string]time.Time `json:"activeAt"`
}

func regionCachePath(cfg config.Config, pc profileContext) (string, error) {
	log, err := cfg.AuditLogPath()
	if err != nil {
		return "", err
	}
	key := pc.AccountID
	if key == "" {
		sum := sha256.Sum256([]byte(pc.Name))
		key = hex.EncodeToString(sum[:8])
	}
	return filepath.Join(filepath.Dir(log), "regions", key+".json"), nil
}

func loadRegionCache(cfg config.Config, pc profileContext) regionCache {
	var c regionCache
	if p, err := regionCachePath(cfg, pc); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(data, &c)
		}
	}
	return c
}

func saveRegionCache(cfg config.Config, pc profileContext, c regionCache) {
	p, err := regionCachePath(cfg, pc)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(c); err == nil {
		_ = writeFileAtomic(p, data, 0o600) // best effort: a cache must never fail a command
	}
}

// enabledRegions lists the regions enabled for the account.
func enabledRegions(ctx context.Context, cfg config.Config, pc profileContext, cache *regionCache) ([]string, error) {
	if len(cache.Enabled) > 0 && now().Sub(cache.EnabledAt) < regionCacheTTL {
		return cache.Enabled, nil
	}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "ec2", "describe-regions", "--profile", pc.Name,
		"--query", "Regions[].RegionName", "--output", "json")
	if err != nil {
		return nil, err
	}
	var regions []string
	if err := json.Unmarshal(out, &regions); err != nil {
		return nil, fmt.Errorf("parsing ec2 describe-regions: %w", err)
	}
	for _, r := range regions {
		if !awsRegionRe.MatchString(r) {
			return nil, fmt.Errorf("ec2 returned an invalid region %q", r)
		}
	}
	sort.Strings(regions)
	cache.Enabled, cache.EnabledAt = regions, now()
	return regions, nil
}

// regionSearch is how a command looks across regions.
type regionSearch struct {
	Flag string // --region
	All  bool   // --all-regions
}

func addRegionFlags(fs interface {
	StringVar(*string, string, string, string)
	BoolVar(*bool, string, bool, string)
}, rs *regionSearch) {
	fs.StringVar(&rs.Flag, "region", "", "search only this region (default: found automatically)")
	fs.BoolVar(&rs.All, "all-regions", false, "search every enabled region, not only where things were found before")
}

// regionDenied reports errors that mean "this region is not usable from
// here" (a Control Tower region-deny SCP, an opt-in region), which a search
// skips instead of failing on.
func regionDenied(err error) bool {
	msg := err.Error()
	for _, s := range []string{"AccessDenied", "UnauthorizedOperation", "explicit deny", "AuthFailure", "UnrecognizedClientException", "InvalidClientTokenId", "OptInRequired"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// searchRegions runs find in each region the search covers and returns
// everything it found, with the regions it searched. find must return an
// empty result (not an error) for a region with nothing in it.
func searchRegions[T any](ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, kind string, stderr io.Writer,
	find func(region string) ([]T, error)) ([]T, []string, error) {
	got, searched, err := searchRegionsOnce(ctx, cfg, pc, rs, kind, stderr, find)
	if err == nil {
		rememberNames(cfg, pc, kind, got, rs.Flag != "")
	}
	return got, searched, err
}

func searchRegionsOnce[T any](ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, kind string, stderr io.Writer,
	find func(region string) ([]T, error)) ([]T, []string, error) {
	if rs.Flag != "" {
		if !awsRegionRe.MatchString(rs.Flag) {
			return nil, nil, fmt.Errorf("--region %q is not an AWS region such as af-south-1", rs.Flag)
		}
		got, err := find(rs.Flag)
		return got, []string{rs.Flag}, err
	}
	if len(cfg.AWS.Regions) > 0 {
		return scanRegions(ctx, cfg.AWS.Regions, find)
	}
	cache := loadRegionCache(cfg, pc)
	if cache.Active == nil {
		cache.Active, cache.ActiveAt = map[string][]string{}, map[string]time.Time{}
	}
	if active := cache.Active[kind]; !rs.All && len(active) > 0 && now().Sub(cache.ActiveAt[kind]) < regionCacheTTL {
		got, searched, err := scanRegions(ctx, active, find)
		if err != nil || len(got) > 0 {
			return got, searched, err
		}
		// Nothing where things used to be: look everywhere before concluding.
	}
	all, err := enabledRegions(ctx, cfg, pc, &cache)
	if err != nil {
		region := cfg.AWS.ProfileRegion()
		fmt.Fprintf(stderr, "warning: could not list the account's regions (%v); searching %s only — set aws.regions or pass --region\n", err, region)
		got, err := find(region)
		return got, []string{region}, err
	}
	if httpx.Debug() {
		fmt.Fprintf(stderr, "nedctl debug: searching %d enabled regions\n", len(all))
	}
	got, searched, err := scanRegions(ctx, all, find)
	if err == nil {
		cache.Active[kind], cache.ActiveAt[kind] = activeRegions(got), now()
		saveRegionCache(cfg, pc, cache)
	}
	return got, searched, err
}

// regioned is implemented by results that know their region.
type regioned interface{ regionOf() string }

func activeRegions[T any](items []T) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if r, ok := any(it).(regioned); ok && !seen[r.regionOf()] {
			seen[r.regionOf()] = true
			out = append(out, r.regionOf())
		}
	}
	sort.Strings(out)
	return out
}

// scanRegions calls find in every region, at most six at once. Regions the
// account may not use are skipped; any other failure fails the search, so a
// partial answer is never presented as complete.
func scanRegions[T any](ctx context.Context, regions []string, find func(string) ([]T, error)) ([]T, []string, error) {
	type res struct {
		items []T
		err   error
	}
	results := make([]res, len(regions))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := find(r)
			results[i] = res{items, err}
		}()
	}
	wg.Wait()
	var all []T
	var searched []string
	for i, r := range results {
		if r.err != nil {
			if regionDenied(r.err) {
				continue
			}
			return nil, nil, fmt.Errorf("%s: %w", regions[i], r.err)
		}
		searched = append(searched, regions[i])
		all = append(all, r.items...)
	}
	return all, searched, ctx.Err()
}
