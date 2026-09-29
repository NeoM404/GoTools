package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func countingFetch(f Fleet, err error) (func(string) (Fleet, error), *int) {
	n := 0
	return func(string) (Fleet, error) { n++; return f, err }, &n
}

var one = Fleet{Clusters: []Cluster{{Name: "c1", Cloud: AWS}}}

func cacheFile(t *testing.T, dir string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "inventory-*.json"))
	if len(m) != 1 {
		t.Fatalf("want one cache file, got %v", m)
	}
	return m[0]
}

func TestCacheServesFreshCopyWithoutFetching(t *testing.T) {
	dir := t.TempDir()
	fetch, n := countingFetch(one, nil)
	if _, src, err := loadURLCached("https://x/fleet.json", dir, time.Hour, fetch); err != nil || src.Kind != "url" {
		t.Fatalf("first load: %+v %v", src, err)
	}
	f, src, err := loadURLCached("https://x/fleet.json", dir, time.Hour, fetch)
	if err != nil || src.Kind != "cache" || *n != 1 || f.Clusters[0].Name != "c1" {
		t.Fatalf("second load must hit cache: src=%+v fetches=%d err=%v", src, *n, err)
	}
	info, _ := os.Stat(cacheFile(t, dir))
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("cache must be private, got %o", perm)
	}
}

func TestCacheRefetchesWhenStale(t *testing.T) {
	dir := t.TempDir()
	fetch, n := countingFetch(one, nil)
	_, _, _ = loadURLCached("https://x/fleet.json", dir, time.Hour, fetch)
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(cacheFile(t, dir), old, old)
	if _, src, err := loadURLCached("https://x/fleet.json", dir, time.Hour, fetch); err != nil || src.Kind != "url" || *n != 2 {
		t.Fatalf("stale cache must refetch: src=%+v fetches=%d err=%v", src, *n, err)
	}
}

func TestStaleCacheUsedWhenFetchFails(t *testing.T) {
	dir := t.TempDir()
	ok, _ := countingFetch(one, nil)
	_, _, _ = loadURLCached("https://x/fleet.json", dir, time.Minute, ok)
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(cacheFile(t, dir), old, old)

	down, _ := countingFetch(Fleet{}, errors.New("connection refused"))
	f, src, err := loadURLCached("https://x/fleet.json", dir, time.Minute, down)
	if err != nil || src.Kind != "stale-cache" || src.FetchErr != "connection refused" || len(f.Clusters) != 1 {
		t.Fatalf("got src=%+v err=%v", src, err)
	}
}

func TestNoCacheAndFetchFailsIsAnError(t *testing.T) {
	down, _ := countingFetch(Fleet{}, errors.New("connection refused"))
	if _, _, err := loadURLCached("https://x/fleet.json", t.TempDir(), time.Minute, down); err == nil {
		t.Fatal("want error")
	}
}

func TestCacheKeyedByURL(t *testing.T) {
	dir := t.TempDir()
	a, _ := countingFetch(one, nil)
	_, _, _ = loadURLCached("https://a/fleet.json", dir, time.Hour, a)
	two := Fleet{Clusters: []Cluster{{Name: "c2", Cloud: AWS}}}
	b, _ := countingFetch(two, nil)
	f, _, _ := loadURLCached("https://b/fleet.json", dir, time.Hour, b)
	if f.Clusters[0].Name != "c2" {
		t.Fatal("a different URL must not be served another URL's cache")
	}
}
