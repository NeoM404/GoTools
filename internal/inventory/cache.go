package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Source says where a loaded fleet came from, for diagnostics.
type Source struct {
	Kind string        `json:"kind"`          // "url", "cache" or "stale-cache"
	Age  time.Duration `json:"age,omitempty"` // age of the cached copy
	// FetchErr is why a stale copy was used instead of a fresh fetch.
	FetchErr string `json:"fetchError,omitempty"`
}

// LoadURLCached serves an https inventory from a local cache when the cached
// copy is younger than ttl, so latency-sensitive callers (a shell prompt
// running `nedctl guard`) do not hit the network every time.
//
// On a stale or missing cache it fetches; if that fetch fails but any cached
// copy exists, the copy is returned with Kind "stale-cache" and the fetch
// error, rather than failing — a network blip must not disable the guard.
// Cache files are 0600 and written atomically.
func LoadURLCached(raw, cacheDir string, ttl time.Duration) (Fleet, Source, error) {
	return loadURLCached(raw, cacheDir, ttl, LoadURL)
}

// loadURLCached takes the fetcher as a parameter so tests can serve over a
// TLS test server; the https-only guarantee lives in LoadURL itself.
func loadURLCached(raw, cacheDir string, ttl time.Duration, fetch func(string) (Fleet, error)) (Fleet, Source, error) {
	sum := sha256.Sum256([]byte(raw))
	path := filepath.Join(cacheDir, "inventory-"+hex.EncodeToString(sum[:8])+".json")

	info, statErr := os.Stat(path)
	if statErr == nil && time.Since(info.ModTime()) < ttl {
		if f, err := LoadFile(path); err == nil {
			return f, Source{Kind: "cache", Age: time.Since(info.ModTime())}, nil
		}
	}

	f, fetchErr := fetch(raw)
	if fetchErr == nil {
		_ = writeCache(path, f) // best-effort: a cache write failure must not fail the load
		return f, Source{Kind: "url"}, nil
	}
	if statErr == nil {
		if cached, err := LoadFile(path); err == nil {
			return cached, Source{Kind: "stale-cache", Age: time.Since(info.ModTime()), FetchErr: fetchErr.Error()}, nil
		}
	}
	return Fleet{}, Source{}, fetchErr
}

func writeCache(path string, f Fleet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := marshal(f)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".inventory-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// DefaultCacheDir is the per-user cache directory for nedctl.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating cache directory: %w", err)
	}
	return filepath.Join(base, "nedctl"), nil
}
