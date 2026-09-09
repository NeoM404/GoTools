package inventory

import (
	"fmt"
	"strconv"
	"strings"
)

// Minor represents a Kubernetes minor version (major, minor) e.g. 1.29.
type Minor struct {
	Major int
	Minor int
}

// ParseMinor parses "1.29", "v1.29", or "1.29.4" into a Minor.
func ParseMinor(s string) (Minor, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return Minor{}, fmt.Errorf("invalid version %q", s)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return Minor{}, fmt.Errorf("invalid major in %q: %w", s, err)
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return Minor{}, fmt.Errorf("invalid minor in %q: %w", s, err)
	}
	return Minor{Major: maj, Minor: min}, nil
}

// MinorsBehind returns how many minor versions `v` is behind `target`
// (0 if equal or ahead). Only meaningful within the same major.
func (v Minor) MinorsBehind(target Minor) int {
	if v.Major != target.Major {
		// Cross-major: treat as far behind so it always surfaces.
		if v.Major < target.Major {
			return 99
		}
		return 0
	}
	if v.Minor >= target.Minor {
		return 0
	}
	return target.Minor - v.Minor
}

// DriftStatus classifies a cluster's version against the fleet target.
type DriftStatus string

const (
	StatusCurrent DriftStatus = "current" // == target or newer
	StatusN1      DriftStatus = "n-1"     // exactly one minor behind (allowed)
	StatusStale   DriftStatus = "STALE"   // two or more behind — must upgrade
	StatusUnknown DriftStatus = "unknown" // version unparseable/missing
)

// Classify compares a cluster version string to the fleet target string.
func Classify(clusterVersion, targetVersion string) DriftStatus {
	if targetVersion == "" || clusterVersion == "" {
		return StatusUnknown
	}
	cv, err1 := ParseMinor(clusterVersion)
	tv, err2 := ParseMinor(targetVersion)
	if err1 != nil || err2 != nil {
		return StatusUnknown
	}
	switch cv.MinorsBehind(tv) {
	case 0:
		return StatusCurrent
	case 1:
		return StatusN1
	default:
		return StatusStale
	}
}
