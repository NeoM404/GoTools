package tools

import "regexp"

// semverRe matches the first "MAJOR.MINOR[.PATCH]" in a string, tolerating a
// leading "v" and surrounding noise (e.g. "aws-cli/2.15.30 Python/3.11").
var semverRe = regexp.MustCompile(`v?(\d+)\.(\d+)(?:\.(\d+))?`)

// SemVer is a coarse version used for floor comparisons. Pre-release and build
// metadata are ignored — we only care whether a CLI meets a minimum.
type SemVer struct {
	Major, Minor, Patch int
}

// ParseSemVer extracts the first version-looking token from s. ok is false if
// none is found.
func ParseSemVer(s string) (SemVer, bool) {
	m := semverRe.FindStringSubmatch(s)
	if m == nil {
		return SemVer{}, false
	}
	v := SemVer{Major: atoi(m[1]), Minor: atoi(m[2])}
	if m[3] != "" {
		v.Patch = atoi(m[3])
	}
	return v, true
}

// Below reports whether v is strictly less than min.
func (v SemVer) Below(min SemVer) bool {
	if v.Major != min.Major {
		return v.Major < min.Major
	}
	if v.Minor != min.Minor {
		return v.Minor < min.Minor
	}
	return v.Patch < min.Patch
}

// atoi parses a known-numeric capture group; it cannot fail given the regex.
func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
