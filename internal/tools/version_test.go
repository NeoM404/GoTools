package tools

import "testing"

func TestParseSemVer(t *testing.T) {
	cases := map[string]struct {
		ok            bool
		maj, min, pat int
	}{
		"v1.30.2":                       {true, 1, 30, 2},
		"Client Version: v1.28.4":       {true, 1, 28, 4},
		"aws-cli/2.15.30 Python/3.11.8": {true, 2, 15, 30},
		`{"azure-cli": "2.60.0"}`:       {true, 2, 60, 0},
		"v3.14":                         {true, 3, 14, 0},
		"no version here":               {false, 0, 0, 0},
	}
	for in, want := range cases {
		got, ok := ParseSemVer(in)
		if ok != want.ok {
			t.Errorf("ParseSemVer(%q) ok=%v want %v", in, ok, want.ok)
			continue
		}
		if ok && (got.Major != want.maj || got.Minor != want.min || got.Patch != want.pat) {
			t.Errorf("ParseSemVer(%q)=%+v want %d.%d.%d", in, got, want.maj, want.min, want.pat)
		}
	}
}

func TestBelow(t *testing.T) {
	v := func(s string) SemVer { x, _ := ParseSemVer(s); return x }
	if !v("1.27.9").Below(v("1.28")) {
		t.Error("1.27.9 should be below 1.28")
	}
	if v("1.30.2").Below(v("1.30")) {
		t.Error("1.30.2 should not be below 1.30")
	}
	if v("2.60.0").Below(v("2.55")) {
		t.Error("2.60 should not be below 2.55")
	}
	if !v("2.13.0").Below(v("2.15")) {
		t.Error("2.13 should be below 2.15")
	}
	if v("1.28").Below(v("1.28")) {
		t.Error("equal versions: not below")
	}
}

func TestInspectOverrideAndPresence(t *testing.T) {
	// A tool that certainly is not installed stays not-found and not-outdated.
	results := Inspect(map[string]string{"kubectl": "99.0"})
	var kubectl *Result
	for i := range results {
		if results[i].Name == "kubectl" {
			kubectl = &results[i]
		}
	}
	if kubectl == nil {
		t.Fatal("kubectl not in catalog results")
	}
	// The override must have been applied.
	if kubectl.MinVersion != "99.0" {
		t.Fatalf("override not applied, MinVersion=%q", kubectl.MinVersion)
	}
	// If kubectl is installed on this machine it must now read as outdated
	// (nothing is >= 99.0); if absent, it's simply not found. Either is valid,
	// but it must never be found-and-current against an impossible floor.
	if kubectl.Found && !kubectl.Outdated {
		t.Fatalf("kubectl found (%s) but not flagged against floor 99.0", kubectl.Detected)
	}
}
