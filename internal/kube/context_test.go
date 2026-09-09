package kube

import "testing"

func TestIsProd(t *testing.T) {
	patterns := []string{`(?i)prod`, `(?i)-prd-`}
	cases := map[string]bool{
		"eks-payments-prod-euw1": true,
		"aks-core-PROD-weu":      true,
		"app-prd-cluster":        true,
		"eks-nonprod-euw1":       true, // contains "prod" — intentionally caught (safer to over-warn)
		"eks-sandbox":            false,
		"dev-cluster":            false,
	}
	for name, want := range cases {
		if got := IsProd(name, patterns); got != want {
			t.Errorf("IsProd(%q)=%v want %v", name, got, want)
		}
	}
}

func TestIsProdSkipsInvalidPattern(t *testing.T) {
	// A bad regex must not panic and must not make a prod context look safe.
	if IsProd("prod-x", []string{"(", "(?i)prod"}) != true {
		t.Fatal("valid pattern after invalid one should still match")
	}
	if IsProd("safe", []string{"("}) != false {
		t.Fatal("invalid-only patterns should match nothing")
	}
}
