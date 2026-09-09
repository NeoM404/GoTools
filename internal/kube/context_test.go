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

func TestParseExecAPIVersion(t *testing.T) {
	current := []byte(`{"users":[{"name":"u","user":{"exec":{"apiVersion":"client.authentication.k8s.io/v1beta1","command":"aws"}}}]}`)
	if v, err := parseExecAPIVersion(current); err != nil || v != "client.authentication.k8s.io/v1beta1" {
		t.Fatalf("got %q err=%v", v, err)
	}
	// A token-auth user (no exec block) yields empty, not an error.
	token := []byte(`{"users":[{"name":"u","user":{"token":"abc"}}]}`)
	if v, err := parseExecAPIVersion(token); err != nil || v != "" {
		t.Fatalf("token user: got %q err=%v", v, err)
	}
	if _, err := parseExecAPIVersion([]byte("not json")); err == nil {
		t.Fatal("expected error on invalid json")
	}
}

func TestIsDeprecatedExecAPIVersion(t *testing.T) {
	if !IsDeprecatedExecAPIVersion("client.authentication.k8s.io/v1alpha1") {
		t.Fatal("v1alpha1 should be flagged deprecated")
	}
	for _, ok := range []string{"client.authentication.k8s.io/v1beta1", "client.authentication.k8s.io/v1", ""} {
		if IsDeprecatedExecAPIVersion(ok) {
			t.Fatalf("%q should not be flagged", ok)
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
