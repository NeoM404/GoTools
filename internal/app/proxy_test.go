package app

import (
	"errors"
	"strings"
	"testing"
)

func TestProxyVariablesThatDisagreeAreReported(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.bank.example:8080")
	t.Setenv("https_proxy", "http://nb000001:s3cret@proxy.bank.example:8080")
	t.Setenv("NO_PROXY", "")
	cs := proxyConsistency()
	if len(cs) != 1 || cs[0].Status != "warn" || !strings.Contains(cs[0].Detail, "HTTPS_PROXY=http://proxy.bank.example:8080") || strings.Contains(cs[0].Detail, "s3cret") {
		t.Fatalf("checks: %+v", cs)
	}
	if h := ssmRouteHint(); !strings.Contains(h, "HTTPS_PROXY and https_proxy differ") || !strings.Contains(h, "--via legacy") {
		t.Fatalf("hint: %q", h)
	}
	t.Setenv("https_proxy", "http://proxy.bank.example:8080")
	if cs := proxyConsistency(); len(cs) != 0 {
		t.Fatalf("the same values are fine: %+v", cs)
	}
}

func TestProxyAuthenticationRequiredIsExplained(t *testing.T) {
	h := networkHint(errors.New(`Get "https://oidc.eu-west-1.amazonaws.com/": Proxy Authentication Required`))
	if !strings.Contains(h, "the proxy wants a login") || !strings.Contains(h, "nedctl doctor") {
		t.Fatalf("hint: %q", h)
	}
}
