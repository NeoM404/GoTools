package httpx

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// The regression: a hand-built http.Transport has no Proxy, so behind a
// corporate proxy every call dials out directly and hangs until timeout.
func TestTransportUsesTheEnvironmentProxy(t *testing.T) {
	tr := Transport()
	if tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("Transport must use http.ProxyFromEnvironment (HTTPS_PROXY / NO_PROXY)")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("Transport must require TLS 1.2 or later")
	}
	if tr.TLSHandshakeTimeout == 0 || tr.DialContext == nil {
		t.Fatal("Transport must keep Go's default dial and handshake timeouts")
	}
}

func TestClientUsesTheConfiguredProxy(t *testing.T) {
	hits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("via proxy"))
	}))
	defer proxy.Close()
	tr := Transport()
	pu, _ := url.Parse(proxy.URL)
	tr.Proxy = http.ProxyURL(pu) // stands in for HTTPS_PROXY, which Go caches per process
	resp, err := (&http.Client{Transport: tr}).Get("http://portal.example.invalid/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits != 1 {
		t.Fatal("the request did not go through the proxy")
	}
}

func TestDebugLogsRouteAndStatusButNoSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer srv.Close()
	var out bytes.Buffer
	c := &http.Client{Transport: &logging{next: Transport(), out: &out}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/assignment/accounts?next_token=SECRET-PAGE", nil)
	req.Header.Set("x-amz-sso_bearer_token", "tok-secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	log := out.String()
	for _, want := range []string{"GET " + srv.URL + "/assignment/accounts via ", "-> 418"} {
		if !strings.Contains(log, want) {
			t.Fatalf("log lacks %q:\n%s", want, log)
		}
	}
	for _, secret := range []string{"tok-secret", "SECRET-PAGE"} {
		if strings.Contains(log, secret) {
			t.Fatalf("debug log leaked %q:\n%s", secret, log)
		}
	}
}

func TestDebugSwitch(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true} {
		t.Setenv("NEDCTL_DEBUG", v)
		if Debug() != want {
			t.Fatalf("NEDCTL_DEBUG=%q: got %v", v, Debug())
		}
	}
}
