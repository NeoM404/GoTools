// Package httpx builds the HTTP clients nedctl uses for its own HTTPS calls
// (Identity Center portal, inventory URL, ServiceNow, SIEM). One place, so
// every client behaves the same on a corporate network:
//
//   - Proxy: HTTPS_PROXY / HTTP_PROXY / NO_PROXY from the environment, as
//     the AWS CLI and kubectl use them. Without this a client dials out
//     directly, a corporate firewall silently drops it, and the call hangs
//     until its timeout.
//   - TLS 1.2 or later; the system trust store (on Linux, SSL_CERT_FILE and
//     SSL_CERT_DIR are honoured, for a corporate root CA).
//   - NEDCTL_DEBUG=1 logs each request to stderr: method, URL without its
//     query, the proxy used, status and duration. Headers are never logged,
//     so bearer tokens cannot leak into the log.
package httpx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Transport returns a transport with Go's default dialer, timeouts and
// HTTP/2 support, the environment's proxy, and TLS 1.2 as the floor.
func Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return t
}

// Client returns a client with the given overall timeout. checkRedirect may
// be nil (Go's default policy).
func Client(timeout time.Duration, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
	var rt http.RoundTripper = Transport()
	if Debug() {
		rt = &logging{next: rt.(*http.Transport), out: os.Stderr}
	}
	return &http.Client{Timeout: timeout, Transport: rt, CheckRedirect: checkRedirect}
}

// Debug reports whether NEDCTL_DEBUG asks for request logging.
func Debug() bool {
	v := os.Getenv("NEDCTL_DEBUG")
	return v != "" && v != "0" && v != "false"
}

type logging struct {
	next *http.Transport
	out  io.Writer
}

func (l *logging) RoundTrip(req *http.Request) (*http.Response, error) {
	via := "direct (no proxy configured for this host)"
	if u, err := l.next.Proxy(req); err != nil {
		via = "proxy error: " + err.Error()
	} else if u != nil {
		via = "proxy " + u.Redacted()
	}
	target := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	fmt.Fprintf(l.out, "nedctl debug: %s %s via %s\n", req.Method, target, via)
	start := time.Now()
	resp, err := l.next.RoundTrip(req)
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(l.out, "nedctl debug: %s %s failed after %s: %v\n", req.Method, target, took, err)
		return nil, err
	}
	fmt.Fprintf(l.out, "nedctl debug: %s %s -> %s in %s\n", req.Method, target, resp.Status, took)
	return resp, nil
}
