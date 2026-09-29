package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Forwarder sends each event to a SIEM collector over HTTPS as it is written,
// so the record does not depend on the laptop. Delivery is best-effort: the
// local log is authoritative, and a SIEM outage must never block access.
type Forwarder struct {
	URL     string
	Token   string // from the environment; never stored in config
	Scheme  string // Authorization scheme, e.g. "Bearer" or "Splunk"
	Format  string // "json" (the event) or "splunk-hec" (HEC envelope)
	Timeout time.Duration
	client  *http.Client
}

func (f *Forwarder) httpClient() *http.Client {
	if f.client != nil {
		return f.client
	}
	return &http.Client{
		Timeout:   f.Timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https URL %q", req.URL.String())
			}
			return nil
		},
	}
}

// Send delivers one event.
func (f *Forwarder) Send(ctx context.Context, e Event) error {
	var body any = e
	if f.Format == "splunk-hec" {
		t, _ := time.Parse(time.RFC3339Nano, e.Time)
		body = map[string]any{
			"time": float64(t.UnixNano()) / 1e9, "host": e.Host,
			"source": "bankctl", "sourcetype": "bankctl:audit", "event": e,
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.Token != "" {
		scheme := f.Scheme
		if scheme == "" {
			scheme = "Bearer"
		}
		req.Header.Set("Authorization", scheme+" "+f.Token)
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector returned %s", resp.Status)
	}
	return nil
}

// Recorder writes events to the local log and forwards them.
type Recorder struct {
	Log     Log
	Forward *Forwarder // nil = local only
	// Warn receives forwarding failures (never fatal).
	Warn io.Writer
}

// Record appends e locally — an error here is the caller's to act on, since
// "every access is recorded" depends on it — then forwards it best-effort.
func (r *Recorder) Record(ctx context.Context, e Event) (Event, error) {
	written, err := r.Log.Append(e)
	if err != nil {
		return Event{}, err
	}
	if r.Forward != nil {
		if ferr := r.Forward.Send(ctx, written); ferr != nil && r.Warn != nil {
			fmt.Fprintf(r.Warn, "warning: audit event kept locally but not forwarded to the SIEM: %v\n", ferr)
		}
	}
	return written, nil
}
