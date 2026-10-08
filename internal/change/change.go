// Package change verifies change records before production access: that the
// record exists, is approved, is in an implementable state, and that now is
// inside its planned window. The ServiceNow Table API is the supported source.
package change

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultPattern matches ServiceNow change numbers (CHG + 7 digits).
const DefaultPattern = `^CHG\d{7}$`

// DefaultAllowedStates are the change states in which work may proceed.
var DefaultAllowedStates = []string{"Scheduled", "Implement"}

// ValidateFormat checks a change number against pattern (DefaultPattern when
// empty) before any network call.
func ValidateFormat(number, pattern string) error {
	if pattern == "" {
		pattern = DefaultPattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("changeControl.pattern: %w", err)
	}
	if !re.MatchString(number) {
		return fmt.Errorf("change record %q does not match the expected format %s", number, pattern)
	}
	return nil
}

// Record is the subset of a change request nedctl checks.
type Record struct {
	Number      string `json:"number"`
	State       string `json:"state"`
	Approval    string `json:"approval"`
	WindowStart string `json:"windowStart"` // UTC
	WindowEnd   string `json:"windowEnd"`   // UTC
	Summary     string `json:"summary,omitempty"`
}

// Rejection is a change record that exists but does not permit access now.
// It is distinct from an error reaching ServiceNow.
type Rejection struct {
	Number, Reason string
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("change record %s does not permit access: %s", r.Number, r.Reason)
}

// ServiceNow checks change requests through the Table API.
type ServiceNow struct {
	Instance      string // https://<instance>.service-now.com
	Token         string // from the environment; never stored in config
	Scheme        string // Authorization scheme; default "Bearer"
	AllowedStates []string
	Timeout       time.Duration
	Client        *http.Client // optional; tests inject one
}

func (s *ServiceNow) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{
		Timeout:   s.Timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https URL %q", req.URL.String())
			}
			return nil
		},
	}
}

// field is a Table API value under sysparm_display_value=all.
type field struct {
	DisplayValue string `json:"display_value"`
	Value        string `json:"value"`
}

// ServiceNow's internal date format, always UTC in the "value" member.
const snowTime = "2006-01-02 15:04:05"

// Check fetches number and verifies it permits access at now. A *Rejection
// means the record says no; any other error means it could not be checked.
func (s *ServiceNow) Check(ctx context.Context, number string, now time.Time) (Record, error) {
	q := url.Values{}
	q.Set("sysparm_query", "number="+number)
	q.Set("sysparm_fields", "number,state,approval,start_date,end_date,short_description")
	// "all" returns each field as {display_value, value}; dates in "value" are
	// UTC in a fixed format, independent of the API user's locale settings.
	q.Set("sysparm_display_value", "all")
	q.Set("sysparm_exclude_reference_link", "true")
	q.Set("sysparm_limit", "2")
	endpoint := strings.TrimRight(s.Instance, "/") + "/api/now/table/change_request?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Record{}, err
	}
	req.Header.Set("Accept", "application/json")
	scheme := s.Scheme
	if scheme == "" {
		scheme = "Bearer"
	}
	req.Header.Set("Authorization", scheme+" "+s.Token)

	resp, err := s.client().Do(req)
	if err != nil {
		return Record{}, fmt.Errorf("querying ServiceNow: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Record{}, fmt.Errorf("reading ServiceNow response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Record{}, fmt.Errorf("ServiceNow returned %s", resp.Status)
	}
	var doc struct {
		Result []map[string]field `json:"result"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return Record{}, fmt.Errorf("parsing ServiceNow response: %w", err)
	}
	switch len(doc.Result) {
	case 0:
		return Record{}, &Rejection{Number: number, Reason: "no such change request"}
	case 1:
	default:
		return Record{}, &Rejection{Number: number, Reason: "the number matches more than one change request"}
	}
	r := doc.Result[0]
	rec := Record{
		Number: r["number"].Value, State: r["state"].DisplayValue, Approval: r["approval"].Value,
		WindowStart: r["start_date"].Value, WindowEnd: r["end_date"].Value, Summary: r["short_description"].DisplayValue,
	}
	return rec, s.permits(rec, r["state"], now)
}

func (s *ServiceNow) permits(rec Record, state field, now time.Time) error {
	reject := func(format string, a ...any) error {
		return &Rejection{Number: rec.Number, Reason: fmt.Sprintf(format, a...)}
	}
	if !strings.EqualFold(rec.Approval, "approved") {
		return reject("approval is %q, not approved", rec.Approval)
	}
	allowed := s.AllowedStates
	if len(allowed) == 0 {
		allowed = DefaultAllowedStates
	}
	ok := false
	for _, a := range allowed {
		if strings.EqualFold(a, state.DisplayValue) || a == state.Value {
			ok = true
		}
	}
	if !ok {
		return reject("state is %q; access needs one of %s", state.DisplayValue, strings.Join(allowed, ", "))
	}
	start, errS := time.Parse(snowTime, rec.WindowStart)
	end, errE := time.Parse(snowTime, rec.WindowEnd)
	if errS != nil || errE != nil {
		return reject("it has no planned start and end date")
	}
	t := now.UTC()
	if t.Before(start) {
		return reject("its window opens at %s UTC", rec.WindowStart)
	}
	if !t.Before(end) {
		return reject("its window closed at %s UTC", rec.WindowEnd)
	}
	return nil
}

// IsRejection reports whether err is a *Rejection.
func IsRejection(err error) bool {
	var r *Rejection
	return errors.As(err, &r)
}
