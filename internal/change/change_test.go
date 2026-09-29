package change

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// snow serves one change request in Table API "display_value=all" shape.
func snow(t *testing.T, approval, stateLabel, stateValue, start, end string, status int) (*ServiceNow, *http.Request) {
	t.Helper()
	var seen http.Request
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = *r
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if !strings.Contains(r.URL.Query().Get("sysparm_query"), "number=CHG0012345") {
			fmt.Fprint(w, `{"result":[]}`)
			return
		}
		fmt.Fprintf(w, `{"result":[{
		  "number":{"display_value":"CHG0012345","value":"CHG0012345"},
		  "state":{"display_value":%q,"value":%q},
		  "approval":{"display_value":"Approved","value":%q},
		  "start_date":{"display_value":"29/09/2026 10:00:00","value":%q},
		  "end_date":{"display_value":"29/09/2026 20:00:00","value":%q},
		  "short_description":{"display_value":"Upgrade payments ingress","value":"Upgrade payments ingress"}}]}`,
			stateLabel, stateValue, approval, start, end)
	}))
	t.Cleanup(srv.Close)
	return &ServiceNow{Instance: srv.URL, Token: "tok", Client: srv.Client()}, &seen
}

var inWindow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func TestApprovedImplementInWindow(t *testing.T) {
	s, seen := snow(t, "approved", "Implement", "-1", "2026-09-29 08:00:00", "2026-09-29 18:00:00", 200)
	rec, err := s.Check(context.Background(), "CHG0012345", inWindow)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != "Implement" || rec.Summary != "Upgrade payments ingress" || rec.WindowEnd != "2026-09-29 18:00:00" {
		t.Fatalf("got %+v", rec)
	}
	q := seen.URL.Query()
	if q.Get("sysparm_display_value") != "all" || seen.URL.Path != "/api/now/table/change_request" {
		t.Fatalf("query: %s", seen.URL)
	}
	if seen.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("auth: %q", seen.Header.Get("Authorization"))
	}
}

func TestRejections(t *testing.T) {
	cases := []struct {
		name, approval, label, value, start, end, want string
	}{
		{"not approved", "requested", "Implement", "-1", "2026-09-29 08:00:00", "2026-09-29 18:00:00", `approval is "requested"`},
		{"wrong state", "approved", "Review", "0", "2026-09-29 08:00:00", "2026-09-29 18:00:00", `state is "Review"`},
		{"window not open", "approved", "Scheduled", "-2", "2026-09-29 13:00:00", "2026-09-29 18:00:00", "window opens at 2026-09-29 13:00:00 UTC"},
		{"window closed", "approved", "Implement", "-1", "2026-09-29 08:00:00", "2026-09-29 12:00:00", "window closed"}, // end is exclusive
		{"no window", "approved", "Implement", "-1", "", "", "no planned start and end"},
	}
	for _, c := range cases {
		s, _ := snow(t, c.approval, c.label, c.value, c.start, c.end, 200)
		_, err := s.Check(context.Background(), "CHG0012345", inWindow)
		if !IsRejection(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestUnknownChangeIsRejected(t *testing.T) {
	s, _ := snow(t, "approved", "Implement", "-1", "2026-09-29 08:00:00", "2026-09-29 18:00:00", 200)
	if _, err := s.Check(context.Background(), "CHG9999999", inWindow); !IsRejection(err) || !strings.Contains(err.Error(), "no such change") {
		t.Fatalf("got %v", err)
	}
}

func TestServiceNowErrorsAreNotRejections(t *testing.T) {
	s, _ := snow(t, "", "", "", "", "", http.StatusUnauthorized)
	_, err := s.Check(context.Background(), "CHG0012345", inWindow)
	if err == nil || IsRejection(err) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an unreachable/unauthorised ServiceNow is an error, not a verdict: %v", err)
	}
}

func TestAllowedStatesByLabelOrValue(t *testing.T) {
	s, _ := snow(t, "approved", "Review", "0", "2026-09-29 08:00:00", "2026-09-29 18:00:00", 200)
	s.AllowedStates = []string{"0"} // by numeric value
	if _, err := s.Check(context.Background(), "CHG0012345", inWindow); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFormat(t *testing.T) {
	if err := ValidateFormat("CHG0012345", ""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"CHG12345", "chg0012345", "INC0012345", "CHG0012345; rm -rf"} {
		if err := ValidateFormat(bad, ""); err == nil {
			t.Errorf("%q should fail the default format", bad)
		}
	}
	if err := ValidateFormat("RFC-42", `^RFC-\d+$`); err != nil {
		t.Fatalf("custom pattern: %v", err)
	}
}
