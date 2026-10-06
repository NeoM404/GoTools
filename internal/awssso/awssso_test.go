package awssso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

func writeToken(t *testing.T, dir, session string, expires time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"accessToken":"tok-secret","expiresAt":%q,"region":"af-south-1","startUrl":"https://d-1.awsapps.com/start"}`, expires.Format(time.RFC3339))
	if err := os.WriteFile(TokenPath(dir, session), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTokenPathMatchesAWSCLINaming(t *testing.T) {
	// The AWS CLI names an sso-session's cache file by the SHA-1 of the
	// session name; sha1("bankctl") is fixed, so this pins the convention.
	if got := filepath.Base(TokenPath("/x", "bankctl")); got != "e0721f7377d8ab9c121e259752704d9f86c899ec.json" {
		t.Fatalf("got %s", got)
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadToken(dir, "bankctl", now, time.Minute); !errors.Is(err, ErrNoToken) {
		t.Fatalf("missing cache: %v", err)
	}
	writeToken(t, dir, "bankctl", now.Add(30*time.Second))
	if _, err := ReadToken(dir, "bankctl", now, time.Minute); !errors.Is(err, ErrNoToken) {
		t.Fatalf("token expiring inside the margin must count as expired: %v", err)
	}
	writeToken(t, dir, "bankctl", now.Add(8*time.Hour))
	tok, err := ReadToken(dir, "bankctl", now, time.Minute)
	if err != nil || tok.AccessToken != "tok-secret" {
		t.Fatalf("tok=%+v err=%v", tok, err)
	}
}

// fakePortal serves ListAccounts/ListAccountRoles in pages of one.
func fakePortal(t *testing.T, roles map[string][]string, names map[string]string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	ids := make([]string, 0, len(names))
	for id := range names {
		ids = append(ids, id)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("x-amz-sso_bearer_token") != "tok-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.Contains(r.URL.RawQuery, "tok-secret") {
			t.Error("the token must travel in a header, never the URL")
		}
		switch r.URL.Path {
		case "/assignment/accounts":
			// sorted so paging is deterministic
			for i := 0; i < len(ids); i++ {
				for j := i + 1; j < len(ids); j++ {
					if ids[j] < ids[i] {
						ids[i], ids[j] = ids[j], ids[i]
					}
				}
			}
			i := 0
			if n := r.URL.Query().Get("next_token"); n != "" {
				fmt.Sscan(n, &i)
			}
			next := ""
			if i+1 < len(ids) {
				next = fmt.Sprint(i + 1)
			}
			fmt.Fprintf(w, `{"accountList":[{"accountId":%q,"accountName":%q}],"nextToken":%q}`, ids[i], names[ids[i]], next)
		case "/assignment/roles":
			id := r.URL.Query().Get("account_id")
			var parts []string
			for _, role := range roles[id] {
				parts = append(parts, fmt.Sprintf(`{"roleName":%q,"accountId":%q}`, role, id))
			}
			fmt.Fprintf(w, `{"roleList":[%s]}`, strings.Join(parts, ","))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestAssignmentsPagesAndSorts(t *testing.T) {
	srv, _ := fakePortal(t,
		map[string][]string{"111111111111": {"Platform-ReadOnly", "Platform-Admin"}, "222222222222": {"Platform-Admin"}},
		map[string]string{"111111111111": "payments-prod", "222222222222": "payments-dev"})
	p := Portal{BaseURL: srv.URL, Client: srv.Client()}
	got, err := p.Assignments(context.Background(), Token{AccessToken: "tok-secret"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Assignment{
		{"222222222222", "payments-dev", "Platform-Admin"},
		{"111111111111", "payments-prod", "Platform-Admin"},
		{"111111111111", "payments-prod", "Platform-ReadOnly"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v", got)
	}
}

func TestAssignmentsRejectedToken(t *testing.T) {
	srv, _ := fakePortal(t, nil, map[string]string{"111111111111": "a"})
	p := Portal{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := p.Assignments(context.Background(), Token{AccessToken: "stale"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("got %v", err)
	}
}

func TestAssignmentsRefusesInvalidRoleName(t *testing.T) {
	srv, _ := fakePortal(t, map[string][]string{"111111111111": {"Admin\n[profile evil]"}}, map[string]string{"111111111111": "a"})
	p := Portal{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := p.Assignments(context.Background(), Token{AccessToken: "tok-secret"}); err == nil || !strings.Contains(err.Error(), "invalid account or role") {
		t.Fatalf("a role name that could inject config must be refused: %v", err)
	}
}

func TestPortalRefusesPlainHTTP(t *testing.T) {
	p := Portal{BaseURL: "http://portal.example"}
	if _, err := p.Assignments(context.Background(), Token{AccessToken: "tok-secret"}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("got %v", err)
	}
}

func TestProfileName(t *testing.T) {
	if got := ProfileName("bankctl", Assignment{AccountID: "111111111111", AccountName: "Payments Prod (ZA)", Role: "Platform-Admin"}); got != "bankctl.Payments-Prod-ZA.Platform-Admin" {
		t.Fatalf("got %q", got)
	}
	if got := ProfileName("bankctl", Assignment{AccountID: "111111111111", Role: "R"}); got != "bankctl.111111111111.R" {
		t.Fatalf("got %q", got)
	}
}

func managed() Managed {
	return Managed{
		Session: Session{Name: "bankctl", StartURL: "https://d-1.awsapps.com/start", Region: "af-south-1"},
		Profiles: map[string]Profile{"bankctl.payments-prod.Platform-ReadOnly": {
			Name: "bankctl.payments-prod.Platform-ReadOnly", AccountID: "111111111111", Role: "Platform-ReadOnly",
			Region: "af-south-1", Squad: "payments", Environment: "prod"}},
	}
}

func TestSaveManagedKeepsOtherProfilesByteForByte(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	theirs := "[default]\nregion = af-south-1\n\n[profile sm-legacy]\nregion = eu-west-1   # hand-written\n"
	if err := os.WriteFile(path, []byte(theirs), 0o640); err != nil {
		t.Fatal(err)
	}
	m := managed()
	if err := SaveManaged(path, m); err != nil {
		t.Fatal(err)
	}
	// Second save with one more profile replaces the block, not appends.
	m.Profiles["bankctl.payments-dev.Platform-Admin"] = Profile{Name: "bankctl.payments-dev.Platform-Admin", AccountID: "222222222222", Role: "Platform-Admin"}
	if err := SaveManaged(path, m); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	if !strings.HasPrefix(text, theirs) {
		t.Fatalf("content outside the block changed:\n%s", text)
	}
	if strings.Count(text, beginMarker) != 1 || strings.Count(text, "[sso-session bankctl]") != 1 {
		t.Fatalf("block duplicated:\n%s", text)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("file mode changed to %v", fi.Mode().Perm())
	}
	got, err := LoadManaged(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Session != m.Session || len(got.Profiles) != 2 || got.Profiles["bankctl.payments-prod.Platform-ReadOnly"] != m.Profiles["bankctl.payments-prod.Platform-ReadOnly"] {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestSaveManagedRefusesSomeoneElsesSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("[sso-session bankctl]\nsso_start_url = https://other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveManaged(path, managed()); err == nil || !strings.Contains(err.Error(), "outside the bankctl section") {
		t.Fatalf("got %v", err)
	}
}

func TestSaveManagedRefusesBrokenBlockAndBadValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(beginMarker+"\n[profile x]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveManaged(path, managed()); err == nil || !strings.Contains(err.Error(), "no end marker") {
		t.Fatalf("got %v", err)
	}
	m := managed()
	m.Session.StartURL = "https://x\n[profile evil]"
	if err := SaveManaged(filepath.Join(t.TempDir(), "c"), m); err == nil {
		t.Fatal("a newline in a value must be refused")
	}
}
