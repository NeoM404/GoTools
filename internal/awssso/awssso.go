// Package awssso lists the AWS accounts and roles an engineer is assigned in
// IAM Identity Center, and maintains the AWS CLI profiles nedctl generates
// for the ones they pick.
//
// Security properties the rest of nedctl relies on:
//   - No AWS access keys pass through nedctl. Sign-in is `aws sso login`
//     (the AWS CLI's own flow), and the profiles written here make the AWS CLI
//     fetch role credentials itself, for one account and role, when used.
//   - The Identity Center access token is read from the AWS CLI's cache only
//     to list assignments, sent only to the Identity Center portal endpoint
//     over TLS 1.2+, in a header, and never written, logged or passed on a
//     command line (where other users could read it from the process list).
//   - The list shows only what Identity Center assigns the engineer. It is a
//     view, not a control: access is enforced by Identity Center and IAM.
package awssso

import (
	"context"
	"crypto/sha1" //nolint:gosec // the AWS CLI names its cache files by SHA-1; not a security use
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nedctl/internal/httpx"
)

// Token is a cached Identity Center access token. AccessToken is a bearer
// secret: keep it in memory, never print it.
type Token struct {
	AccessToken string    `json:"accessToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Region      string    `json:"region"`
	StartURL    string    `json:"startUrl"`
}

// ValidFor reports whether the token is still valid margin from now.
func (t Token) ValidFor(now time.Time, margin time.Duration) bool {
	return t.AccessToken != "" && now.Add(margin).Before(t.ExpiresAt)
}

// ErrNoToken means there is no usable cached sign-in: run `aws sso login`.
var ErrNoToken = errors.New("no valid Identity Center sign-in cached — sign in first")

// CacheDir is where the AWS CLI caches Identity Center tokens.
func CacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "sso", "cache"), nil
}

// TokenPath is the cache file the AWS CLI writes for an sso-session: the
// SHA-1 of the session name.
func TokenPath(dir, session string) string {
	sum := sha1.Sum([]byte(session)) //nolint:gosec // cache file naming, as the AWS CLI does
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

// ReadToken loads the cached token for session, failing with ErrNoToken when
// it is missing, unreadable or expired (within margin).
func ReadToken(dir, session string, now time.Time, margin time.Duration) (Token, error) {
	data, err := os.ReadFile(TokenPath(dir, session))
	if err != nil {
		if os.IsNotExist(err) {
			return Token{}, ErrNoToken
		}
		return Token{}, fmt.Errorf("reading the Identity Center token cache: %w", err)
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return Token{}, fmt.Errorf("parsing the Identity Center token cache: %w", err)
	}
	if !t.ValidFor(now, margin) {
		return Token{}, ErrNoToken
	}
	return t, nil
}

// Assignment is one account + role the engineer may use.
type Assignment struct {
	AccountID   string `json:"accountId"`
	AccountName string `json:"accountName"`
	Role        string `json:"role"`
}

// ErrUnauthorized means Identity Center rejected the token (expired or
// revoked): sign in again.
var ErrUnauthorized = errors.New("the sign-in was rejected by Identity Center (expired or revoked) — sign in again")

// Portal is the Identity Center portal API (ListAccounts, ListAccountRoles).
type Portal struct {
	// BaseURL defaults to https://portal.sso.<Region>.amazonaws.com.
	BaseURL string
	Region  string
	// Concurrency caps role lookups in flight (default 8).
	Concurrency int
	Timeout     time.Duration
	Client      *http.Client
}

// MaxResponseBytes caps one portal response.
const MaxResponseBytes = 4 << 20

func (p Portal) base() string {
	if p.BaseURL != "" {
		return strings.TrimRight(p.BaseURL, "/")
	}
	return "https://portal.sso." + p.Region + ".amazonaws.com"
}

func (p Portal) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	// The bearer token must never follow a redirect off the portal.
	return httpx.Client(timeout, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse })
}

func (p Portal) get(ctx context.Context, tok Token, path string, q url.Values, into any) error {
	u := p.base() + path + "?" + q.Encode()
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("the Identity Center portal URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-amz-sso_bearer_token", tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("calling the Identity Center portal: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("calling the Identity Center portal: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrUnauthorized
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("the Identity Center portal returned %s", resp.Status)
	case len(body) > MaxResponseBytes:
		return fmt.Errorf("the Identity Center portal response exceeds %d MiB", MaxResponseBytes>>20)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("parsing Identity Center portal response: %w", err)
	}
	return nil
}

type account struct {
	ID, Name string
}

func (p Portal) accounts(ctx context.Context, tok Token) ([]account, error) {
	var out []account
	next := ""
	for {
		q := url.Values{"max_result": {"100"}}
		if next != "" {
			q.Set("next_token", next)
		}
		var page struct {
			AccountList []struct {
				AccountID   string `json:"accountId"`
				AccountName string `json:"accountName"`
			} `json:"accountList"`
			NextToken string `json:"nextToken"`
		}
		if err := p.get(ctx, tok, "/assignment/accounts", q, &page); err != nil {
			return nil, err
		}
		for _, a := range page.AccountList {
			out = append(out, account{ID: a.AccountID, Name: a.AccountName})
		}
		if page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

func (p Portal) roles(ctx context.Context, tok Token, accountID string) ([]string, error) {
	var out []string
	next := ""
	for {
		q := url.Values{"account_id": {accountID}, "max_result": {"100"}}
		if next != "" {
			q.Set("next_token", next)
		}
		var page struct {
			RoleList []struct {
				RoleName string `json:"roleName"`
			} `json:"roleList"`
			NextToken string `json:"nextToken"`
		}
		if err := p.get(ctx, tok, "/assignment/roles", q, &page); err != nil {
			return nil, err
		}
		for _, r := range page.RoleList {
			out = append(out, r.RoleName)
		}
		if page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

// Assignments lists every account + role the token's owner is assigned,
// sorted by account name then role. Any failed lookup fails the whole list:
// a partial list would silently hide accounts.
func (p Portal) Assignments(ctx context.Context, tok Token) ([]Assignment, error) {
	accts, err := p.accounts(ctx, tok)
	if err != nil {
		return nil, err
	}
	n := p.Concurrency
	if n <= 0 {
		n = 8
	}
	sem := make(chan struct{}, n)
	results := make([][]string, len(accts))
	errs := make([]error, len(accts))
	var wg sync.WaitGroup
	for i, a := range accts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = p.roles(ctx, tok, a.ID)
		}()
	}
	wg.Wait()
	var out []Assignment
	for i, a := range accts {
		if errs[i] != nil {
			return nil, fmt.Errorf("listing roles in account %s: %w", a.ID, errs[i])
		}
		for _, r := range results[i] {
			if !accountIDRe.MatchString(a.ID) || !roleNameRe.MatchString(r) {
				return nil, fmt.Errorf("the Identity Center portal returned an invalid account or role (%q, %q)", a.ID, r)
			}
			out = append(out, Assignment{AccountID: a.ID, AccountName: a.Name, Role: r})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AccountName != out[j].AccountName {
			return out[i].AccountName < out[j].AccountName
		}
		return out[i].Role < out[j].Role
	})
	return out, nil
}

var (
	accountIDRe = regexp.MustCompile(`^\d{12}$`)
	// roleNameRe is IAM's role-name alphabet; anything else is refused before
	// it reaches a file or a command line.
	roleNameRe = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)
	unsafeRe   = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	// accountTagRe matches a leading "[NONPROD] "-style label, which says
	// nothing a profile name needs.
	accountTagRe = regexp.MustCompile(`^\s*\[[^\]]*\]\s*`)
)

// ProfileName is the AWS CLI profile nedctl writes for an assignment:
// <prefix>.<account name>.<role>, restricted to a safe alphabet.
func ProfileName(prefix string, a Assignment) string {
	name := strings.TrimSpace(accountTagRe.ReplaceAllString(a.AccountName, ""))
	if name == "" {
		name = a.AccountID
	}
	clean := func(s string) string { return strings.Trim(unsafeRe.ReplaceAllString(s, "-"), "-") }
	return clean(prefix) + "." + clean(name) + "." + clean(a.Role)
}
