package redact

import (
	"strings"
	"testing"
)

func TestLineMasksSecretsAndPersonalData(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123", "Authorization: Bearer ‹redacted›"},
		{"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c ok", "token ‹jwt redacted› ok"},
		{"key AKIAIOSFODNN7EXAMPLE used", "key AKIA‹redacted› used"},
		{`{"password":"hunter22","user":"neo"}`, `{"password":"‹redacted›","user":"neo"}`},
		{"db_password=S3cr3t! host=db", "db_password=‹redacted› host=db"},
		{"client_secret: abc123xyz", "client_secret: ‹redacted›"},
		{"postgres://app:pa55w0rd@db.internal:5432/x", "postgres://app:‹redacted›@db.internal:5432/x"},
		{"paid with 4111 1111 1111 1111 today", "paid with ‹card ****1111› today"},
		{"pan=5555555555554444", "pan=‹card ****4444›"},
		{"customer id 8001015009087 verified", "customer id ‹id number redacted› verified"},
		{"conn AccountKey=Zm9vYmFyYmF6cXV4cXV1eA== end", "conn AccountKey=‹redacted› end"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----", "‹private key redacted›"},
		{"ghp_abcdefghijklmnopqrstuvwxyz0123456789", "‹token redacted›"},
	}
	for _, c := range cases {
		got, changed := Line(c.in)
		if got != c.want || !changed {
			t.Errorf("Line(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestLineLeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"GET /api/v1/payments 200 12ms",
		"order 1234567890123 shipped",          // 13 digits, not Luhn / not an ID
		"ts=1728640000000 level=info",          // epoch millis
		"password reset email sent to user 42", // the word, no value
		"token expired, refreshing",
		"replicas=3 ready=3",
	} {
		if got, changed := Line(in); changed {
			t.Errorf("Line(%q) changed it to %q", in, got)
		}
	}
	if got, _ := Line(strings.Repeat("a", 10000)); len(got) != 10000 {
		t.Error("long lines survive")
	}
}
