// Package redact masks secrets and personal data in text before it is
// shown: tokens (JWT, bearer, AWS, GitHub, Slack, Azure keys and SAS),
// passwords and secrets in key=value or JSON form, credentials in
// connection strings, private keys, payment card numbers (Luhn-checked)
// and South African ID numbers (date- and Luhn-checked). What a log line
// is about stays readable; the value does not.
package redact

import (
	"regexp"
	"strings"
)

const mask = "‹redacted›"

type rule struct {
	re   *regexp.Regexp
	repl func(m []string) string // m: submatches; returns the replacement
}

var rules = []rule{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), func([]string) string { return "‹private key redacted›" }},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), func([]string) string { return "‹jwt redacted›" }},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}`), func(m []string) string { return m[1] + " " + mask }},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), func(m []string) string { return m[1] + "‹redacted›" }},
	{regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,})`), func([]string) string { return "‹token redacted›" }},
	{regexp.MustCompile(`(?i)\b(AccountKey|SharedAccessKey|sig)=([A-Za-z0-9%+/=]{16,})`), func(m []string) string { return m[1] + "=" + mask }},
	// scheme://user:password@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)`), func(m []string) string { return m[1] + mask + m[3] }},
	// key=value, key: value, "key": "value" for secret-sounding keys
	{regexp.MustCompile(`(?i)("?\b[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential)s?"?\s*[:=]\s*"?)([^\s"',;&}]{3,})`), func(m []string) string { return m[1] + mask }},
	// card numbers and SA ID numbers: digits, checked below
	{regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`), digits},
}

// digits masks a run of 13-19 digits that is a payment card number (Luhn)
// or a 13-digit South African ID number (valid date and Luhn); anything
// else (order numbers, timestamps) is left as it is.
func digits(m []string) string {
	s := m[0]
	d := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	switch {
	case len(d) == 13 && saID(d):
		return "‹id number redacted›"
	case len(d) >= 13 && len(d) <= 19 && luhn(d) && cardPrefix(d):
		return "‹card ****" + d[len(d)-4:] + "›"
	}
	return s
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// cardPrefix: the major schemes' leading digits (Visa, Mastercard, Amex,
// Discover, Diners, JCB, UnionPay, Maestro).
func cardPrefix(d string) bool {
	switch d[0] {
	case '2', '3', '4', '5', '6':
		return true
	}
	return false
}

// saID checks YYMMDD, citizenship digit (0 or 1) and the Luhn check digit.
func saID(d string) bool {
	mm := (d[2]-'0')*10 + d[3] - '0'
	dd := (d[4]-'0')*10 + d[5] - '0'
	return mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31 && (d[10] == '0' || d[10] == '1') && luhn(d)
}

// Line masks what a line holds; it returns the line and whether anything
// was masked.
func Line(s string) (string, bool) {
	out := s
	for _, r := range rules {
		out = r.re.ReplaceAllStringFunc(out, func(x string) string {
			return r.repl(r.re.FindStringSubmatch(x))
		})
	}
	return out, out != s
}
