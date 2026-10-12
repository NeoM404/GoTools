package app

import (
	"io"
	"os"
	"regexp"
	"strings"

	"nedctl/internal/config"
)

// Presenter mode (NEDCTL_PRESENT=1) is for screen-shares, demos and
// recordings: everything nedctl prints has AWS account IDs, IP addresses,
// email addresses and your user names masked. Programs nedctl starts in
// your terminal (a shell, kubectl in it) print for themselves and are not
// masked.

var (
	presentAccount = regexp.MustCompile(`\b\d{8}(\d{4})\b`)
	presentIP      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	presentEmail   = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
)

func presenting() bool { return os.Getenv("NEDCTL_PRESENT") != "" }

// presentWriter masks as it writes; File lets terminal checks see through.
type presentWriter struct {
	w     io.Writer
	users []string
}

func (p *presentWriter) File() *os.File {
	f, _ := asFile(p.w)
	return f
}

func (p *presentWriter) Write(b []byte) (int, error) {
	s := presentMask(string(b), p.users)
	if _, err := io.WriteString(p.w, s); err != nil {
		return 0, err
	}
	return len(b), nil
}

func presentMask(s string, users []string) string {
	s = presentEmail.ReplaceAllString(s, "‹email›")
	s = presentIP.ReplaceAllString(s, "‹ip›")
	s = presentAccount.ReplaceAllString(s, "••••••••$1")
	for _, u := range users {
		if len(u) >= 3 {
			s = strings.ReplaceAll(s, u, "‹user›")
		}
	}
	return s
}

// presentUsers are the names presenter mode hides: this machine's user
// and the configured Azure SSH user.
func presentUsers(cfgPath string) []string {
	var users []string
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			users = append(users, v)
		}
	}
	if cfg, _, err := config.Load(cfgPath); err == nil && cfg.Azure.User != "" {
		users = append(users, cfg.Azure.User)
	}
	return users
}

// asFile is the terminal behind w, seeing through presenter mode.
func asFile(w io.Writer) (*os.File, bool) {
	switch t := w.(type) {
	case *os.File:
		return t, true
	case interface{ File() *os.File }:
		f := t.File()
		return f, f != nil
	}
	return nil, false
}
