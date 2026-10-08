package awssso

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The AWS CLI config is shared with other tools (sm, SSMshell, hand-written
// profiles). nedctl owns only the lines between these markers and never
// touches anything outside them.
const (
	beginMarker = "# >>> nedctl managed — edits here are overwritten by `nedctl aws login` >>>"
	endMarker   = "# <<< nedctl managed <<<"
)

// Session is an [sso-session] block.
type Session struct {
	Name, StartURL, Region string
}

// Profile is a generated [profile …] block for one account + role.
type Profile struct {
	Name      string
	AccountID string
	Role      string
	Region    string
	// Squad and Environment are recorded as comments, for people reading
	// the file; the AWS CLI ignores them.
	Squad, Environment string
}

// ConfigPath is the AWS CLI config file: $AWS_CONFIG_FILE or ~/.aws/config.
func ConfigPath() (string, error) {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "config"), nil
}

// Managed is the nedctl-owned part of the AWS CLI config.
type Managed struct {
	Session  Session
	Profiles map[string]Profile // by name
}

// split returns the text before the managed block, the block's lines, and
// the text after it.
func split(text string) (before string, block []string, after string, err error) {
	b := strings.Index(text, beginMarker)
	if b < 0 {
		return text, nil, "", nil
	}
	rest := text[b+len(beginMarker):]
	e := strings.Index(rest, endMarker)
	if e < 0 {
		return "", nil, "", fmt.Errorf("the nedctl section of the AWS config has a start marker but no end marker — fix the file by hand")
	}
	after = strings.TrimPrefix(rest[e+len(endMarker):], "\n")
	return text[:b], strings.Split(strings.Trim(rest[:e], "\n"), "\n"), after, nil
}

// LoadManaged reads the managed block (empty when the file or block does not
// exist).
func LoadManaged(path string) (Managed, error) {
	m := Managed{Profiles: map[string]Profile{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return m, err
	}
	_, block, _, err := split(string(data))
	if err != nil {
		return m, err
	}
	var cur *Profile
	inSession := false
	for _, raw := range block {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "[sso-session "):
			m.Session.Name = strings.TrimSuffix(strings.TrimPrefix(line, "[sso-session "), "]")
			inSession, cur = true, nil
		case strings.HasPrefix(line, "[profile "):
			name := strings.TrimSuffix(strings.TrimPrefix(line, "[profile "), "]")
			m.Profiles[name] = Profile{Name: name}
			p := m.Profiles[name]
			cur, inSession = &p, false
		case strings.HasPrefix(line, "#") || line == "":
			if cur != nil {
				if v, ok := strings.CutPrefix(line, "# squad = "); ok {
					cur.Squad = v
				}
				if v, ok := strings.CutPrefix(line, "# environment = "); ok {
					cur.Environment = v
				}
				m.Profiles[cur.Name] = *cur
			}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch {
			case inSession && k == "sso_start_url":
				m.Session.StartURL = v
			case inSession && k == "sso_region":
				m.Session.Region = v
			case cur != nil:
				switch k {
				case "sso_account_id":
					cur.AccountID = v
				case "sso_role_name":
					cur.Role = v
				case "region":
					cur.Region = v
				}
				m.Profiles[cur.Name] = *cur
			}
		}
	}
	return m, nil
}

func (m Managed) render() string {
	var b strings.Builder
	b.WriteString(beginMarker + "\n")
	fmt.Fprintf(&b, "[sso-session %s]\nsso_start_url = %s\nsso_region = %s\nsso_registration_scopes = sso:account:access\n",
		m.Session.Name, m.Session.StartURL, m.Session.Region)
	names := make([]string, 0, len(m.Profiles))
	for n := range m.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := m.Profiles[n]
		fmt.Fprintf(&b, "\n[profile %s]\n", p.Name)
		if p.Squad != "" {
			fmt.Fprintf(&b, "# squad = %s\n", p.Squad)
		}
		if p.Environment != "" {
			fmt.Fprintf(&b, "# environment = %s\n", p.Environment)
		}
		fmt.Fprintf(&b, "sso_session = %s\nsso_account_id = %s\nsso_role_name = %s\n", m.Session.Name, p.AccountID, p.Role)
		if p.Region != "" {
			fmt.Fprintf(&b, "region = %s\n", p.Region)
		}
		b.WriteString("output = json\n")
	}
	b.WriteString(endMarker + "\n")
	return b.String()
}

// SaveManaged rewrites only the managed block of path, atomically, keeping
// every other line byte for byte. It refuses when a section it would write
// already exists outside the block — that section belongs to someone else.
func SaveManaged(path string, m Managed) error {
	for _, v := range []string{m.Session.Name, m.Session.StartURL, m.Session.Region} {
		if v == "" || strings.ContainsAny(v, "\r\n[]") {
			return fmt.Errorf("invalid sso-session setting %q", v)
		}
	}
	for _, p := range m.Profiles {
		if !accountIDRe.MatchString(p.AccountID) || !roleNameRe.MatchString(p.Role) || unsafeRe.MatchString(p.Name) ||
			strings.ContainsAny(p.Region+p.Squad+p.Environment, "\r\n") {
			return fmt.Errorf("refusing to write invalid profile %q", p.Name)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	before, _, after, err := split(string(data))
	if err != nil {
		return err
	}
	outside := before + after
	headers := []string{"[sso-session " + m.Session.Name + "]"}
	for n := range m.Profiles {
		headers = append(headers, "[profile "+n+"]")
	}
	for _, h := range headers {
		for _, line := range strings.Split(outside, "\n") {
			if strings.TrimSpace(line) == h {
				return fmt.Errorf("%s already exists in %s outside the nedctl section — rename one of them", h, path)
			}
		}
	}
	if before != "" && !strings.HasSuffix(before, "\n") {
		before += "\n"
	}
	text := before + m.render() + after

	perm := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.nedctl-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
