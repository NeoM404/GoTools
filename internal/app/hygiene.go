package app

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// `nedctl doctor --hygiene` looks on this machine for what turns a stolen
// laptop or a shared screen into an incident: long-term AWS keys on disk
// or in the environment, kubeconfigs holding static credentials, private
// keys without a passphrase or readable by others, plain-text git and
// netrc credentials, and secrets typed into shell history. It reports
// where and how to fix, never a secret itself. Local only.

var (
	accessKeyRe  = regexp.MustCompile(`(?i)^\s*aws_access_key_id\s*=\s*((AKIA|ASIA)[A-Z0-9]{12,})`)
	profileRe    = regexp.MustCompile(`^\s*\[([^\]]+)\]`)
	kubeSecretRe = regexp.MustCompile(`^\s*(client-key-data|token|password):\s*\S`)
	historyRe    = regexp.MustCompile(`AWS_SECRET_ACCESS_KEY=\S|aws_secret_access_key\s*=\s*\S|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|xox[bpa]-[A-Za-z0-9-]{10,}|(?i)(password|passwd)=\S{4,}|-----BEGIN [A-Z ]*PRIVATE KEY`)
)

func hygieneChecks(home string) []doctorCheck {
	var cs []doctorCheck
	add := func(name, status, detail string) { cs = append(cs, doctorCheck{name, status, detail}) }
	clean := map[string]bool{}

	// AWS keys on disk.
	credPath := filepath.Join(home, ".aws", "credentials")
	if f, err := os.Open(credPath); err == nil {
		profile := ""
		var longTerm, temp []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if m := profileRe.FindStringSubmatch(sc.Text()); m != nil {
				profile = m[1]
			}
			if m := accessKeyRe.FindStringSubmatch(sc.Text()); m != nil {
				if strings.EqualFold(m[2], "AKIA") {
					longTerm = append(longTerm, profile)
				} else {
					temp = append(temp, profile)
				}
			}
		}
		f.Close()
		if len(longTerm) > 0 {
			add("aws keys on disk", "fail", fmt.Sprintf("long-term access keys in %s (profiles: %s) — delete them, use `nedctl aws login`, and have them deactivated in IAM", credPath, strings.Join(longTerm, ", ")))
		}
		if len(temp) > 0 {
			add("aws keys on disk", "warn", fmt.Sprintf("short-term keys left in %s (profiles: %s) — remove them; sign-in profiles need none", credPath, strings.Join(temp, ", ")))
		}
		if len(longTerm)+len(temp) == 0 {
			clean["aws keys on disk"] = true
		}
		cs = append(cs, permCheck(credPath)...)
	} else {
		clean["aws keys on disk"] = true
	}

	// AWS keys in this shell.
	if id := os.Getenv("AWS_ACCESS_KEY_ID"); id != "" {
		status, what := "warn", "short-term"
		if strings.HasPrefix(id, "AKIA") {
			status, what = "fail", "long-term"
		}
		add("aws keys in environment", status, fmt.Sprintf("%s keys are exported in this shell (AWS_ACCESS_KEY_ID) — they reach every program you start; unset them and use a profile", what))
	}

	// Kubeconfigs with static credentials.
	var kubeFiles []string
	if env := os.Getenv("KUBECONFIG"); env != "" {
		kubeFiles = append(kubeFiles, filepath.SplitList(env)...)
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".kube", "*"))
	kubeFiles = append(kubeFiles, matches...)
	seen := map[string]bool{}
	sort.Strings(kubeFiles)
	staticKube := 0
	for _, p := range kubeFiles {
		if seen[p] {
			continue
		}
		seen[p] = true
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Size() > 5<<20 {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil || !bytes.Contains(data, []byte("clusters:")) {
			continue
		}
		n := 0
		for _, l := range strings.Split(string(data), "\n") {
			if kubeSecretRe.MatchString(l) {
				n++
			}
		}
		if n > 0 {
			staticKube++
			add("kubeconfig credentials", "warn", fmt.Sprintf("%s holds %d static credential(s) (client keys, tokens or passwords) — anyone who copies the file gets in; prefer nedctl kube / azure kube, and delete contexts you no longer use (nedctl sweep)", p, n))
		}
		cs = append(cs, permCheck(p)...)
	}
	if staticKube == 0 {
		clean["kubeconfig credentials"] = true
	}

	// SSH private keys.
	keys, _ := filepath.Glob(filepath.Join(home, ".ssh", "*"))
	sort.Strings(keys)
	keysOK := true
	for _, p := range keys {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() || fi.Size() > 64<<10 || strings.HasSuffix(p, ".pub") {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil || !bytes.Contains(data, []byte("PRIVATE KEY-----")) {
			continue
		}
		if !keyEncrypted(data) {
			keysOK = false
			add("ssh key passphrase", "warn", fmt.Sprintf("%s has no passphrase — add one: ssh-keygen -p -f %s (the SSH agent means you still type it once a day)", p, p))
		}
		if pc := permCheck(p); len(pc) > 0 {
			keysOK = false
			cs = append(cs, pc...)
		}
	}
	if keysOK {
		clean["ssh keys"] = true
	}

	// Plain-text credentials for git and other tools.
	for _, f := range []string{".git-credentials", ".netrc", "_netrc"} {
		p := filepath.Join(home, f)
		if data, err := os.ReadFile(p); err == nil {
			lines := 0
			for _, l := range strings.Split(string(data), "\n") {
				if strings.Contains(l, "@") || strings.Contains(l, "password") {
					lines++
				}
			}
			if lines > 0 {
				add("plain-text credentials", "warn", fmt.Sprintf("%s holds %d credential line(s) in plain text — use a credential manager (git: credential.helper manager/osxkeychain/cache)", p, lines))
			}
		}
	}

	// Secrets typed into shell history.
	hist := []string{filepath.Join(home, ".bash_history"), filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".local", "share", "fish", "fish_history")}
	if goos == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			hist = append(hist, filepath.Join(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
		}
	}
	historyClean := true
	for _, p := range hist {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		n := 0
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if historyRe.MatchString(sc.Text()) {
				n++
			}
		}
		f.Close()
		if n > 0 {
			historyClean = false
			add("secrets in shell history", "warn", fmt.Sprintf("%s has %d line(s) that look like secrets (keys, tokens, passwords) — remove those lines and rotate what they hold", p, n))
		}
	}
	if historyClean {
		clean["secrets in shell history"] = true
	}

	names := make([]string, 0, len(clean))
	for n := range clean {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(n, "ok", "nothing found")
	}
	return cs
}

// permCheck reports a credential file others can read (not on Windows,
// whose ACLs Unix modes do not describe).
func permCheck(p string) []doctorCheck {
	if goos == "windows" {
		return nil
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return []doctorCheck{{"file permissions", "warn", fmt.Sprintf("%s is readable by others (%s) — chmod 600 %s", p, fi.Mode().Perm(), p)}}
}

// keyEncrypted reports whether a private key file is protected by a
// passphrase: an OpenSSH key whose cipher is not "none", or a PEM key
// marked ENCRYPTED.
func keyEncrypted(data []byte) bool {
	s := string(data)
	if strings.Contains(s, "ENCRYPTED") {
		return true
	}
	const begin, end = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		return false // a PEM key without ENCRYPTED has no passphrase
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s[i+len(begin):j]), ""))
	magic := "openssh-key-v1\x00"
	if err != nil || len(raw) < len(magic)+4 || string(raw[:len(magic)]) != magic {
		return true // unreadable: do not claim it is unprotected
	}
	rest := raw[len(magic):]
	n := binary.BigEndian.Uint32(rest[:4])
	if int(n) > len(rest)-4 {
		return true
	}
	return string(rest[4:4+n]) != "none"
}
