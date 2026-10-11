package app

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// opensshKey is a private key file in OpenSSH's format with this cipher
// ("none" = no passphrase); only the header matters to the check.
func opensshKey(cipher string) string {
	var b []byte
	b = append(b, "openssh-key-v1\x00"...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(cipher)))
	b = append(b, cipher...)
	b = append(b, make([]byte, 32)...)
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(b) + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

func TestDoctorHygieneFindsRiskyLeftovers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	write(".aws/credentials", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n[old]\naws_access_key_id=ASIAIOSFODNN7EXAMPLE\n", 0o644)
	write(".kube/config", "apiVersion: v1\nclusters:\n- name: c\nusers:\n- name: u\n  user:\n    token: abcdef0123456789\n", 0o600)
	write(".kube/nedctl-eks.json", "apiVersion: v1\nclusters:\n- name: c\nusers:\n- name: u\n  user:\n    exec:\n      command: aws\n", 0o600)
	write(".ssh/id_ed25519", opensshKey("none"), 0o600)
	write(".ssh/id_work", opensshKey("aes256-ctr"), 0o644)
	write(".ssh/id_work.pub", "ssh-ed25519 AAAA", 0o644)
	write(".bash_history", "ls\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\nkubectl get pods\n", 0o600)
	write(".git-credentials", "https://neo:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com\n", 0o600)

	code, out, errb := run("doctor", "--hygiene")
	if code != ExitFailure {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range []string{
		"aws keys on disk", "long-term access keys in " + filepath.Join(home, ".aws/credentials") + " (profiles: default)",
		"short-term keys left", "(profiles: old)",
		filepath.Join(home, ".aws/credentials") + " is readable by others (-rw-r--r--)",
		filepath.Join(home, ".kube/config") + " holds 1 static credential(s)",
		filepath.Join(home, ".ssh/id_ed25519") + " has no passphrase",
		filepath.Join(home, ".ssh/id_work") + " is readable by others",
		".git-credentials holds 1 credential line(s)",
		".bash_history has 1 line(s) that look like secrets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI", "abcdef0123456789", "ghp_abcdef"} {
		if strings.Contains(out+errb, secret) {
			t.Errorf("printed a secret: %s", secret)
		}
	}
	if strings.Contains(out, "nedctl-eks.json") || strings.Contains(out, "id_work has no passphrase") {
		t.Error("exec-based kubeconfig or an encrypted key flagged")
	}
	if t.Failed() {
		t.Log(out)
	}
}

func TestDoctorHygieneOnACleanMachine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	code, out, _ := run("doctor", "--hygiene", "-o", "json")
	if code != ExitOK || !strings.Contains(out, `"healthy": true`) || strings.Contains(out, `"warn"`) {
		t.Fatalf("code=%d out=%s", code, out)
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	if code, out, _ := run("doctor", "--hygiene"); code != ExitFailure || !strings.Contains(out, "long-term keys are exported in this shell") {
		t.Fatalf("env keys: %d %s", code, out)
	}
}

func TestKeyEncryptedOnRealKeys(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	for _, c := range []struct {
		pass string
		typ  string
		want bool
	}{{"", "ed25519", false}, {"correct horse", "ed25519", true}, {"", "rsa", false}, {"pw12345678", "rsa", true}} {
		p := filepath.Join(dir, c.typ+c.pass)
		args := []string{"-q", "-t", c.typ, "-N", c.pass, "-f", p}
		if c.typ == "rsa" {
			args = append(args, "-b", "2048")
		}
		if out, err := exec.Command("ssh-keygen", args...).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		data, _ := os.ReadFile(p)
		if got := keyEncrypted(data); got != c.want {
			t.Errorf("%s with passphrase %q: encrypted=%v", c.typ, c.pass, got)
		}
	}
}
