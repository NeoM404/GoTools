// Package release verifies nedctl releases: the release pipeline signs
// SHA256SUMS with an Ed25519 key kept as an Azure DevOps secure file, and
// every binary carries the public keys it trusts (built in with -ldflags, so
// a binary can only be replaced by one the bank signed). Standard library
// only.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// PublicKeys are the trusted signing keys, base64, comma-separated (the
// current key, and the next one during a rotation). Set at build time:
// -X nedctl/internal/release.PublicKeys=…
var PublicKeys string

// ErrNoKeys means this build trusts no key (a development build).
var ErrNoKeys = errors.New("this nedctl build has no release signing key built in, so it cannot verify a release")

// Keys parses PublicKeys.
func Keys() ([]ed25519.PublicKey, error) {
	return ParseKeys(PublicKeys)
}

// ParseKeys reads comma-separated base64 Ed25519 public keys.
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key %q is not a base64 Ed25519 public key", k)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	return keys, nil
}

// Verify checks sig (the contents of SHA256SUMS.sig: one base64 line)
// over sums with any trusted key.
func Verify(keys []ed25519.PublicKey, sums, sig []byte) error {
	if len(keys) == 0 {
		return ErrNoKeys
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("SHA256SUMS.sig is not an Ed25519 signature")
	}
	for _, k := range keys {
		if ed25519.Verify(k, sums, raw) {
			return nil
		}
	}
	return errors.New("SHA256SUMS is not signed by a key this nedctl trusts — do not install it")
}

// Sign is the signature file for sums: one base64 line.
func Sign(key ed25519.PrivateKey, sums []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, sums)) + "\n")
}

// SumFor returns the SHA-256 that sums lists for name.
func SumFor(sums []byte, name string) ([]byte, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			h, err := hex.DecodeString(f[0])
			if err != nil || len(h) != 32 {
				return nil, fmt.Errorf("SHA256SUMS: bad checksum for %s", name)
			}
			return h, nil
		}
	}
	return nil, fmt.Errorf("SHA256SUMS does not list %s", name)
}
