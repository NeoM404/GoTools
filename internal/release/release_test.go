package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSignVerifyAndChecksums(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	bin := []byte("nedctl binary")
	h := sha256.Sum256(bin)
	sums := []byte(hex.EncodeToString(h[:]) + "  nedctl-linux-amd64\n" + strings.Repeat("0", 64) + "  nedctl-darwin-arm64\n")
	sig := Sign(priv, sums)

	keys, err := ParseKeys(base64.StdEncoding.EncodeToString(other) + ", " + base64.StdEncoding.EncodeToString(pub))
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys: %v %v", keys, err)
	}
	if err := Verify(keys, sums, sig); err != nil {
		t.Fatalf("a signature by the second (rotation) key verifies: %v", err)
	}
	if err := Verify(keys[:1], sums, sig); err == nil {
		t.Fatal("a key that did not sign must not verify")
	}
	tampered := append([]byte(nil), sums...)
	tampered[0] ^= 1
	if err := Verify(keys, tampered, sig); err == nil {
		t.Fatal("changed checksums must not verify")
	}
	if err := Verify(nil, sums, sig); err != ErrNoKeys {
		t.Fatalf("no keys: %v", err)
	}
	if err := Verify(keys, sums, []byte("not base64!")); err == nil {
		t.Fatal("garbage signature")
	}
	got, err := SumFor(sums, "nedctl-linux-amd64")
	if err != nil || hex.EncodeToString(got) != hex.EncodeToString(h[:]) {
		t.Fatalf("sum: %x %v", got, err)
	}
	if _, err := SumFor(sums, "nedctl-windows-amd64.exe"); err == nil {
		t.Fatal("a file not listed has no sum")
	}
	if _, err := ParseKeys("bm90IGEga2V5"); err == nil {
		t.Fatal("a short key is refused")
	}
}
