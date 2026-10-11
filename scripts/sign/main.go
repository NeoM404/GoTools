// Command sign manages the nedctl release signing key (Ed25519, standard
// library only):
//
//	go run ./scripts/sign keygen -out nedctl-signing.key   # once, by the release owner
//	go run ./scripts/sign pub -key nedctl-signing.key      # the public key to build in
//	go run ./scripts/sign sign -key nedctl-signing.key dist/SHA256SUMS
//
// The private key file goes into Azure DevOps as the secure file
// nedctl-signing.key and nowhere else: never commit it, never email it.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"nedctl/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New(path + " is not a base64 Ed25519 seed (made by: sign keygen)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sign keygen -out FILE | pub -key FILE | sign -key FILE SHA256SUMS")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	keyPath := fs.String("key", "", "the private key file")
	out := fs.String("out", "", "where keygen writes the private key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "keygen":
		if *out == "" {
			return errors.New("keygen needs -out FILE")
		}
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err // never overwrites an existing key
		}
		if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("private key: %s (upload it as the secure file nedctl-signing.key, then delete this copy)\npublic key:  %s\n", *out, base64.StdEncoding.EncodeToString(pub))
	case "pub":
		k, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
	case "sign":
		if fs.NArg() != 1 {
			return errors.New("sign needs the SHA256SUMS file")
		}
		k, err := readKey(*keyPath)
		if err != nil {
			return err
		}
		sums, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		sig := release.Sign(k, sums)
		keys, _ := release.ParseKeys(base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)))
		if err := release.Verify(keys, sums, sig); err != nil {
			return err
		}
		if err := os.WriteFile(fs.Arg(0)+".sig", sig, 0o644); err != nil {
			return err
		}
		fmt.Println("signed", fs.Arg(0))
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	return nil
}
