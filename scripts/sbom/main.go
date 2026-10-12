// Command sbom writes a CycloneDX 1.5 software bill of materials for the
// release binaries from the build information Go embeds in them (standard
// library only): the nedctl module, every module it depends on (none, by
// policy), the Go toolchain, and each binary's SHA-256 and build settings.
//
//	go run ./scripts/sbom -version v1.3.0 -out dist/sbom.cdx.json dist/nedctl-*
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []hash     `json:"hashes,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

func run() error {
	version := flag.String("version", "", "the release version")
	out := flag.String("out", "", "where to write the SBOM")
	flag.Parse()
	if *version == "" || *out == "" || flag.NArg() == 0 {
		return errors.New("usage: sbom -version vX.Y.Z -out FILE BINARY…")
	}
	var comps []component
	deps := map[string]string{}
	goVersion := ""
	for _, path := range flag.Args() {
		info, err := buildinfo.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		var props []property
		for _, s := range info.Settings {
			switch s.Key {
			case "GOOS", "GOARCH", "CGO_ENABLED", "-trimpath", "vcs.revision", "vcs.time", "vcs.modified":
				props = append(props, property{"go:" + s.Key, s.Value})
			}
		}
		comps = append(comps, component{Type: "application", Name: filepath.Base(path), Version: *version,
			Hashes: []hash{{"SHA-256", hex.EncodeToString(sum[:])}}, Properties: props})
		goVersion = info.GoVersion
		for _, d := range info.Deps {
			deps[d.Path] = d.Version
		}
	}
	comps = append(comps, component{Type: "framework", Name: "golang", Version: goVersion, PURL: "pkg:golang/stdlib@" + goVersion})
	var names []string
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		comps = append(comps, component{Type: "library", Name: n, Version: deps[n], PURL: "pkg:golang/" + n + "@" + deps[n]})
	}
	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"component": component{Type: "application", Name: "nedctl", Version: *version, PURL: "pkg:golang/nedctl@" + *version},
			"properties": []property{{"nedctl:thirdPartyGoModules", fmt.Sprint(len(names))}},
		},
		"components": comps,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(data, '\n'), 0o644)
}
