BINARY   := bankctl
PKG      := ./cmd/bankctl
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/NeoM404/GoTools/internal/app.Version=$(VERSION)

# Release builds are static (no cgo), carry no local filesystem paths
# (-trimpath) and are reproducible: the same commit and toolchain produce
# byte-identical binaries, which `make repro` verifies.
BUILDFLAGS := -trimpath -ldflags "$(LDFLAGS)"
STATIC     := CGO_ENABLED=0

# Analysis tools are pinned so CI and every laptop run identical checks.
# Bump deliberately, in their own commit.
STATICCHECK_VERSION := v0.8.1
GOVULNCHECK_VERSION := v1.8.0

GOBIN ?= $(shell go env GOPATH)/bin
SHA256 := $(shell command -v sha256sum 2>/dev/null || echo "shasum -a 256")

.PHONY: all build install test vet fmt fmt-check lint vuln deps-check ci cross checksums repro tools clean

all: ci build

build:
	$(STATIC) go build $(BUILDFLAGS) -o bin/$(BINARY) $(PKG)

install:
	$(STATIC) go install $(BUILDFLAGS) $(PKG)

# -race needs cgo, so tests deliberately do not use $(STATIC).
test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	@command -v staticcheck >/dev/null || { echo "staticcheck missing — run: make tools"; exit 1; }
	staticcheck ./...

# Scans our code AND the standard library it links: zero third-party
# dependencies is not zero CVEs.
vuln:
	@command -v govulncheck >/dev/null || { echo "govulncheck missing — run: make tools"; exit 1; }
	govulncheck ./...

# Enforces the zero-dependency policy (see go.mod): the build graph must
# contain only this module.
deps-check:
	@mods="$$(go list -m all)" || { echo "deps-check: go list failed"; exit 1; }; \
	if [ "$$(printf '%s\n' "$$mods" | wc -l | tr -d ' ')" != "1" ]; then \
		echo "third-party dependency added — policy is stdlib only:"; printf '%s\n' "$$mods" | tail -n +2; exit 1; fi; \
	echo "deps-check: stdlib only"

# Everything CI gates on, in one command.
ci: fmt-check vet deps-check lint test vuln

cross:
	$(STATIC) GOOS=darwin GOARCH=arm64 go build $(BUILDFLAGS) -o dist/$(BINARY)-darwin-arm64 $(PKG)
	$(STATIC) GOOS=darwin GOARCH=amd64 go build $(BUILDFLAGS) -o dist/$(BINARY)-darwin-amd64 $(PKG)
	$(STATIC) GOOS=linux  GOARCH=amd64 go build $(BUILDFLAGS) -o dist/$(BINARY)-linux-amd64  $(PKG)
	$(STATIC) GOOS=linux  GOARCH=arm64 go build $(BUILDFLAGS) -o dist/$(BINARY)-linux-arm64  $(PKG)

checksums: cross
	cd dist && $(SHA256) $(BINARY)-* > SHA256SUMS

# Build twice — the second from an empty, throwaway build cache — and require
# byte-identical output. Leaves your own build cache untouched.
repro:
	@rm -rf dist/repro-a dist/repro-b
	@$(STATIC) GOOS=linux GOARCH=amd64 go build $(BUILDFLAGS) -o dist/repro-a/$(BINARY) $(PKG)
	@cache="$$(mktemp -d)"; $(STATIC) GOCACHE="$$cache" GOOS=linux GOARCH=amd64 go build $(BUILDFLAGS) -o dist/repro-b/$(BINARY) $(PKG); \
	status=$$?; chmod -R u+w "$$cache"; rm -rf "$$cache"; exit $$status
	@a="$$($(SHA256) dist/repro-a/$(BINARY) | cut -d' ' -f1)"; b="$$($(SHA256) dist/repro-b/$(BINARY) | cut -d' ' -f1)"; \
	rm -rf dist/repro-a dist/repro-b; \
	if [ "$$a" != "$$b" ]; then echo "NOT reproducible: $$a != $$b"; exit 1; fi; echo "reproducible: $$a"

tools:
	go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

clean:
	rm -rf bin dist
