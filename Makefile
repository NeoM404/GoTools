BINARY   := bankctl
PKG      := ./cmd/bankctl
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/NeoM404/GoTools/internal/app.Version=$(VERSION)

.PHONY: all build install test vet fmt lint clean cross

all: vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Static analysis (optional): install with `go install honnef.co/go/tools/cmd/staticcheck@latest`
lint:
	staticcheck ./... || echo "staticcheck not installed — skipping"

# Reproducible cross-compiles for the team's mixed macOS/Linux fleet.
cross:
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64  $(PKG)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-amd64  $(PKG)
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   $(PKG)
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64   $(PKG)

clean:
	rm -rf bin dist
