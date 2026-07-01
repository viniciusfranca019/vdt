VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-X github.com/viniciusfranca/vdt/internal/version.Version=$(VERSION) -X github.com/viniciusfranca/vdt/internal/version.Commit=$(COMMIT) -X github.com/viniciusfranca/vdt/internal/version.Date=$(DATE)"

.PHONY: build test fmt vet lint check install uninstall clean

build:
	@go build $(LDFLAGS) -o vdt ./cmd/vdt

test:
	@go test -race ./...

fmt:
	@gofmt -w .

vet:
	@go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.12.2"; exit 1; }
	@golangci-lint run

check: fmt vet lint test

install:
	@./install.sh install

uninstall:
	@./install.sh uninstall

clean:
	@rm -f vdt
