VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-X github.com/viniciusfranca/vdt/internal/version.Version=$(VERSION) -X github.com/viniciusfranca/vdt/internal/version.Commit=$(COMMIT) -X github.com/viniciusfranca/vdt/internal/version.Date=$(DATE)"

.PHONY: build test fmt vet lint check install uninstall clean

build:
	go build $(LDFLAGS) -o vdt .

test:
	go test -race ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

lint:
	golangci-lint run

check: fmt vet lint test

install:
	./install.sh install

uninstall:
	./install.sh uninstall

clean:
	rm -f vdt
