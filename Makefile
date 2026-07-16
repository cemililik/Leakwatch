.PHONY: build test lint cover clean

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/leakwatch .

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./... --config .golangci.yml

cover: test
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/ coverage.out coverage.html dist/
