.PHONY: all build test clean lint vet release

APP_NAME    := elencho
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
GOFLAGS     := -ldflags="-X github.com/lukemcqueen/elencho/internal/config.Version=$(VERSION)"

all: build

build:
	go build $(GOFLAGS) -o $(APP_NAME) ./cmd/elencho/

test:
	go test ./... -count=1 -v

clean:
	rm -f $(APP_NAME)
	rm -rf artifacts/

lint:
	golangci-lint run ./...

vet:
	go vet ./...

# Cross-compile all targets
release: clean
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -o $(APP_NAME)-linux-amd64   ./cmd/elencho/
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -o $(APP_NAME)-linux-arm64   ./cmd/elencho/
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -o $(APP_NAME)-darwin-amd64  ./cmd/elencho/
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -o $(APP_NAME)-darwin-arm64  ./cmd/elencho/
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $(APP_NAME)-windows-amd64.exe ./cmd/elencho/
	ls -lh $(APP_NAME)-*

genkey:
	go run ./tools/genkey/

sign:
	go run ./tools/sign/ internal/scan/rules/rules.yaml
