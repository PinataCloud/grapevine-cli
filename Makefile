# CLI-specific Makefile
# Run from the cli/ directory

BINARY_NAME := grapevine
VERSION := 0.1.0

.PHONY: build test clean deps

# Build for current platform
build:
	go build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY_NAME) src/main.go

# Run tests
test:
	go test -v ./src

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)

# Download dependencies
deps:
	go mod download
	go mod tidy

# Development build with debug info
build-dev:
	go build -o $(BINARY_NAME) src/main.go

# Install locally (Unix systems)
install: build
	cp $(BINARY_NAME) /usr/local/bin/

# Cross-compile for all platforms
build-all: build-linux build-darwin build-windows

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-linux-amd64 src/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-linux-arm64 src/main.go

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-darwin-amd64 src/main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-darwin-arm64 src/main.go

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-windows-amd64.exe src/main.go
	GOOS=windows GOARCH=arm64 go build -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BINARY_NAME)-windows-arm64.exe src/main.go

