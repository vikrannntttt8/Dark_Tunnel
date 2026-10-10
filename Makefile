BINARY_NAME=tunnel
BUILD_DIR=bin
MODULE=github.com/vikrannntttt8/Dark_Tunnel

.PHONY: all build test clean run-client run-server lint

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tunnel

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tunnel

build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/tunnel

build-darwin:
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tunnel

test:
	go test -v -race ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

clean:
	rm -rf $(BUILD_DIR) coverage.out

genkey:
	go run ./cmd/tunnel genkey
