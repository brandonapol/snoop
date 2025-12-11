.PHONY: help build test clean install cross-compile release

# Variables
BINARY_NAME=snoop
VERSION?=0.1.0
BUILD_DIR=build
GO=go
GOFLAGS=-ldflags="-s -w -X main.version=$(VERSION)"

# Colors for output
BLUE=\033[0;34m
GREEN=\033[0;32m
NC=\033[0m # No Color

help: ## Show this help message
	@echo '$(BLUE)Snoop - Node.js Security Audit CLI$(NC)'
	@echo ''
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'

build: ## Build snoop for current platform
	@echo "$(BLUE)Building $(BINARY_NAME)...$(NC)"
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .
	@echo "$(GREEN)✓ Build complete: ./$(BINARY_NAME)$(NC)"

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(GO) test ./... -v
	@echo "$(GREEN)✓ Tests complete$(NC)"

test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✓ Coverage report: coverage.html$(NC)"

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning...$(NC)"
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	rm -f snoop-test
	rm -f coverage.out coverage.html
	@echo "$(GREEN)✓ Clean complete$(NC)"

install: build ## Install snoop to /usr/local/bin
	@echo "$(BLUE)Installing $(BINARY_NAME)...$(NC)"
	cp $(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)✓ Installed to /usr/local/bin/$(BINARY_NAME)$(NC)"

uninstall: ## Uninstall snoop from /usr/local/bin
	@echo "$(BLUE)Uninstalling $(BINARY_NAME)...$(NC)"
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)✓ Uninstalled $(BINARY_NAME)$(NC)"

cross-compile: ## Build for all platforms
	@echo "$(BLUE)Cross-compiling for all platforms...$(NC)"
	@mkdir -p $(BUILD_DIR)

	# Linux amd64
	@echo "Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .

	# Linux arm64
	@echo "Building for linux/arm64..."
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .

	# macOS amd64 (Intel)
	@echo "Building for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .

	# macOS arm64 (Apple Silicon)
	@echo "Building for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

	# Windows amd64
	@echo "Building for windows/amd64..."
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

	@echo "$(GREEN)✓ Cross-compilation complete$(NC)"
	@ls -lh $(BUILD_DIR)/

release: clean test cross-compile ## Create release builds
	@echo "$(BLUE)Creating release v$(VERSION)...$(NC)"
	@cd $(BUILD_DIR) && \
	for binary in *; do \
		echo "Creating archive for $$binary..."; \
		tar czf $$binary.tar.gz $$binary; \
		rm $$binary; \
	done
	@echo "$(GREEN)✓ Release v$(VERSION) ready in $(BUILD_DIR)/$(NC)"
	@ls -lh $(BUILD_DIR)/

run: build ## Build and run snoop
	./$(BINARY_NAME) --help

dev: ## Run in development mode with test project
	$(GO) run . --path test-project --verbose

lint: ## Run linter
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

fmt: ## Format code
	$(GO) fmt ./...
	$(GO) vet ./...

deps: ## Download dependencies
	$(GO) mod download
	$(GO) mod tidy

.DEFAULT_GOAL := help
