# FlareSolverr-Go Makefile
# Run 'make help' for available commands

.PHONY: all build run test lint clean docker help

# Variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY_NAME := flaresolverr
BUILD_DIR := bin
GO_FILES := $(shell find . -type f -name '*.go' -not -path "./vendor/*")
LDFLAGS := -ldflags "-s -w -X github.com/user/flaresolverr-go/pkg/version.Version=$(VERSION)"

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

#------------------------------------------------------------------------------
# Main Targets
#------------------------------------------------------------------------------

all: lint test build ## Run lint, test, and build

build: ## Build the binary
	@echo "$(GREEN)Building $(BINARY_NAME) $(VERSION)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/flaresolverr
	@echo "$(GREEN)Binary created: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

build-linux: ## Build for Linux
	@echo "$(GREEN)Building for Linux...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/flaresolverr

build-all: ## Build for all platforms
	@echo "$(GREEN)Building for all platforms...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/flaresolverr
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/flaresolverr
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/flaresolverr
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/flaresolverr
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/flaresolverr

run: build ## Build and run
	@echo "$(GREEN)Running $(BINARY_NAME)...$(NC)"
	./$(BUILD_DIR)/$(BINARY_NAME)

#------------------------------------------------------------------------------
# Testing
#------------------------------------------------------------------------------

test: ## Run all tests
	@echo "$(GREEN)Running tests...$(NC)"
	go test -v -race ./...

test-short: ## Run tests (skip integration)
	@echo "$(GREEN)Running short tests...$(NC)"
	go test -v -short ./...

test-coverage: ## Run tests with coverage
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report: coverage.html$(NC)"

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(NC)"
	go test -v -tags=integration ./...

bench: ## Run benchmarks
	@echo "$(GREEN)Running benchmarks...$(NC)"
	go test -bench=. -benchmem ./...

#------------------------------------------------------------------------------
# Code Quality
#------------------------------------------------------------------------------

lint: ## Run linter
	@echo "$(GREEN)Running linter...$(NC)"
	golangci-lint run --config .golangci.yml

lint-fix: ## Run linter with auto-fix
	@echo "$(GREEN)Running linter with auto-fix...$(NC)"
	golangci-lint run --config .golangci.yml --fix

fmt: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	gofmt -s -w $(GO_FILES)
	goimports -w -local github.com/user/flaresolverr-go $(GO_FILES)

vet: ## Run go vet
	@echo "$(GREEN)Running go vet...$(NC)"
	go vet ./...

check: fmt vet lint test ## Run all checks (fmt, vet, lint, test)

#------------------------------------------------------------------------------
# Dependencies
#------------------------------------------------------------------------------

deps: ## Download dependencies
	@echo "$(GREEN)Downloading dependencies...$(NC)"
	go mod download

deps-update: ## Update dependencies
	@echo "$(GREEN)Updating dependencies...$(NC)"
	go get -u ./...
	go mod tidy

deps-tidy: ## Tidy dependencies
	@echo "$(GREEN)Tidying dependencies...$(NC)"
	go mod tidy

deps-verify: ## Verify dependencies
	@echo "$(GREEN)Verifying dependencies...$(NC)"
	go mod verify

#------------------------------------------------------------------------------
# Docker
#------------------------------------------------------------------------------

docker: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t flaresolverr-go:$(VERSION) -f deployments/Dockerfile .

docker-run: docker ## Run Docker container
	@echo "$(GREEN)Running Docker container...$(NC)"
	docker run -p 8191:8191 --shm-size=2g flaresolverr-go:$(VERSION)

docker-compose-up: ## Start with docker-compose
	@echo "$(GREEN)Starting with docker-compose...$(NC)"
	docker-compose -f deployments/docker-compose.yml up -d

docker-compose-down: ## Stop docker-compose
	@echo "$(GREEN)Stopping docker-compose...$(NC)"
	docker-compose -f deployments/docker-compose.yml down

#------------------------------------------------------------------------------
# Development
#------------------------------------------------------------------------------

dev: ## Run in development mode with auto-reload
	@echo "$(GREEN)Starting development server...$(NC)"
	@which air > /dev/null || go install github.com/cosmtrek/air@latest
	air

install-tools: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(NC)"
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/cosmtrek/air@latest
	@echo "$(GREEN)Tools installed!$(NC)"

pre-commit-install: ## Install pre-commit hooks
	@echo "$(GREEN)Installing pre-commit hooks...$(NC)"
	pip install pre-commit
	pre-commit install
	@echo "$(GREEN)Pre-commit hooks installed!$(NC)"

pre-commit-run: ## Run pre-commit on all files
	@echo "$(GREEN)Running pre-commit...$(NC)"
	pre-commit run --all-files

#------------------------------------------------------------------------------
# Cleanup
#------------------------------------------------------------------------------

clean: ## Clean build artifacts
	@echo "$(GREEN)Cleaning...$(NC)"
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	go clean -cache -testcache

clean-all: clean ## Clean everything including Docker
	@echo "$(GREEN)Cleaning everything...$(NC)"
	docker rmi flaresolverr-go:$(VERSION) 2>/dev/null || true

#------------------------------------------------------------------------------
# Help
#------------------------------------------------------------------------------

help: ## Show this help
	@echo "$(GREEN)FlareSolverr-Go Makefile$(NC)"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          Build the binary"
	@echo "  make test           Run all tests"
	@echo "  make lint           Run linter"
	@echo "  make docker         Build Docker image"
	@echo "  make check          Run all checks before commit"

.DEFAULT_GOAL := help
