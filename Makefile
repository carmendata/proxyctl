# proxyctl - Unified Proxy Management Tool
# Makefile for building and managing the Go-based CLI tool

.PHONY: help build test test-coverage lint clean install verify fmt fmt-check vet coverage release package-deb package-rpm dev run-egress run-ingress ci

.DEFAULT_GOAL := help

##
## Build Variables
##

BINARY_NAME := proxyctl
BIN_DIR := bin
CMD_DIR := cmd/proxyctl
OUTPUT_BINARY := $(BIN_DIR)/$(BINARY_NAME)

# Version information (from git or env vars)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Linker flags for version info
LDFLAGS := -ldflags "\
	-X github.com/carmendata/proxyctl/internal/version.Version=$(VERSION) \
	-X github.com/carmendata/proxyctl/internal/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/carmendata/proxyctl/internal/version.BuildDate=$(BUILD_DATE)"

# Colors
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
RED    := $(shell tput -Txterm setaf 1)
RESET  := $(shell tput -Txterm sgr0)

##
## Help
##

help: ## Show this help message
	@echo ''
	@echo '${GREEN}proxyctl - Unified Proxy Management Tool${RESET}'
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${YELLOW}%-20s${RESET} %s\n", $$1, $$2}'
	@echo ''

##
## Build & Development
##

build: ## Build proxyctl binary and create symlinks
	@echo "${GREEN}Building $(BINARY_NAME)...${RESET}"
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(OUTPUT_BINARY) ./$(CMD_DIR)
	@echo "${GREEN}Creating symlinks...${RESET}"
	@cd $(BIN_DIR) && ln -sf $(BINARY_NAME) egressctl
	@cd $(BIN_DIR) && ln -sf $(BINARY_NAME) ingressctl
	@echo "${GREEN}Build complete: $(OUTPUT_BINARY)${RESET}"
	@ls -lh $(BIN_DIR)/

clean: ## Remove build artifacts
	@echo "${GREEN}Cleaning build artifacts...${RESET}"
	@rm -rf $(BIN_DIR)
	@rm -rf dist/
	@rm -f coverage.out coverage.html
	@echo "${GREEN}Clean complete${RESET}"

dev: build ## Build and show usage examples
	@echo ""
	@echo "${GREEN}Build complete! Try these commands:${RESET}"
	@echo "  ${YELLOW}./bin/egressctl --help${RESET}"
	@echo "  ${YELLOW}./bin/ingressctl --help${RESET}"
	@echo "  ${YELLOW}./bin/proxyctl version${RESET}"
	@echo ""
	@echo "  ${YELLOW}./bin/egressctl --config configs/egress.yaml.example acl${RESET}"
	@echo "  ${YELLOW}./bin/ingressctl --config configs/ingress.yaml.example backend${RESET}"

run-egress: build ## Run egressctl with example config
	@echo "${GREEN}Running egressctl with example config...${RESET}"
	./bin/egressctl --config configs/egress.yaml.example --help

run-ingress: build ## Run ingressctl with example config
	@echo "${GREEN}Running ingressctl with example config...${RESET}"
	./bin/ingressctl --config configs/ingress.yaml.example --help

install: build ## Install to /usr/local/bin (requires sudo)
	@echo "${GREEN}Installing to /usr/local/bin...${RESET}"
	install -m 755 $(OUTPUT_BINARY) /usr/local/bin/$(BINARY_NAME)
	@cd /usr/local/bin && ln -sf $(BINARY_NAME) egressctl
	@cd /usr/local/bin && ln -sf $(BINARY_NAME) ingressctl
	@echo "${GREEN}Installed: /usr/local/bin/{$(BINARY_NAME),egressctl,ingressctl}${RESET}"

##
## Testing
##

test: ## Run all Go tests
	@echo "${GREEN}Running Go tests...${RESET}"
	go test -v -race ./...

test-coverage: ## Run tests with coverage (for CI)
	@echo "${GREEN}Running tests with coverage...${RESET}"
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

coverage: ## Generate test coverage report
	@echo "${GREEN}Generating coverage report...${RESET}"
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}Coverage report: coverage.html${RESET}"

##
## Code Quality
##

verify: ## Verify Go module dependencies
	@echo "${GREEN}Verifying dependencies...${RESET}"
	go mod verify

fmt: ## Format Go code
	@echo "${GREEN}Formatting Go code...${RESET}"
	go fmt ./...

fmt-check: ## Check if code is formatted (for CI)
	@echo "${GREEN}Checking code formatting...${RESET}"
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "${RED}Code not formatted. Run: make fmt${RESET}"; \
		gofmt -s -l .; \
		exit 1; \
	fi
	@echo "${GREEN}Code is properly formatted${RESET}"

vet: ## Run go vet
	@echo "${GREEN}Running go vet...${RESET}"
	go vet ./...

lint: ## Run golangci-lint (if available)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "${GREEN}Running golangci-lint...${RESET}"; \
		golangci-lint run ./...; \
	else \
		echo "${YELLOW}golangci-lint not found, running go vet instead...${RESET}"; \
		go vet ./...; \
	fi

##
## CI/CD
##

ci: lint test ## Run CI checks (lint + test)
	@echo "${GREEN}CI checks passed!${RESET}"

##
## Release & Packaging
##

release: ## Build release binaries for multiple platforms
	@echo "${GREEN}Building release binaries...${RESET}"
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@echo "${GREEN}Copying install script...${RESET}"
	@cp install.sh dist/install.sh
	@chmod +x dist/install.sh
	@echo "${GREEN}Release builds complete:${RESET}"
	@ls -lh dist/

package-deb: build ## Build .deb package (requires fpm)
	@command -v fpm >/dev/null 2>&1 || { echo "${RED}fpm not installed. Install with: gem install fpm${RESET}"; exit 1; }
	@echo "${GREEN}Building .deb package...${RESET}"
	@mkdir -p dist/deb/usr/bin
	@mkdir -p dist/deb/etc/proxyctl
	@cp $(OUTPUT_BINARY) dist/deb/usr/bin/
	@cp configs/*.example dist/deb/etc/proxyctl/
	fpm -s dir -t deb -n proxyctl -v $(VERSION) \
		--description "HAProxy proxy management tool" \
		--license "MIT" \
		--url "https://github.com/carmendata/proxyctl" \
		-C dist/deb \
		usr/bin etc/proxyctl usr/share/proxyctl
	@echo "${GREEN}Package created: proxyctl_$(VERSION)_amd64.deb${RESET}"

package-rpm: build ## Build .rpm package (requires fpm)
	@command -v fpm >/dev/null 2>&1 || { echo "${RED}fpm not installed. Install with: gem install fpm${RESET}"; exit 1; }
	@echo "${GREEN}Building .rpm package...${RESET}"
	@mkdir -p dist/rpm/usr/bin
	@mkdir -p dist/rpm/etc/proxyctl
	@cp $(OUTPUT_BINARY) dist/rpm/usr/bin/
	@cp configs/*.example dist/rpm/etc/proxyctl/
	fpm -s dir -t rpm -n proxyctl -v $(VERSION) \
		--description "HAProxy proxy management tool" \
		--license "MIT" \
		--url "https://github.com/carmendata/proxyctl" \
		-C dist/rpm \
		usr/bin etc/proxyctl usr/share/proxyctl
	@echo "${GREEN}Package created: proxyctl-$(VERSION)-1.x86_64.rpm${RESET}"

##
## Docker
##

docker-build: ## Build Docker image
	@echo "${GREEN}Building Docker image...${RESET}"
	docker build -t proxyctl:$(VERSION) -t proxyctl:latest .

docker-run: docker-build ## Run proxyctl in Docker container
	@echo "${GREEN}Running proxyctl in Docker...${RESET}"
	docker run --rm -it proxyctl:latest version
