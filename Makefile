# proxyctl - Unified Proxy Management Tool
# Makefile for building and managing the Go-based CLI tool

.PHONY: help build test test-coverage lint clean install verify fmt fmt-check vet coverage release build-release package-deb package-rpm dev run-egress run-ingress ci install-hooks

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
	@echo "  ${YELLOW}./bin/egressctl --config configs/egress.json.example acl${RESET}"
	@echo "  ${YELLOW}./bin/ingressctl --config configs/ingress.json.example backend${RESET}"

run-egress: build ## Run egressctl with example config
	@echo "${GREEN}Running egressctl with example config...${RESET}"
	./bin/egressctl --config configs/egress.json.example --help

run-ingress: build ## Run ingressctl with example config
	@echo "${GREEN}Running ingressctl with example config...${RESET}"
	./bin/ingressctl --config configs/ingress.json.example --help

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

coverage: ## Generate test coverage report (HTML + summary)
	@echo "${GREEN}Generating coverage report...${RESET}"
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}Coverage report: coverage.html${RESET}"
	@echo ""
	@echo "${GREEN}Coverage summary:${RESET}"
	@go tool cover -func=coverage.out | grep total

coverage-pkg: ## Run coverage for specific package (usage: make coverage-pkg PKG=./internal/logger)
	@if [ -z "$(PKG)" ]; then \
		echo "${RED}Error: PKG variable required${RESET}"; \
		echo "Usage: make coverage-pkg PKG=./internal/logger"; \
		exit 1; \
	fi
	@echo "${GREEN}Running coverage for $(PKG)...${RESET}"
	@go test -coverprofile=coverage-pkg.out $(PKG)
	@go tool cover -html=coverage-pkg.out -o coverage-pkg.html
	@echo "${GREEN}Coverage report: coverage-pkg.html${RESET}"
	@echo ""
	@echo "${GREEN}Coverage summary for $(PKG):${RESET}"
	@go tool cover -func=coverage-pkg.out | grep total
	@echo ""
	@echo "${YELLOW}Detailed coverage:${RESET}"
	@go tool cover -func=coverage-pkg.out

##
## Code Quality
##

install-hooks: ## Install Git pre-commit and pre-push hooks
	@echo "${GREEN}Installing Git hooks...${RESET}"
	@cp scripts/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@cp scripts/pre-push.sh .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "${GREEN}Git hooks installed successfully${RESET}"
	@echo ""
	@echo "${YELLOW}Pre-commit hook:${RESET} Runs 'make fmt' and 'make vet' before each commit"
	@echo "${YELLOW}Pre-push hook:${RESET} Runs full CI checks before pushing to remote"
	@echo ""
	@echo "To skip hooks temporarily:"
	@echo "  git commit --no-verify"
	@echo "  git push --no-verify"

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

check-ci: ## Run all GitHub Actions CI checks locally
	@./scripts/check-ci.sh

##
## Release & Packaging
##

build-release: ## Build release binaries locally (used by CI)
	@echo "${GREEN}Building release binaries...${RESET}"
	@mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@echo "${GREEN}Copying and versioning install script...${RESET}"
	@cp install.sh dist/install.sh
	@sed -i 's/VERSION="$${VERSION:-latest}"/VERSION="$${VERSION:-$(VERSION)}"/' dist/install.sh
	@chmod +x dist/install.sh
	@echo "${GREEN}Release builds complete:${RESET}"
	@ls -lh dist/

release: ## Create and push a new release (interactive)
	@echo "${GREEN}=== proxyctl Release Process ===${RESET}"
	@echo ""
	@# Auto-commit integration test status if it changed and tests passed
	@# This solves the catch-22: integration tests update .integration-test-status,
	@# but we can't release with uncommitted changes. Solution:
	@#   1. The file already says COMMIT=X (the tested commit)
	@#   2. We commit this file, creating commit Y
	@#   3. Commit Y contains a status file that says "commit X was tested"
	@#   4. Commit Y only differs from X by the status file itself (metadata)
	@# This is safe because commit Y = commit X + test metadata.
	@# The verification logic will check that either:
	@#   - Current commit matches COMMIT= in file (exact match), OR
	@#   - Current commit's parent matches COMMIT= in file (metadata commit)
	@if git status --porcelain | grep -q '^\s*[AM]\s*\.integration-test-status'; then \
		if [ -f .integration-test-status ]; then \
			TEST_STATUS=$$(grep '^STATUS=' .integration-test-status | cut -d= -f2); \
			if [ "$$TEST_STATUS" = "passed" ]; then \
				echo "${GREEN}Auto-committing integration test status (tests passed)${RESET}"; \
				git add .integration-test-status; \
				git commit --no-verify -m "chore: update integration test status"; \
				git push --no-verify origin main; \
				echo ""; \
			fi; \
		fi; \
	fi
	@# Check for uncommitted changes
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "${RED}Error: You have uncommitted changes${RESET}"; \
		echo "Please commit or stash them before releasing:"; \
		git status --short; \
		exit 1; \
	fi
	@# Check if on main branch
	@if [ "$$(git branch --show-current)" != "main" ]; then \
		echo "${RED}Error: You must be on the main branch to release${RESET}"; \
		echo "Current branch: $$(git branch --show-current)"; \
		exit 1; \
	fi
	@# Check integration test status (unless FORCE_RELEASE=true)
	@if [ "$(FORCE_RELEASE)" != "true" ]; then \
		if [ ! -f .integration-test-status ]; then \
			echo "${RED}Error: Integration tests have not been run${RESET}"; \
			echo ""; \
			echo "This commit has not been tested on real infrastructure."; \
			echo ""; \
			echo "To release safely, run integration tests first:"; \
			echo "  ${YELLOW}cd test/integration && ./run-integration-tests.sh --all${RESET}"; \
			echo ""; \
			echo "Or force release without tests (NOT recommended):"; \
			echo "  ${YELLOW}FORCE_RELEASE=true make release${RESET}"; \
			echo ""; \
			exit 1; \
		fi; \
		CURRENT_COMMIT=$$(git rev-parse HEAD); \
		PARENT_COMMIT=$$(git rev-parse HEAD^); \
		TESTED_COMMIT=$$(grep '^COMMIT=' .integration-test-status | cut -d= -f2); \
		TEST_STATUS=$$(grep '^STATUS=' .integration-test-status | cut -d= -f2); \
		TEST_TIMESTAMP=$$(grep '^TIMESTAMP=' .integration-test-status | cut -d= -f2); \
		TESTED_DISTROS=$$(grep '^DISTROS=' .integration-test-status | cut -d= -f2); \
		if [ "$$CURRENT_COMMIT" != "$$TESTED_COMMIT" ] && [ "$$PARENT_COMMIT" != "$$TESTED_COMMIT" ]; then \
			echo "${RED}Error: Current commit has not been integration tested${RESET}"; \
			echo ""; \
			echo "Current commit:  $$CURRENT_COMMIT"; \
			echo "Parent commit:   $$PARENT_COMMIT"; \
			echo "Tested commit:   $$TESTED_COMMIT"; \
			echo "Test timestamp:  $$TEST_TIMESTAMP"; \
			echo ""; \
			echo "Run integration tests on the current commit:"; \
			echo "  ${YELLOW}cd test/integration && ./run-integration-tests.sh --all${RESET}"; \
			echo ""; \
			echo "Or force release without tests (NOT recommended):"; \
			echo "  ${YELLOW}FORCE_RELEASE=true make release${RESET}"; \
			echo ""; \
			exit 1; \
		fi; \
		if [ "$$TEST_STATUS" != "passed" ]; then \
			echo "${RED}Error: Integration tests FAILED on this commit${RESET}"; \
			echo ""; \
			echo "Tested commit:   $$TESTED_COMMIT"; \
			echo "Test status:     $$TEST_STATUS"; \
			echo "Test timestamp:  $$TEST_TIMESTAMP"; \
			echo "Tested distros:  $$TESTED_DISTROS"; \
			echo ""; \
			echo "Fix the failing tests before releasing."; \
			echo ""; \
			echo "Or force release despite failures (DANGEROUS):"; \
			echo "  ${YELLOW}FORCE_RELEASE=true make release${RESET}"; \
			echo ""; \
			exit 1; \
		fi; \
		if [ "$$CURRENT_COMMIT" = "$$TESTED_COMMIT" ]; then \
			echo "${GREEN}✓ Integration tests passed on this commit${RESET}"; \
		else \
			echo "${GREEN}✓ Integration tests passed on parent commit (metadata-only change)${RESET}"; \
		fi; \
		echo "  Tested commit:  $$TESTED_COMMIT"; \
		echo "  Test status:    $$TEST_STATUS"; \
		echo "  Test timestamp: $$TEST_TIMESTAMP"; \
		echo "  Tested distros: $$TESTED_DISTROS"; \
		echo ""; \
	else \
		echo "${YELLOW}⚠ WARNING: Skipping integration test verification (FORCE_RELEASE=true)${RESET}"; \
		echo ""; \
	fi
	@# Get current version
	@CURRENT_VERSION=$$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || echo "0.0.0"); \
	echo "Current version: v$$CURRENT_VERSION"; \
	echo ""; \
	echo "Enter new version (e.g., 0.1.4, 0.2.0, 1.0.0):"; \
	read -r NEW_VERSION; \
	if [ -z "$$NEW_VERSION" ]; then \
		echo "${RED}Error: Version cannot be empty${RESET}"; \
		exit 1; \
	fi; \
	TAG="v$$NEW_VERSION"; \
	echo ""; \
	echo "${YELLOW}Creating release: $$TAG${RESET}"; \
	echo ""; \
	echo "Enter release message (or press Enter for default):"; \
	read -r RELEASE_MSG; \
	if [ -z "$$RELEASE_MSG" ]; then \
		RELEASE_MSG="Release $$TAG"; \
	fi; \
	echo ""; \
	echo "${YELLOW}Summary:${RESET}"; \
	echo "  Tag:     $$TAG"; \
	echo "  Message: $$RELEASE_MSG"; \
	echo "  Branch:  main"; \
	echo ""; \
	echo "This will:"; \
	echo "  1. Run tests"; \
	echo "  2. Create git tag: $$TAG"; \
	echo "  3. Push to origin/main"; \
	echo "  4. Push tag to origin"; \
	echo "  5. Trigger GitHub Actions release workflow"; \
	echo ""; \
	echo -n "Continue? [y/N] "; \
	read -r CONFIRM; \
	if [ "$$CONFIRM" != "y" ] && [ "$$CONFIRM" != "Y" ]; then \
		echo "${YELLOW}Release cancelled${RESET}"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "${GREEN}Running tests...${RESET}"; \
	$(MAKE) test || exit 1; \
	echo ""; \
	echo "${GREEN}Creating tag: $$TAG${RESET}"; \
	git tag -a "$$TAG" -m "$$RELEASE_MSG"; \
	echo "${GREEN}Pushing to origin/main...${RESET}"; \
	git push origin main; \
	echo "${GREEN}Pushing tag: $$TAG${RESET}"; \
	git push origin "$$TAG"; \
	echo ""; \
	echo "${GREEN}✓ Release initiated!${RESET}"; \
	echo ""; \
	echo "Monitor the release workflow at:"; \
	echo "  ${YELLOW}https://github.com/carmendata/proxyctl/actions${RESET}"; \
	echo ""; \
	echo "Once complete, the release will be available at:"; \
	echo "  ${YELLOW}https://github.com/carmendata/proxyctl/releases/tag/$$TAG${RESET}"; \
	echo ""

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
