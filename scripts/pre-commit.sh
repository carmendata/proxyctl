#!/bin/bash
# proxyctl pre-commit hook
# Automatically format Go code before committing

set -e

echo "Running pre-commit checks..."

# Format Go code using Makefile
echo "→ Formatting Go code..."
make fmt

# Re-add formatted files to staging
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [ -n "$STAGED_GO_FILES" ]; then
    echo "→ Re-staging formatted files..."
    echo "$STAGED_GO_FILES" | xargs git add
fi

# Run go vet using Makefile
echo "→ Running go vet..."
make vet

echo "✓ Pre-commit checks passed!"
