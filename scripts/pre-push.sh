#!/bin/bash
# proxyctl pre-push hook
# Run full CI checks before pushing to remote
#
# This prevents pushing code that would fail GitHub Actions CI.
# To skip this hook temporarily, use: git push --no-verify

set -e

echo ""
echo "==========================================="
echo "Running pre-push CI checks..."
echo "==========================================="
echo ""
echo "This ensures your code will pass GitHub Actions CI."
echo "To skip (NOT recommended): git push --no-verify"
echo ""

# Store the exit status
EXIT_CODE=0

# Run dependency verification
echo "→ Step 1/4: Verifying dependencies..."
if ! make verify; then
    echo "✗ Dependency verification failed!"
    EXIT_CODE=1
fi

# Run format check (don't auto-format, just check)
echo ""
echo "→ Step 2/4: Checking code formatting..."
if ! make fmt-check; then
    echo "✗ Code formatting check failed!"
    echo "  Run 'make fmt' to fix formatting"
    EXIT_CODE=1
fi

# Run go vet
echo ""
echo "→ Step 3/4: Running static analysis (go vet)..."
if ! make vet; then
    echo "✗ Static analysis failed!"
    EXIT_CODE=1
fi

# Run tests with coverage
echo ""
echo "→ Step 4/4: Running tests..."
if ! make test-coverage; then
    echo "✗ Tests failed!"
    EXIT_CODE=1
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "==========================================="
    echo "✅ All pre-push checks passed!"
    echo "==========================================="
    echo ""
    echo "Pushing to remote..."
else
    echo "==========================================="
    echo "✗ Pre-push checks FAILED!"
    echo "==========================================="
    echo ""
    echo "Please fix the errors above before pushing."
    echo ""
    echo "To skip this hook (NOT recommended):"
    echo "  git push --no-verify"
    echo ""
fi

exit $EXIT_CODE
