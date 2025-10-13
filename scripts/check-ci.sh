#!/bin/bash
# Run all CI checks locally (mirrors GitHub Actions workflow)
set -e

echo "==========================================="
echo "Running CI checks locally"
echo "==========================================="
echo ""

echo "✓ Step 1/5: Verifying dependencies..."
make verify

echo ""
echo "✓ Step 2/5: Checking code formatting..."
make fmt-check

echo ""
echo "✓ Step 3/5: Running go vet..."
make vet

echo ""
echo "✓ Step 4/5: Running tests with coverage..."
make test-coverage

echo ""
echo "✓ Step 5/5: Building binaries..."
make build

echo ""
echo "Testing binaries..."
./bin/proxyctl version
./bin/egressctl version
./bin/ingressctl version

echo ""
echo "==========================================="
echo "✅ All CI checks passed!"
echo "==========================================="
echo ""
echo "Your code is ready for GitHub Actions."
