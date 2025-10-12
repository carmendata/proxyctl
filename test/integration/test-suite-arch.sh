#!/bin/bash
#
# Architecture Test Suite for proxyctl
# Tests x86_64 architecture detection and binary compatibility
#
# Usage: ./test-suite-arch.sh

set -euo pipefail

echo "=== Test Suite: Architecture Detection (x86_64) ==="
echo ""

# Test 1: Verify system is x86_64
echo "Test 1: Verify system architecture is x86_64..."

DETECTED_ARCH=$(uname -m)
echo "  Detected architecture: $DETECTED_ARCH"

if [[ "$DETECTED_ARCH" != "x86_64" ]]; then
    echo "FAIL: Expected x86_64, got: $DETECTED_ARCH"
    echo "Note: Integration tests currently only support x86_64 platforms"
    exit 1
fi

echo "PASS: Architecture is x86_64"
echo ""

# Test 2: Verify binary is x86-64
echo "Test 2: Verify binary is x86-64..."

# Check if binary exists
if [ ! -f /usr/local/bin/proxyctl ]; then
    echo "FAIL: Binary not found at /usr/local/bin/proxyctl"
    exit 1
fi

# Get binary file type
BINARY_TYPE=$(file /usr/local/bin/proxyctl)
echo "  Binary type: $BINARY_TYPE"

# Verify it's x86-64
if ! echo "$BINARY_TYPE" | grep -q "x86-64\|x86_64"; then
    echo "FAIL: Binary is not x86-64"
    echo "  Binary info: $BINARY_TYPE"
    exit 1
fi

echo "PASS: Binary is x86-64"
echo ""

# Test 3: Binary execution test
echo "Test 3: Verify binary executes correctly..."

if ! /usr/local/bin/proxyctl version > /dev/null 2>&1; then
    echo "FAIL: Binary failed to execute"
    /usr/local/bin/proxyctl version
    exit 1
fi

VERSION_OUTPUT=$(/usr/local/bin/proxyctl version)
echo "  Version output:"
echo "$VERSION_OUTPUT" | sed 's/^/    /'

echo "PASS: Binary executes successfully"
echo ""

# Test 4: Symlinks work correctly
echo "Test 4: Verify symlinks work..."

if ! /usr/local/bin/egressctl version > /dev/null 2>&1; then
    echo "FAIL: egressctl symlink failed"
    exit 1
fi

if ! /usr/local/bin/ingressctl version > /dev/null 2>&1; then
    echo "FAIL: ingressctl symlink failed"
    exit 1
fi

echo "PASS: Symlinks work correctly"
echo ""

# Test 5: Logger installation works on x86_64
echo "Test 5: Verify logger installation works..."

if ! /usr/local/bin/egressctl logger install; then
    echo "FAIL: Logger installation failed on x86_64"
    exit 1
fi

echo "PASS: Logger installation successful on x86_64"
echo ""

# Cleanup
echo "Cleanup: Removing logger..."
/usr/local/bin/egressctl logger remove || {
    echo "WARN: Logger removal failed (non-critical)"
}

echo "=== All architecture tests passed on x86_64 ==="
