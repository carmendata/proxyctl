#!/bin/bash
#
# Integration test suite for firewall detection and management
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Firewall"
echo "Started: $(date)"
echo "========================================"
echo ""

# Test 1: Firewall type detection
# Story: S004 (Multiple Firewall Backend Support)
test_firewall_type_detection() {
    echo "Test 1: Firewall Type Detection (Story: S004)"
    echo "---"

    local has_iptables=false
    local has_nftables=false

    # Check iptables
    if command -v iptables >/dev/null 2>&1; then
        has_iptables=true
        echo "✓ iptables available: $(iptables --version)"
    fi

    # Check nftables
    if command -v nft >/dev/null 2>&1; then
        has_nftables=true
        echo "✓ nftables available: $(nft --version)"
    fi

    # At least one should be available
    if [ "$has_iptables" = false ] && [ "$has_nftables" = false ]; then
        echo "✗ FAIL: No firewall tools detected"
        return 1
    fi

    echo "✓ PASS: Firewall type detection"
    echo ""
}

# Test 2: UFW conflict detection
# Story: S002 (UFW Conflict Detection)
test_ufw_conflict() {
    echo "Test 2: UFW Conflict Detection (Story: S002)"
    echo "---"

    if ! command -v ufw >/dev/null 2>&1; then
        echo "  UFW not installed (expected)"
        echo "✓ PASS: No UFW conflict"
        echo ""
        return 0
    fi

    # Check if UFW is active
    local ufw_status=$(ufw status 2>/dev/null | grep -i "Status:" || echo "Status: inactive")
    echo "  UFW status: $ufw_status"

    # Check for "Status: active" (not "Status: inactive")
    if echo "$ufw_status" | grep -qi "Status:.*active" && ! echo "$ufw_status" | grep -qi "inactive"; then
        echo "✗ FAIL: UFW is active (should be inactive for proxyctl)"
        return 1
    fi

    echo "✓ PASS: No UFW conflict"
    echo ""
}

# Test 3: firewalld conflict detection
# Story: S003 (firewalld Conflict Detection)
test_firewalld_conflict() {
    echo "Test 3: firewalld Conflict Detection (Story: S003)"
    echo "---"

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        echo "  firewalld not installed (expected)"
        echo "✓ PASS: No firewalld conflict"
        echo ""
        return 0
    fi

    # Check if firewalld is running
    if systemctl is-active firewalld >/dev/null 2>&1; then
        echo "✗ FAIL: firewalld is active (should be inactive for proxyctl)"
        return 1
    fi

    echo "  firewalld inactive (expected)"
    echo "✓ PASS: No firewalld conflict"
    echo ""
}

# Test 4: nftables configuration path detection
# Story: S024 (CentOS/RHEL Support), S025 (Ubuntu/Debian Support)
test_nftables_config_path() {
    echo "Test 4: nftables Config Path Detection (Stories: S024, S025)"
    echo "---"

    if ! command -v nft >/dev/null 2>&1; then
        echo "  nftables not available, skipping test"
        echo "✓ PASS: Test skipped"
        echo ""
        return 0
    fi

    # Check for common config paths
    local found_config=false

    for path in /etc/nftables.conf /etc/sysconfig/nftables.conf; do
        if [ -f "$path" ]; then
            echo "✓ Found nftables config: $path"
            found_config=true
            break
        fi
    done

    if [ "$found_config" = false ]; then
        echo "  No nftables config found (will be created)"
    fi

    echo "✓ PASS: nftables config path detection"
    echo ""
}

# Test 5: iptables systemd service detection
test_iptables_service() {
    echo "Test 5: iptables Service Detection"
    echo "---"

    if ! command -v iptables >/dev/null 2>&1; then
        echo "  iptables not available, skipping test"
        echo "✓ PASS: Test skipped"
        echo ""
        return 0
    fi

    # Check for iptables persistence services
    local has_service=false

    for service in iptables iptables-persistent netfilter-persistent; do
        if systemctl list-unit-files | grep -q "^$service"; then
            echo "✓ Found iptables service: $service"
            has_service=true
        fi
    done

    if [ "$has_service" = false ]; then
        echo "  No iptables persistence service found"
        echo "  (proxyctl will create systemd service for persistence)"
    fi

    echo "✓ PASS: iptables service detection"
    echo ""
}

# Test 6: Firewall rule syntax validation
test_firewall_syntax() {
    echo "Test 6: Firewall Rule Syntax Validation"
    echo "---"

    # Test iptables syntax (if available)
    if command -v iptables >/dev/null 2>&1; then
        # Try a harmless iptables command
        if iptables -L OUTPUT -n >/dev/null 2>&1; then
            echo "✓ iptables syntax valid"
        else
            echo "✗ FAIL: iptables syntax check failed"
            return 1
        fi
    fi

    # Test nftables syntax (if available)
    if command -v nft >/dev/null 2>&1; then
        # Try a harmless nft command
        if nft list tables >/dev/null 2>&1; then
            echo "✓ nftables syntax valid"
        else
            echo "✗ FAIL: nftables syntax check failed"
            return 1
        fi
    fi

    echo "✓ PASS: Firewall syntax validation"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    for test_func in \
        test_firewall_type_detection \
        test_ufw_conflict \
        test_firewalld_conflict \
        test_nftables_config_path \
        test_iptables_service \
        test_firewall_syntax; do

        if ! $test_func; then
            failed_tests+=("$test_func")
        fi
    done

    echo "========================================"
    echo "Test Results"
    echo "========================================"
    if [ ${#failed_tests[@]} -eq 0 ]; then
        echo "✓ All tests passed!"
        echo "Completed: $(date)"
        exit 0
    else
        echo "✗ Failed tests: ${failed_tests[*]}"
        echo "Completed: $(date)"
        exit 1
    fi
}

main
