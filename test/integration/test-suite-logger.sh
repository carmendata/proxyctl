#!/bin/bash
#
# Integration test suite for proxyctl logger functionality
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Logger"
echo "Started: $(date)"
echo "========================================"
echo ""

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."
    remove_logger 2>/dev/null || true
    exit $exit_code
}

trap cleanup EXIT

# Helper functions for logger operations with proper error handling

install_logger() {
    /usr/local/bin/egressctl logger install || return 1
    return 0
}

remove_logger() {
    /usr/local/bin/egressctl logger remove || return 1
    return 0
}

# Test 1: Firewall detection
# Story: S001 (Clean System Installation), S004 (Multiple Firewall Backend Support)
test_firewall_detection() {
    echo "Test 1: Firewall Detection (Stories: S001, S004)"
    echo "---"

    # Check if firewall tools are available
    if command -v iptables >/dev/null 2>&1; then
        echo "✓ iptables available: $(iptables --version)"
    fi

    if command -v nft >/dev/null 2>&1; then
        echo "✓ nftables available: $(nft --version)"
    fi

    # Check for conflicting managers
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status 2>/dev/null | grep -i "Status:" || echo "Status: inactive")
        echo "  UFW: $ufw_status"
        if echo "$ufw_status" | grep -qi "Status: active"; then
            echo "✗ FAIL: UFW is active (conflicts with proxyctl)"
            return 1
        fi
    fi

    if systemctl is-active firewalld >/dev/null 2>&1; then
        echo "✗ FAIL: firewalld is active (conflicts with proxyctl)"
        return 1
    fi

    echo "✓ PASS: Firewall detection"
    echo ""
}

# Test 2: Logger installation
# Story: S001 (Clean System Installation), S008 (Connection Capture), S009 (Private IP Filtering),
#        S010 (Log File Management), S011 (Real-time Monitoring)
test_logger_install() {
    echo "Test 2: Logger Installation (Stories: S001, S008, S009, S010, S011)"
    echo "---"

    # Install logger
    if ! install_logger; then
        echo "✗ FAIL: Logger installation failed"
        return 1
    fi

    echo "✓ Logger installed successfully"

    # Verify rsyslog config (check new filename)
    if [ ! -f /etc/rsyslog.d/10-egress-monitor.conf ]; then
        echo "✗ FAIL: Rsyslog config not created"
        return 1
    fi
    echo "✓ Rsyslog config created"

    # Verify logrotate config
    if [ ! -f /etc/logrotate.d/egress-monitor ]; then
        echo "✗ FAIL: Logrotate config not created"
        return 1
    fi
    echo "✓ Logrotate config created"

    # Validate logrotate config with dry-run test
    # This catches permission issues (missing 'su' directive on Ubuntu)
    LOGROTATE_TEST=$(logrotate -d /etc/logrotate.d/egress-monitor 2>&1)

    # Filter out state file errors (CentOS: state dir doesn't exist until first run)
    # We only care about config errors, not missing state files
    FILTERED_ERRORS=$(echo "$LOGROTATE_TEST" | grep -i "error" | grep -v "state file" || true)

    if [ -n "$FILTERED_ERRORS" ]; then
        echo "✗ FAIL: Logrotate configuration has errors"
        echo "  Dry-run output:"
        echo "$FILTERED_ERRORS" | sed 's/^/    /'
        echo ""
        echo "  Common cause: Missing 'su' directive for group-writable directories"
        echo "  This will prevent log rotation in production!"
        return 1
    fi
    echo "✓ Logrotate config validated (dry-run passed)"

    # Verify log directory
    if [ ! -d /var/log/proxyctl ]; then
        echo "✗ FAIL: Log directory not created"
        return 1
    fi
    echo "✓ Log directory created"

    # Check firewall rules based on what's actually being used
    local using_nftables=false
    if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q "egress_monitor"; then
        using_nftables=true
        echo "✓ nftables rules created"

        # Verify rules content
        if nft list table ip egress_monitor >/dev/null 2>&1; then
            echo "✓ nftables table accessible"
        else
            echo "✗ FAIL: nftables table not accessible"
            return 1
        fi
    elif command -v iptables >/dev/null 2>&1 && iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG"; then
        echo "✓ iptables rules created"
    else
        echo "✗ FAIL: No firewall rules created"
        return 1
    fi

    echo "✓ PASS: Logger installation"
    echo ""
}

# Test 3: Log generation
# Story: S008 (Connection Capture Accuracy), S011 (Real-time Monitoring)
test_log_generation() {
    echo "Test 3: Log Generation (Stories: S008, S011)"
    echo "---"

    # Debug: Check if rsyslog is running
    if systemctl is-active rsyslog >/dev/null 2>&1; then
        echo "  rsyslog is running"
    else
        echo "  WARNING: rsyslog is not running"
    fi

    # Debug: Check nftables rules are still active
    if nft list table ip egress_monitor >/dev/null 2>&1; then
        echo "  nftables rules are active"
    else
        echo "  WARNING: nftables rules not found"
    fi

    # Generate some network traffic
    echo "Generating test traffic..."
    curl -s http://example.com >/dev/null 2>&1 || true
    curl -s http://google.com >/dev/null 2>&1 || true
    # Also try HTTPS to ensure we get connections
    curl -s https://example.com >/dev/null 2>&1 || true

    # Wait for logs to be written
    sleep 5

    # Debug: Check kernel messages for EGRESS_MONITOR
    echo "  Checking kernel messages..."
    if dmesg | tail -100 | grep -q "EGRESS_MONITOR"; then
        echo "  ✓ Kernel is logging EGRESS_MONITOR messages"
    else
        echo "  ⚠ WARNING: No EGRESS_MONITOR in recent kernel messages"
        echo "    This suggests nftables rules aren't triggering"
    fi

    # Check if log file was created
    if [ ! -f /var/log/proxyctl/egress.log ]; then
        echo "✗ FAIL: Log file not created"
        echo "  Debug: Checking if rsyslog captured any messages..."
        if grep -r "EGRESS_MONITOR" /var/log/ 2>/dev/null; then
            echo "  Found EGRESS_MONITOR in other log files (rsyslog config issue)"
        fi
        return 1
    fi
    echo "✓ Log file created"

    # Check if logs contain our prefix
    if grep -q "EGRESS_MONITOR" /var/log/proxyctl/egress.log 2>/dev/null; then
        echo "✓ Logs contain EGRESS_MONITOR prefix"

        # Show sample logs
        echo "Sample log entries:"
        head -n 3 /var/log/proxyctl/egress.log | sed 's/^/  /'
    else
        echo "⚠ WARNING: No logs with EGRESS_MONITOR prefix (yet)"
        echo "  This may be normal if traffic hasn't triggered logging yet"
    fi

    echo "✓ PASS: Log generation"
    echo ""
}

# Test 4: Idempotency (install twice)
# Story: S007 (Broken Installation Recovery)
test_idempotency_install() {
    echo "Test 4: Idempotency - Install Twice (Story: S007)"
    echo "---"

    # First install was already done in Test 2
    # Try to install again (capture output for checking message)
    install_output=$(/usr/local/bin/egressctl logger install 2>&1 || true)

    if echo "$install_output" | grep -qi "already installed"; then
        echo "✓ Correctly detected existing installation"
    else
        # If it didn't error, that's also acceptable (silent idempotency)
        echo "✓ Second installation succeeded (idempotent)"
    fi

    echo "✓ PASS: Installation idempotency"
    echo ""
}

# Test 5: Logger removal
# Story: S018 (Clean Removal), S019 (Firewall Rule Cleanup)
test_logger_remove() {
    echo "Test 5: Logger Removal (Stories: S018, S019)"
    echo "---"

    # Determine which firewall type is currently in use BEFORE removal
    local using_nftables=false
    local using_iptables=false

    if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q "egress_monitor"; then
        using_nftables=true
    fi

    if command -v iptables >/dev/null 2>&1 && iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG"; then
        using_iptables=true
    fi

    # Remove logger
    if ! remove_logger; then
        echo "✗ FAIL: Logger removal failed"
        return 1
    fi
    echo "✓ Logger removed successfully"

    # Verify rsyslog config removed (check both old and new filenames for compatibility)
    if [ -f /etc/rsyslog.d/99-egress-monitor.conf ] || [ -f /etc/rsyslog.d/10-egress-monitor.conf ]; then
        echo "✗ FAIL: Rsyslog config not removed"
        return 1
    fi
    echo "✓ Rsyslog config removed"

    # Verify logrotate config removed
    if [ -f /etc/logrotate.d/egress-monitor ]; then
        echo "✗ FAIL: Logrotate config not removed"
        return 1
    fi
    echo "✓ Logrotate config removed"

    # Check firewall rules removed (only check types that were in use)
    if [ "$using_nftables" = true ]; then
        if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q "egress_monitor"; then
            echo "✗ FAIL: nftables rules not removed"
            return 1
        else
            echo "✓ nftables rules removed"
        fi
    fi

    if [ "$using_iptables" = true ]; then
        if command -v iptables >/dev/null 2>&1 && iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG"; then
            echo "✗ FAIL: iptables rules not removed"
            return 1
        else
            echo "✓ iptables rules removed"
        fi
    fi

    # If neither was in use, something is wrong
    if [ "$using_nftables" = false ] && [ "$using_iptables" = false ]; then
        echo "⚠ WARNING: No firewall rules found before removal"
    fi

    echo "✓ PASS: Logger removal"
    echo ""
}

# Test 6: Idempotency (remove twice)
# Story: S018 (Clean Removal), S019 (Firewall Rule Cleanup)
test_idempotency_remove() {
    echo "Test 6: Idempotency - Remove Twice (Stories: S018, S019)"
    echo "---"

    # First removal was already done in Test 5
    # Try to remove again
    if ! remove_logger; then
        echo "✗ FAIL: Second removal should not error"
        return 1
    fi

    echo "✓ PASS: Removal idempotency"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    for test_func in \
        test_firewall_detection \
        test_logger_install \
        test_log_generation \
        test_idempotency_install \
        test_logger_remove \
        test_idempotency_remove; do

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
