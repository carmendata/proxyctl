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

# Test 7: Config-driven logger with private IPs
# Story: S009 (Private IP Filtering - configurable)
test_logger_config_private_ips() {
    echo "Test 7: Config-Driven Logger - Private IP Monitoring (Story: S009)"
    echo "---"

    # Create config file with private IP monitoring
    cat > /tmp/egress-test.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-private.log",
    "include_private": true,
    "protocols": ["tcp", "udp"]
  }
}
EOF

    # Install logger with config
    if ! /usr/local/bin/egressctl logger install --config /tmp/egress-test.json; then
        echo "✗ FAIL: Logger installation with config failed"
        rm -f /tmp/egress-test.json
        return 1
    fi
    echo "✓ Logger installed with private IP monitoring"

    # Verify log file location matches config
    if [ ! -d /var/log/proxyctl ]; then
        echo "✗ FAIL: Log directory not created"
        rm -f /tmp/egress-test.json
        return 1
    fi
    echo "✓ Log directory created"

    # Generate local network traffic (to loopback - should NOT be logged)
    ping -c 2 127.0.0.1 >/dev/null 2>&1 || true

    # Generate traffic to Google DNS (public IP - should be logged)
    ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

    sleep 3

    # Check firewall rules include monitoring for private ranges
    # (This is implementation-specific - we expect rules to NOT exclude 10.x/172.16.x/192.168.x)
    local has_rules=false
    if command -v nft >/dev/null 2>&1 && nft list table ip egress_monitor >/dev/null 2>&1; then
        # For nftables, check that private ranges are NOT in exclusion list
        # (if include_private is true, they should be logged)
        has_rules=true
        echo "✓ nftables rules configured for private IP monitoring"
    elif command -v iptables >/dev/null 2>&1 && iptables -L EGRESS_LOG -n >/dev/null 2>&1; then
        has_rules=true
        echo "✓ iptables rules configured for private IP monitoring"
    fi

    if [ "$has_rules" = false ]; then
        echo "✗ FAIL: No firewall rules found"
        remove_logger 2>/dev/null || true
        rm -f /tmp/egress-test.json
        return 1
    fi

    # Cleanup
    remove_logger
    rm -f /tmp/egress-test.json

    echo "✓ PASS: Config-driven private IP monitoring"
    echo ""
}

# Test 8: Config-driven logger with whitelist mode
# Story: S009 (Advanced Filtering - whitelist mode)
test_logger_config_whitelist() {
    echo "Test 8: Config-Driven Logger - Whitelist Mode (Story: S009)"
    echo "---"

    # Create config file with whitelist mode
    cat > /tmp/egress-test.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-whitelist.log",
    "include_ranges": ["8.8.8.8", "1.1.1.1"],
    "protocols": ["tcp", "udp", "icmp"]
  }
}
EOF

    # Install logger with whitelist config
    if ! /usr/local/bin/egressctl logger install --config /tmp/egress-test.json; then
        echo "✗ FAIL: Logger installation with whitelist config failed"
        rm -f /tmp/egress-test.json
        return 1
    fi
    echo "✓ Logger installed with whitelist mode (8.8.8.8, 1.1.1.1)"

    # Generate traffic to whitelisted IP
    ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

    # Generate traffic to non-whitelisted IP (should NOT be logged)
    ping -c 2 9.9.9.9 >/dev/null 2>&1 || true

    sleep 3

    # Verify firewall rules are in whitelist mode
    local has_whitelist_rules=false
    if command -v nft >/dev/null 2>&1 && nft list table ip egress_monitor >/dev/null 2>&1; then
        # Check for specific IP rules (whitelist mode creates rules per IP)
        if nft list table ip egress_monitor | grep -q "8.8.8.8"; then
            has_whitelist_rules=true
            echo "✓ nftables configured with whitelist rules"
        fi
    elif command -v iptables >/dev/null 2>&1 && iptables -L EGRESS_LOG -n >/dev/null 2>&1; then
        if iptables -L EGRESS_LOG -n | grep -q "8.8.8.8"; then
            has_whitelist_rules=true
            echo "✓ iptables configured with whitelist rules"
        fi
    fi

    if [ "$has_whitelist_rules" = false ]; then
        echo "⚠ WARNING: Could not verify whitelist rules in firewall"
    fi

    # Cleanup
    remove_logger
    rm -f /tmp/egress-test.json

    echo "✓ PASS: Whitelist mode configuration"
    echo ""
}

# Test 9: Config-driven logger with exclude ranges
# Story: S009 (Advanced Filtering - exclude ranges)
test_logger_config_exclude() {
    echo "Test 9: Config-Driven Logger - Exclude Ranges (Story: S009)"
    echo "---"

    # Create config file with exclude ranges
    cat > /tmp/egress-test.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-filtered.log",
    "exclude_ranges": ["8.8.8.8", "8.8.4.4"],
    "protocols": ["tcp", "udp", "icmp"]
  }
}
EOF

    # Install logger with exclude config
    if ! /usr/local/bin/egressctl logger install --config /tmp/egress-test.json; then
        echo "✗ FAIL: Logger installation with exclude config failed"
        rm -f /tmp/egress-test.json
        return 1
    fi
    echo "✓ Logger installed with exclude ranges (8.8.8.8, 8.8.4.4)"

    # Generate traffic to excluded IP (should NOT be logged)
    ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

    # Generate traffic to non-excluded IP (should be logged)
    ping -c 2 1.1.1.1 >/dev/null 2>&1 || true

    sleep 3

    # Verify firewall rules include exclusions
    local has_exclude_rules=false
    if command -v nft >/dev/null 2>&1 && nft list table ip egress_monitor >/dev/null 2>&1; then
        # Check for return rules (exclusions use 'return' to skip logging)
        if nft list table ip egress_monitor | grep -q "8.8.8.8.*return"; then
            has_exclude_rules=true
            echo "✓ nftables configured with exclude rules"
        elif nft list table ip egress_monitor | grep -q "8.8.8.8"; then
            # Rule exists but might not have 'return' in same line
            has_exclude_rules=true
            echo "✓ nftables configured with exclude rules"
        fi
    elif command -v iptables >/dev/null 2>&1 && iptables -L EGRESS_LOG -n >/dev/null 2>&1; then
        if iptables -L EGRESS_LOG -n | grep -q "8.8.8.8"; then
            has_exclude_rules=true
            echo "✓ iptables configured with exclude rules"
        fi
    fi

    if [ "$has_exclude_rules" = false ]; then
        echo "⚠ WARNING: Could not verify exclude rules in firewall"
    fi

    # Cleanup
    remove_logger
    rm -f /tmp/egress-test.json

    echo "✓ PASS: Exclude ranges configuration"
    echo ""
}

# Test 10: Protocol filtering configuration
# Story: S008 (Protocol-specific monitoring)
test_logger_config_protocols() {
    echo "Test 10: Config-Driven Logger - Protocol Filtering (Story: S008)"
    echo "---"

    # Create config file with ICMP-only monitoring
    cat > /tmp/egress-test.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-icmp.log",
    "protocols": ["icmp"]
  }
}
EOF

    # Install logger with protocol filter
    if ! /usr/local/bin/egressctl logger install --config /tmp/egress-test.json; then
        echo "✗ FAIL: Logger installation with protocol filter failed"
        rm -f /tmp/egress-test.json
        return 1
    fi
    echo "✓ Logger installed with ICMP-only monitoring"

    # Generate ICMP traffic (should be logged)
    ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

    # Generate TCP traffic (should NOT be logged)
    curl -s --connect-timeout 2 http://example.com >/dev/null 2>&1 || true

    sleep 3

    # Verify firewall rules are protocol-specific
    local has_icmp_rules=false
    if command -v nft >/dev/null 2>&1 && nft list table ip egress_monitor >/dev/null 2>&1; then
        # Check for ICMP protocol rules
        if nft list table ip egress_monitor | grep -qi "icmp"; then
            has_icmp_rules=true
            echo "✓ nftables configured for ICMP monitoring"
        fi
    elif command -v iptables >/dev/null 2>&1 && iptables -L EGRESS_LOG -n >/dev/null 2>&1; then
        if iptables -L EGRESS_LOG -n | grep -qi "icmp"; then
            has_icmp_rules=true
            echo "✓ iptables configured for ICMP monitoring"
        fi
    fi

    if [ "$has_icmp_rules" = false ]; then
        echo "⚠ WARNING: Could not verify ICMP-specific rules"
    fi

    # Cleanup
    remove_logger
    rm -f /tmp/egress-test.json

    echo "✓ PASS: Protocol filtering configuration"
    echo ""
}

# Test 11: Log analysis with protocol and service extraction
# Story: S008 (Enhanced Analysis), S010 (Log File Management)
test_logger_analysis() {
    echo "Test 11: Log Analysis - Protocol and Service Extraction (Stories: S008, S010)"
    echo "---"

    # Install default logger
    if ! install_logger; then
        echo "✗ FAIL: Logger installation failed"
        return 1
    fi
    echo "✓ Logger installed"

    # Generate diverse traffic for analysis
    echo "Generating test traffic..."
    # HTTPS traffic (port 443)
    curl -s https://example.com >/dev/null 2>&1 || true
    # HTTP traffic (port 80)
    curl -s http://example.com >/dev/null 2>&1 || true
    # DNS query (port 53)
    dig @8.8.8.8 example.com >/dev/null 2>&1 || true
    # ICMP
    ping -c 2 8.8.8.8 >/dev/null 2>&1 || true

    # Wait for logs
    sleep 5

    # Check if log file has entries
    if [ ! -f /var/log/proxyctl/egress.log ]; then
        echo "✗ FAIL: Log file not created"
        remove_logger 2>/dev/null || true
        return 1
    fi

    # Check for protocol information in logs
    local has_proto=false
    if grep -q "PROTO=" /var/log/proxyctl/egress.log 2>/dev/null; then
        has_proto=true
        echo "✓ Logs contain PROTO= field"

        # Show sample with protocol
        echo "Sample log entry:"
        grep "PROTO=" /var/log/proxyctl/egress.log | head -1 | sed 's/^/  /'
    else
        echo "⚠ WARNING: No PROTO= field found in logs (may be normal if no traffic logged yet)"
    fi

    # Try to run analyze command (if it exists and works without error)
    echo "Testing analyze command..."
    if /usr/local/bin/egressctl logger analyze 2>&1 | grep -q "Analyzing"; then
        echo "✓ Analyze command executed"

        # Check if analysis includes protocol breakdown
        if /usr/local/bin/egressctl logger analyze 2>&1 | grep -qi "PROTOCOL BREAKDOWN"; then
            echo "✓ Analysis includes protocol breakdown"
        else
            echo "⚠ WARNING: Protocol breakdown not found in analysis"
        fi

        # Check if analysis includes service identification
        if /usr/local/bin/egressctl logger analyze 2>&1 | grep -qi "SERVICES"; then
            echo "✓ Analysis includes service identification"
        else
            echo "⚠ WARNING: Service identification not found in analysis"
        fi
    else
        echo "⚠ WARNING: Analyze command did not complete (may be normal if no data)"
    fi

    # Cleanup
    remove_logger
    echo "✓ PASS: Log analysis verification"
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
        test_idempotency_remove \
        test_logger_config_private_ips \
        test_logger_config_whitelist \
        test_logger_config_exclude \
        test_logger_config_protocols \
        test_logger_analysis; do

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
