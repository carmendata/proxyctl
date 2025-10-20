#!/bin/bash
#
# Integration test suite for proxyctl multi-chain logger functionality (Phase 2)
#
# Tests the following features:
# - Multiple chain support (INPUT, OUTPUT, FORWARD)
# - Per-chain log files (e.g., egress-input.log, egress-output.log)
# - Per-chain log prefixes (e.g., EGRESS_MONITOR_INPUT:, EGRESS_MONITOR_OUTPUT:)
# - Multi-chain with custom logger names
# - Logrotate with multiple files
# - Both nftables and iptables backends
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output-multichain.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Logger Multi-Chain (Phase 2)"
echo "Started: $(date)"
echo "========================================"
echo ""

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."
    remove_logger 2>/dev/null || true
    rm -f /tmp/egress-test.json
    rm -f /tmp/test-*.json
    exit $exit_code
}

trap cleanup EXIT

# Helper functions
install_logger() {
    /usr/local/bin/egressctl logger install "$@" || return 1
    return 0
}

remove_logger() {
    /usr/local/bin/egressctl logger remove || return 1
    return 0
}

# Detect firewall type
detect_firewall() {
    if command -v nft >/dev/null 2>&1 && systemctl is-active nftables >/dev/null 2>&1; then
        echo "nftables"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

# Test 1: Single OUTPUT chain with per-chain log files (backward compatibility)
test_multichain_single_output() {
    echo "Test 1: Multi-Chain Logger - Single OUTPUT Chain (Backward Compatibility)"
    echo "---"

    # Install default logger (should use OUTPUT chain by default)
    if ! install_logger; then
        echo "✗ FAIL: Logger installation failed"
        return 1
    fi
    echo "✓ Logger installed"

    # Verify per-chain log file naming (egress-output.log, not egress.log)
    echo "Checking log file naming..."

    # Generate traffic to trigger log file creation
    curl -s http://example.com >/dev/null 2>&1 || true
    sleep 3

    # Check that rsyslog config uses per-chain prefix and filename
    if ! grep -q "EGRESS_MONITOR_OUTPUT:" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config doesn't use per-chain prefix EGRESS_MONITOR_OUTPUT:"
        cat /etc/rsyslog.d/10-egress-monitor.conf
        return 1
    fi
    echo "✓ Rsyslog uses per-chain prefix: EGRESS_MONITOR_OUTPUT:"

    if ! grep -q "egress-output.log" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config doesn't use per-chain log file egress-output.log"
        cat /etc/rsyslog.d/10-egress-monitor.conf
        return 1
    fi
    echo "✓ Rsyslog uses per-chain log file: egress-output.log"

    # Verify firewall rules
    local fw_type=$(detect_firewall)
    if [ "$fw_type" = "nftables" ]; then
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "chain output"; then
            echo "✗ FAIL: nftables OUTPUT chain not found"
            nft list table ip egress_monitor
            return 1
        fi
        echo "✓ nftables OUTPUT chain created"

        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "type filter hook output"; then
            echo "✗ FAIL: nftables OUTPUT hook not found"
            return 1
        fi
        echo "✓ nftables OUTPUT hook configured"
    elif [ "$fw_type" = "iptables" ]; then
        if ! iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables EGRESS_LOG_OUTPUT chain not found"
            iptables -L -n
            return 1
        fi
        echo "✓ iptables EGRESS_LOG_OUTPUT chain created"

        if ! iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG_OUTPUT"; then
            echo "✗ FAIL: iptables jump rule to EGRESS_LOG_OUTPUT not found"
            iptables -L OUTPUT -n
            return 1
        fi
        echo "✓ iptables jump rule configured"
    fi

    # Verify logrotate includes per-chain file
    if ! grep -q "egress-output.log" /etc/logrotate.d/egress-monitor; then
        echo "✗ FAIL: Logrotate doesn't include egress-output.log"
        cat /etc/logrotate.d/egress-monitor
        return 1
    fi
    echo "✓ Logrotate configured for egress-output.log"

    # Check if log file created with per-chain naming
    if [ -f /var/log/proxyctl/egress-output.log ]; then
        echo "✓ Per-chain log file created: egress-output.log"

        if grep -q "EGRESS_MONITOR_OUTPUT:" /var/log/proxyctl/egress-output.log 2>/dev/null; then
            echo "✓ Logs contain per-chain prefix"
        else
            echo "⚠ WARNING: No logs with per-chain prefix yet"
        fi
    else
        echo "⚠ WARNING: Log file not created yet (may need more traffic)"
    fi

    # Cleanup
    remove_logger

    echo "✓ PASS: Single OUTPUT chain with per-chain log files"
    echo ""
}

# Test 2: INPUT chain only
test_multichain_input_only() {
    echo "Test 2: Multi-Chain Logger - INPUT Chain Only"
    echo "---"

    # Create config with INPUT chain
    cat > /tmp/test-input.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "egress",
    "chains": ["INPUT"],
    "protocols": ["tcp", "udp"]
  }
}
EOF

    if ! install_logger --config /tmp/test-input.json; then
        echo "✗ FAIL: Logger installation with INPUT chain failed"
        rm -f /tmp/test-input.json
        return 1
    fi
    echo "✓ Logger installed with INPUT chain"

    # Verify firewall rules
    local fw_type=$(detect_firewall)
    if [ "$fw_type" = "nftables" ]; then
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "chain input"; then
            echo "✗ FAIL: nftables INPUT chain not found"
            nft list table ip egress_monitor
            return 1
        fi
        echo "✓ nftables INPUT chain created"

        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "type filter hook input"; then
            echo "✗ FAIL: nftables INPUT hook not configured"
            return 1
        fi
        echo "✓ nftables INPUT hook configured"
    elif [ "$fw_type" = "iptables" ]; then
        if ! iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables EGRESS_LOG_INPUT chain not found"
            return 1
        fi
        echo "✓ iptables EGRESS_LOG_INPUT chain created"

        if ! iptables -L INPUT -n 2>/dev/null | grep -q "EGRESS_LOG_INPUT"; then
            echo "✗ FAIL: iptables jump rule not found in INPUT chain"
            return 1
        fi
        echo "✓ iptables jump rule configured"
    fi

    # Verify rsyslog config
    if ! grep -q "EGRESS_MONITOR_INPUT:" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config doesn't contain EGRESS_MONITOR_INPUT: prefix"
        cat /etc/rsyslog.d/10-egress-monitor.conf
        return 1
    fi
    echo "✓ Rsyslog config contains INPUT chain prefix"

    if ! grep -q "egress-input.log" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config doesn't reference egress-input.log"
        return 1
    fi
    echo "✓ Rsyslog config references egress-input.log"

    # Verify logrotate
    if ! grep -q "egress-input.log" /etc/logrotate.d/egress-monitor; then
        echo "✗ FAIL: Logrotate doesn't include egress-input.log"
        return 1
    fi
    echo "✓ Logrotate configured for egress-input.log"

    # Cleanup
    remove_logger
    rm -f /tmp/test-input.json

    echo "✓ PASS: INPUT chain configuration"
    echo ""
}

# Test 3: All three chains (INPUT + OUTPUT + FORWARD)
test_multichain_all_chains() {
    echo "Test 3: Multi-Chain Logger - INPUT + OUTPUT + FORWARD"
    echo "---"

    # Create config with all chains
    cat > /tmp/test-all.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "egress",
    "chains": ["INPUT", "OUTPUT", "FORWARD"],
    "protocols": ["tcp", "udp", "icmp"]
  }
}
EOF

    if ! install_logger --config /tmp/test-all.json; then
        echo "✗ FAIL: Logger installation with multiple chains failed"
        rm -f /tmp/test-all.json
        return 1
    fi
    echo "✓ Logger installed with INPUT, OUTPUT, and FORWARD chains"

    # Verify firewall rules
    local fw_type=$(detect_firewall)
    if [ "$fw_type" = "nftables" ]; then
        # Check for all three chains in nftables
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "chain input"; then
            echo "✗ FAIL: nftables INPUT chain not found"
            nft list table ip egress_monitor
            return 1
        fi
        echo "✓ nftables INPUT chain created"

        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "chain output"; then
            echo "✗ FAIL: nftables OUTPUT chain not found"
            return 1
        fi
        echo "✓ nftables OUTPUT chain created"

        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "chain forward"; then
            echo "✗ FAIL: nftables FORWARD chain not found"
            return 1
        fi
        echo "✓ nftables FORWARD chain created"

        # Verify hooks
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "type filter hook input"; then
            echo "✗ FAIL: INPUT hook not configured"
            return 1
        fi
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "type filter hook output"; then
            echo "✗ FAIL: OUTPUT hook not configured"
            return 1
        fi
        if ! nft list table ip egress_monitor 2>/dev/null | grep -q "type filter hook forward"; then
            echo "✗ FAIL: FORWARD hook not configured"
            return 1
        fi
        echo "✓ All three netfilter hooks configured"

    elif [ "$fw_type" = "iptables" ]; then
        if ! iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables EGRESS_LOG_INPUT chain not found"
            return 1
        fi
        echo "✓ iptables EGRESS_LOG_INPUT chain created"

        if ! iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables EGRESS_LOG_OUTPUT chain not found"
            return 1
        fi
        echo "✓ iptables EGRESS_LOG_OUTPUT chain created"

        if ! iptables -L EGRESS_LOG_FORWARD -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables EGRESS_LOG_FORWARD chain not found"
            return 1
        fi
        echo "✓ iptables EGRESS_LOG_FORWARD chain created"
    fi

    # Verify rsyslog has three separate filters
    if ! grep -q "# INPUT chain" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config missing INPUT chain section"
        cat /etc/rsyslog.d/10-egress-monitor.conf
        return 1
    fi
    echo "✓ Rsyslog has INPUT chain section"

    if ! grep -q "# OUTPUT chain" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config missing OUTPUT chain section"
        return 1
    fi
    echo "✓ Rsyslog has OUTPUT chain section"

    if ! grep -q "# FORWARD chain" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Rsyslog config missing FORWARD chain section"
        return 1
    fi
    echo "✓ Rsyslog has FORWARD chain section"

    # Verify all three prefixes
    if ! grep -q "EGRESS_MONITOR_INPUT:" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing EGRESS_MONITOR_INPUT: prefix"
        return 1
    fi
    if ! grep -q "EGRESS_MONITOR_OUTPUT:" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing EGRESS_MONITOR_OUTPUT: prefix"
        return 1
    fi
    if ! grep -q "EGRESS_MONITOR_FORWARD:" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing EGRESS_MONITOR_FORWARD: prefix"
        return 1
    fi
    echo "✓ All three per-chain prefixes configured"

    # Verify all three log files referenced
    if ! grep -q "egress-input.log" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing egress-input.log reference"
        return 1
    fi
    if ! grep -q "egress-output.log" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing egress-output.log reference"
        return 1
    fi
    if ! grep -q "egress-forward.log" /etc/rsyslog.d/10-egress-monitor.conf; then
        echo "✗ FAIL: Missing egress-forward.log reference"
        return 1
    fi
    echo "✓ All three per-chain log files configured"

    # Verify logrotate includes all three files
    if ! grep -q "egress-input.log" /etc/logrotate.d/egress-monitor; then
        echo "✗ FAIL: Logrotate missing egress-input.log"
        cat /etc/logrotate.d/egress-monitor
        return 1
    fi
    if ! grep -q "egress-output.log" /etc/logrotate.d/egress-monitor; then
        echo "✗ FAIL: Logrotate missing egress-output.log"
        return 1
    fi
    if ! grep -q "egress-forward.log" /etc/logrotate.d/egress-monitor; then
        echo "✗ FAIL: Logrotate missing egress-forward.log"
        return 1
    fi
    echo "✓ Logrotate configured for all three log files"

    # Generate OUTPUT traffic
    curl -s http://example.com >/dev/null 2>&1 || true
    sleep 3

    # Check log file separation
    if [ -f /var/log/proxyctl/egress-output.log ]; then
        echo "✓ OUTPUT log file created"

        if grep -q "EGRESS_MONITOR_OUTPUT:" /var/log/proxyctl/egress-output.log 2>/dev/null; then
            echo "✓ OUTPUT logs contain correct prefix"

            # Verify no cross-contamination
            if grep -q "EGRESS_MONITOR_INPUT:" /var/log/proxyctl/egress-output.log 2>/dev/null; then
                echo "✗ FAIL: OUTPUT log contains INPUT prefix (cross-contamination)"
                return 1
            fi
            if grep -q "EGRESS_MONITOR_FORWARD:" /var/log/proxyctl/egress-output.log 2>/dev/null; then
                echo "✗ FAIL: OUTPUT log contains FORWARD prefix (cross-contamination)"
                return 1
            fi
            echo "✓ No cross-contamination in OUTPUT logs"
        fi
    else
        echo "⚠ WARNING: OUTPUT log file not created yet"
    fi

    # Cleanup
    remove_logger
    rm -f /tmp/test-all.json

    echo "✓ PASS: All three chains configuration"
    echo ""
}

# Test 4: Multi-chain removal
test_multichain_removal() {
    echo "Test 4: Multi-Chain Logger - Complete Removal"
    echo "---"

    # Install with all chains
    cat > /tmp/test-all.json <<'EOF'
{
  "logger": {
    "enabled": true,
    "name": "egress",
    "chains": ["INPUT", "OUTPUT", "FORWARD"]
  }
}
EOF

    if ! install_logger --config /tmp/test-all.json; then
        echo "✗ FAIL: Logger installation failed"
        rm -f /tmp/test-all.json
        return 1
    fi
    echo "✓ Logger installed with all chains"

    # Verify all chains exist
    local fw_type=$(detect_firewall)
    if [ "$fw_type" = "nftables" ]; then
        local chain_count=$(nft list table ip egress_monitor 2>/dev/null | grep -c "chain " || echo "0")
        if [ "$chain_count" -ne 3 ]; then
            echo "✗ FAIL: Expected 3 chains, found $chain_count"
            nft list table ip egress_monitor
            return 1
        fi
        echo "✓ All 3 nftables chains verified"
    elif [ "$fw_type" = "iptables" ]; then
        if ! iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: INPUT chain not found before removal"
            return 1
        fi
        if ! iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: OUTPUT chain not found before removal"
            return 1
        fi
        if ! iptables -L EGRESS_LOG_FORWARD -n >/dev/null 2>&1; then
            echo "✗ FAIL: FORWARD chain not found before removal"
            return 1
        fi
        echo "✓ All 3 iptables chains verified"
    fi

    # Remove logger
    if ! remove_logger; then
        echo "✗ FAIL: Logger removal failed"
        return 1
    fi
    echo "✓ Logger removed"

    # Verify all chains removed
    if [ "$fw_type" = "nftables" ]; then
        if nft list table ip egress_monitor 2>/dev/null; then
            echo "✗ FAIL: nftables table still exists after removal"
            nft list table ip egress_monitor
            return 1
        fi
        echo "✓ nftables table removed"
    elif [ "$fw_type" = "iptables" ]; then
        if iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: INPUT chain still exists after removal"
            return 1
        fi
        if iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: OUTPUT chain still exists after removal"
            return 1
        fi
        if iptables -L EGRESS_LOG_FORWARD -n >/dev/null 2>&1; then
            echo "✗ FAIL: FORWARD chain still exists after removal"
            return 1
        fi
        echo "✓ All iptables chains removed"
    fi

    # Verify rsyslog config removed
    if [ -f /etc/rsyslog.d/10-egress-monitor.conf ]; then
        echo "✗ FAIL: Rsyslog config still exists"
        return 1
    fi
    echo "✓ Rsyslog config removed"

    # Verify logrotate removed
    if [ -f /etc/logrotate.d/egress-monitor ]; then
        echo "✗ FAIL: Logrotate config still exists"
        return 1
    fi
    echo "✓ Logrotate config removed"

    rm -f /tmp/test-all.json

    echo "✓ PASS: Multi-chain removal"
    echo ""
}

# Test 5: Multi-chain with custom name
test_multichain_custom_name() {
    echo "Test 5: Multi-Chain Logger - Custom Name with Multiple Chains"
    echo "---"

    cat > /tmp/test-custom.json <<'EOF'
{
  "logger": {
    "enabled": true,
    "name": "db-primary",
    "chains": ["INPUT", "OUTPUT"],
    "protocols": ["tcp"]
  }
}
EOF

    if ! install_logger --config /tmp/test-custom.json; then
        echo "✗ FAIL: Logger installation with custom name failed"
        rm -f /tmp/test-custom.json
        return 1
    fi
    echo "✓ Logger installed with custom name 'db-primary'"

    # Verify custom-named table
    local fw_type=$(detect_firewall)
    if [ "$fw_type" = "nftables" ]; then
        if ! nft list table ip db_primary_monitor >/dev/null 2>&1; then
            echo "✗ FAIL: nftables table 'db_primary_monitor' not found"
            nft list tables
            return 1
        fi
        echo "✓ nftables table created: db_primary_monitor"
    elif [ "$fw_type" = "iptables" ]; then
        if ! iptables -L DB_PRIMARY_LOG_INPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables chain 'DB_PRIMARY_LOG_INPUT' not found"
            return 1
        fi
        if ! iptables -L DB_PRIMARY_LOG_OUTPUT -n >/dev/null 2>&1; then
            echo "✗ FAIL: iptables chain 'DB_PRIMARY_LOG_OUTPUT' not found"
            return 1
        fi
        echo "✓ iptables chains created with custom name"
    fi

    # Verify rsyslog config
    if [ ! -f /etc/rsyslog.d/10-db-primary-monitor.conf ]; then
        echo "✗ FAIL: Rsyslog config not created with custom name"
        ls -la /etc/rsyslog.d/
        return 1
    fi
    echo "✓ Rsyslog config created: /etc/rsyslog.d/10-db-primary-monitor.conf"

    # Verify custom prefixes
    if ! grep -q "DB_PRIMARY_MONITOR_INPUT:" /etc/rsyslog.d/10-db-primary-monitor.conf; then
        echo "✗ FAIL: Missing DB_PRIMARY_MONITOR_INPUT: prefix"
        cat /etc/rsyslog.d/10-db-primary-monitor.conf
        return 1
    fi
    if ! grep -q "DB_PRIMARY_MONITOR_OUTPUT:" /etc/rsyslog.d/10-db-primary-monitor.conf; then
        echo "✗ FAIL: Missing DB_PRIMARY_MONITOR_OUTPUT: prefix"
        return 1
    fi
    echo "✓ Custom prefixes configured correctly"

    # Verify custom log file paths
    if ! grep -q "db-primary-input.log" /etc/rsyslog.d/10-db-primary-monitor.conf; then
        echo "✗ FAIL: Missing db-primary-input.log reference"
        return 1
    fi
    if ! grep -q "db-primary-output.log" /etc/rsyslog.d/10-db-primary-monitor.conf; then
        echo "✗ FAIL: Missing db-primary-output.log reference"
        return 1
    fi
    echo "✓ Custom log file paths configured"

    # Verify logrotate with custom name
    if [ ! -f /etc/logrotate.d/db-primary-monitor ]; then
        echo "✗ FAIL: Logrotate config not created with custom name"
        return 1
    fi
    echo "✓ Logrotate config created: /etc/logrotate.d/db-primary-monitor"

    # Cleanup
    remove_logger
    rm -f /tmp/test-custom.json

    echo "✓ PASS: Multi-chain with custom name"
    echo ""
}

# Test 6: Logrotate with multiple files
test_multichain_logrotate() {
    echo "Test 6: Multi-Chain Logger - Logrotate with Multiple Files"
    echo "---"

    cat > /tmp/test.json <<'EOF'
{
  "logger": {
    "enabled": true,
    "name": "egress",
    "chains": ["INPUT", "OUTPUT", "FORWARD"]
  }
}
EOF

    if ! install_logger --config /tmp/test.json; then
        echo "✗ FAIL: Logger installation failed"
        rm -f /tmp/test.json
        return 1
    fi
    echo "✓ Logger installed"

    # Verify logrotate config format
    echo "Checking logrotate configuration..."
    cat /etc/logrotate.d/egress-monitor

    # Verify first line contains all three log files
    local first_line=$(head -1 /etc/logrotate.d/egress-monitor)
    if ! echo "$first_line" | grep -q "egress-input.log"; then
        echo "✗ FAIL: First line doesn't contain egress-input.log"
        echo "First line: $first_line"
        return 1
    fi
    if ! echo "$first_line" | grep -q "egress-output.log"; then
        echo "✗ FAIL: First line doesn't contain egress-output.log"
        return 1
    fi
    if ! echo "$first_line" | grep -q "egress-forward.log"; then
        echo "✗ FAIL: First line doesn't contain egress-forward.log"
        return 1
    fi
    echo "✓ Logrotate first line contains all three log files"

    # Test logrotate dry-run
    echo "Testing logrotate dry-run..."
    local logrotate_output=$(logrotate -d /etc/logrotate.d/egress-monitor 2>&1)

    # Filter out state file errors (normal on first run)
    local filtered_errors=$(echo "$logrotate_output" | grep -i "error" | grep -v "state file" || true)

    if [ -n "$filtered_errors" ]; then
        echo "✗ FAIL: Logrotate dry-run has errors"
        echo "$filtered_errors"
        return 1
    fi
    echo "✓ Logrotate dry-run passed"

    # Verify all three files would be rotated
    if ! echo "$logrotate_output" | grep -q "egress-input.log"; then
        echo "✗ FAIL: Logrotate wouldn't rotate egress-input.log"
        return 1
    fi
    if ! echo "$logrotate_output" | grep -q "egress-output.log"; then
        echo "✗ FAIL: Logrotate wouldn't rotate egress-output.log"
        return 1
    fi
    if ! echo "$logrotate_output" | grep -q "egress-forward.log"; then
        echo "✗ FAIL: Logrotate wouldn't rotate egress-forward.log"
        return 1
    fi
    echo "✓ All three log files configured for rotation"

    # Cleanup
    remove_logger
    rm -f /tmp/test.json

    echo "✓ PASS: Logrotate with multiple files"
    echo ""
}

# Test 7: iptables backend (if available)
test_multichain_iptables() {
    echo "Test 7: Multi-Chain Logger - iptables Backend"
    echo "---"

    # Check if iptables is available and being used
    local fw_type=$(detect_firewall)
    if [ "$fw_type" != "iptables" ]; then
        echo "SKIP: iptables not in use (using $fw_type)"
        echo ""
        return 0
    fi

    cat > /tmp/test.json <<'EOF'
{
  "logger": {
    "enabled": true,
    "name": "egress",
    "chains": ["INPUT", "OUTPUT"]
  }
}
EOF

    if ! install_logger --config /tmp/test.json; then
        echo "✗ FAIL: Logger installation failed"
        rm -f /tmp/test.json
        return 1
    fi
    echo "✓ Logger installed with iptables backend"

    # Verify separate iptables chains created
    if ! iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
        echo "✗ FAIL: EGRESS_LOG_INPUT chain not found"
        iptables -L -n
        return 1
    fi
    echo "✓ iptables chain created: EGRESS_LOG_INPUT"

    if ! iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
        echo "✗ FAIL: EGRESS_LOG_OUTPUT chain not found"
        return 1
    fi
    echo "✓ iptables chain created: EGRESS_LOG_OUTPUT"

    # Verify jump rules in base chains
    if ! iptables -L INPUT -n 2>/dev/null | grep -q "EGRESS_LOG_INPUT"; then
        echo "✗ FAIL: Jump rule not found in INPUT chain"
        iptables -L INPUT -n
        return 1
    fi
    echo "✓ Jump rule configured in INPUT chain"

    if ! iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG_OUTPUT"; then
        echo "✗ FAIL: Jump rule not found in OUTPUT chain"
        iptables -L OUTPUT -n
        return 1
    fi
    echo "✓ Jump rule configured in OUTPUT chain"

    # Remove and verify cleanup
    if ! remove_logger; then
        echo "✗ FAIL: Logger removal failed"
        return 1
    fi
    echo "✓ Logger removed"

    # Verify chains removed
    if iptables -L EGRESS_LOG_INPUT -n >/dev/null 2>&1; then
        echo "✗ FAIL: EGRESS_LOG_INPUT chain still exists"
        return 1
    fi
    if iptables -L EGRESS_LOG_OUTPUT -n >/dev/null 2>&1; then
        echo "✗ FAIL: EGRESS_LOG_OUTPUT chain still exists"
        return 1
    fi
    echo "✓ All iptables chains removed"

    # Verify jump rules removed
    if iptables -L INPUT -n 2>/dev/null | grep -q "EGRESS_LOG_INPUT"; then
        echo "✗ FAIL: Jump rule still in INPUT chain"
        return 1
    fi
    if iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG_OUTPUT"; then
        echo "✗ FAIL: Jump rule still in OUTPUT chain"
        return 1
    fi
    echo "✓ All jump rules removed"

    rm -f /tmp/test.json

    echo "✓ PASS: iptables multi-chain support"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    # Verify binary is available
    if [ ! -f /usr/local/bin/egressctl ]; then
        echo "ERROR: egressctl binary not found at /usr/local/bin/egressctl"
        exit 1
    fi

    echo "Firewall type: $(detect_firewall)"
    echo ""

    for test_func in \
        test_multichain_single_output \
        test_multichain_input_only \
        test_multichain_all_chains \
        test_multichain_removal \
        test_multichain_custom_name \
        test_multichain_logrotate \
        test_multichain_iptables; do

        if ! $test_func; then
            failed_tests+=("$test_func")
        fi
    done

    echo "========================================"
    echo "Test Results - Multi-Chain Logger"
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
