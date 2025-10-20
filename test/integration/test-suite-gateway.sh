#!/bin/bash
#
# Integration test suite for gateway routing
#
# Tests gateway-based policy routing using fwmark, ip route, ip rule, and systemd persistence
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Gateway Routing"
echo "Started: $(date)"
echo "========================================"
echo ""

# Source common helper functions
SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/common-helpers.sh"

# Verify binary is deployed and functional
echo "Verifying egressctl binary..."
if [ ! -f /usr/local/bin/egressctl ]; then
    echo "ERROR: egressctl binary not found at /usr/local/bin/egressctl"
    exit 1
fi

if [ ! -x /usr/local/bin/egressctl ]; then
    echo "ERROR: egressctl binary is not executable"
    exit 1
fi

# Test that binary can run
if ! /usr/local/bin/egressctl version >/dev/null 2>&1; then
    echo "ERROR: egressctl version command failed"
    exit 1
fi

echo "✓ Binary verified and functional"
echo ""

# Helper functions

# Apply firewall with gateway routing
apply_gateway_routing() {
    local config_file="$1"
    echo "yes" | /usr/local/bin/egressctl firewall apply --config "$config_file" || return 1
    return 0
}

# Remove firewall and gateway routing
remove_gateway_routing() {
    /usr/local/bin/egressctl firewall remove || return 1
    return 0
}

# Test 1: Firewall detection before gateway routing
test_firewall_detection() {
    echo "Test 1: Firewall Detection"
    echo "---"

    local has_iptables=false
    local has_nftables=false

    # Check iptables
    if command -v iptables >/dev/null 2>&1; then
        has_iptables=true
        echo "✓ iptables available: $(iptables --version 2>&1 | head -1)"
    fi

    # Check nftables
    if command -v nft >/dev/null 2>&1; then
        has_nftables=true
        echo "✓ nftables available: $(nft --version 2>&1 | head -1)"
    fi

    # At least one should be available
    if [ "$has_iptables" = false ] && [ "$has_nftables" = false ]; then
        echo "✗ FAIL: No firewall tools detected"
        return 1
    fi

    echo "✓ PASS: Firewall detection"
    echo ""
}

# Test 2: Gateway routing configuration validation
test_gateway_config_validation() {
    echo "Test 2: Gateway Routing Configuration Validation"
    echo "---"

    # Detect the actual gateway from the default route
    local actual_gateway=$(ip route show default | awk '/default via/{print $3; exit}')
    if [ -z "$actual_gateway" ]; then
        echo "✗ FAIL: Could not detect default gateway"
        ip route show default
        return 1
    fi

    echo "  Detected default gateway: $actual_gateway"

    # Create test config with gateway routing using actual gateway
    cat > /tmp/gateway-test-config.json <<EOF
{
  "mode": "egress",
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
  },
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "gateway": "$actual_gateway",
    "targets": ["8.8.8.8", "1.1.1.1"],
    "routing_table": 200
  }
}
EOF

    echo "  Created test config with gateway routing"

    # Validate the config loads correctly
    local status_output=$(/usr/local/bin/egressctl status --config /tmp/gateway-test-config.json 2>&1)
    if ! echo "$status_output" | grep -qi "gateway"; then
        echo "✗ FAIL: Config validation failed - 'gateway' not found in status output"
        echo "Status output:"
        echo "$status_output"
        echo ""
        echo "Config file:"
        cat /tmp/gateway-test-config.json
        return 1
    fi

    echo "✓ PASS: Gateway config validation"
    echo ""
}

# Test 3: Apply gateway routing and verify packet marking
test_apply_gateway_routing() {
    echo "Test 3: Apply Gateway Routing (Packet Marking)"
    echo "---"

    # Apply gateway routing
    if ! apply_gateway_routing /tmp/gateway-test-config.json; then
        echo "✗ FAIL: Failed to apply gateway routing"
        return 1
    fi

    echo "  Gateway routing applied"

    # Detect firewall type and check packet marking rules
    local firewall_type=""
    if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q "proxyctl_gateway"; then
        firewall_type="nftables"
    elif command -v iptables >/dev/null 2>&1 && iptables -t mangle -L PROXYCTL_GATEWAY -n 2>/dev/null | grep -q "MARK"; then
        firewall_type="iptables"
    else
        echo "✗ FAIL: Could not detect packet marking rules"
        return 1
    fi

    echo "  Firewall type: $firewall_type"

    # Verify packet marking rules based on firewall type
    if [ "$firewall_type" = "nftables" ]; then
        # Check nftables rules
        local nft_output=$(nft list table ip proxyctl_gateway 2>&1)

        # Check for gateway targets
        if ! echo "$nft_output" | grep -q "ip daddr 8.8.8.8"; then
            echo "✗ FAIL: Target 8.8.8.8 not found in packet marking rules"
            echo "$nft_output"
            return 1
        fi

        if ! echo "$nft_output" | grep -q "ip daddr 1.1.1.1"; then
            echo "✗ FAIL: Target 1.1.1.1 not found in packet marking rules"
            echo "$nft_output"
            return 1
        fi

        # Check for mark set (nftables shows in hex: 0xc8 = 200)
        if ! echo "$nft_output" | grep -qE "(mark set 200|mark set 0x0*c8)"; then
            echo "✗ FAIL: fwmark 200 (0xc8) not found in rules"
            echo "$nft_output"
            return 1
        fi

        # Check for priority mangle (or -150)
        if ! echo "$nft_output" | grep -qE "(priority (mangle|-150))"; then
            echo "✗ FAIL: Priority mangle/-150 not found"
            echo "$nft_output"
            return 1
        fi

        echo "  ✓ nftables packet marking rules verified"

    elif [ "$firewall_type" = "iptables" ]; then
        # Check iptables rules
        local ipt_output=$(iptables -t mangle -L PROXYCTL_GATEWAY -n -v 2>&1)

        # Check for gateway targets
        if ! echo "$ipt_output" | grep -q "8.8.8.8"; then
            echo "✗ FAIL: Target 8.8.8.8 not found in packet marking rules"
            echo "$ipt_output"
            return 1
        fi

        if ! echo "$ipt_output" | grep -q "1.1.1.1"; then
            echo "✗ FAIL: Target 1.1.1.1 not found in packet marking rules"
            echo "$ipt_output"
            return 1
        fi

        # Check for MARK target
        if ! echo "$ipt_output" | grep -q "MARK.*set 0xc8"; then  # 0xc8 = 200 in hex
            echo "✗ FAIL: MARK set 0xc8 (200) not found in rules"
            echo "$ipt_output"
            return 1
        fi

        echo "  ✓ iptables packet marking rules verified"
    fi

    echo "✓ PASS: Gateway routing applied with packet marking"
    echo ""
}

# Test 4: Verify routing table configuration
test_routing_table() {
    echo "Test 4: Routing Table Configuration"
    echo "---"

    # Get the gateway from the config we created
    local expected_gateway=$(grep '"gateway":' /tmp/gateway-test-config.json | sed 's/.*"gateway": "\([^"]*\)".*/\1/')

    # Check /etc/iproute2/rt_tables for routing table entry
    if ! grep -q "200.*egress" /etc/iproute2/rt_tables; then
        echo "✗ FAIL: Routing table entry not found in /etc/iproute2/rt_tables"
        cat /etc/iproute2/rt_tables
        return 1
    fi

    echo "  ✓ Routing table entry found in /etc/iproute2/rt_tables"

    # Check if gateway route exists in routing table
    if ! ip route show table egress 2>/dev/null | grep -q "$expected_gateway"; then
        echo "✗ FAIL: Gateway route via $expected_gateway not found in routing table 'egress'"
        ip route show table egress 2>/dev/null || echo "  (table doesn't exist)"
        return 1
    fi

    echo "  ✓ Gateway route configured (via $expected_gateway)"

    echo "✓ PASS: Routing table configuration"
    echo ""
}

# Test 5: Verify policy routing rule
test_policy_routing_rule() {
    echo "Test 5: Policy Routing Rule (fwmark -> table)"
    echo "---"

    # Check if policy routing rule exists (fwmark 200 -> table egress)
    local rule_output=$(ip rule list 2>&1)

    # Check for fwmark 200 (can be shown as decimal 200 or hex 0xc8)
    if ! echo "$rule_output" | grep -qE "fwmark.*(200|0x0*c8)"; then
        echo "✗ FAIL: Policy routing rule for fwmark 200 (0xc8) not found"
        echo "$rule_output"
        return 1
    fi

    if ! echo "$rule_output" | grep -q "lookup egress"; then
        echo "✗ FAIL: Policy routing rule doesn't lookup table 'egress'"
        echo "$rule_output"
        return 1
    fi

    echo "  ✓ Policy routing rule: fwmark 200 (0xc8) -> table egress"

    echo "✓ PASS: Policy routing rule configuration"
    echo ""
}

# Test 6: Verify systemd service persistence
test_systemd_persistence() {
    echo "Test 6: Systemd Service Persistence"
    echo "---"

    # Check if systemd service file exists
    if [ ! -f /etc/systemd/system/proxyctl-routing.service ]; then
        echo "✗ FAIL: Systemd service file not found"
        return 1
    fi

    echo "  ✓ Service file exists: /etc/systemd/system/proxyctl-routing.service"

    # Check if service is active
    if ! systemctl is-active --quiet proxyctl-routing.service; then
        echo "✗ FAIL: Systemd service is not active"
        systemctl status proxyctl-routing.service || true
        return 1
    fi

    echo "  ✓ Service is active"

    # Check if service is enabled
    if ! systemctl is-enabled --quiet proxyctl-routing.service; then
        echo "✗ FAIL: Systemd service is not enabled"
        return 1
    fi

    echo "  ✓ Service is enabled (will start on boot)"

    echo "✓ PASS: Systemd persistence configuration"
    echo ""
}

# Test 7: Verify status command shows gateway routing
test_status_display() {
    echo "Test 7: Status Command Display"
    echo "---"

    # Get the gateway from the config we created
    local expected_gateway=$(grep '"gateway":' /tmp/gateway-test-config.json | sed 's/.*"gateway": "\([^"]*\)".*/\1/')

    # Get status output
    local status_output=$(/usr/local/bin/egressctl status --config /tmp/gateway-test-config.json 2>&1)

    # Check for gateway routing information
    if ! echo "$status_output" | grep -qi "gateway"; then
        echo "✗ FAIL: Status output doesn't show gateway routing"
        echo "$status_output"
        return 1
    fi

    # Check for specific gateway configuration
    if ! echo "$status_output" | grep -q "$expected_gateway"; then
        echo "✗ FAIL: Gateway IP $expected_gateway not shown in status"
        echo "$status_output"
        return 1
    fi

    echo "  ✓ Status shows gateway routing configuration"

    # Check that there are no drift warnings (⚠)
    if echo "$status_output" | grep -q "⚠"; then
        echo "  WARNING: Status shows drift warnings:"
        echo "$status_output" | grep "⚠"
    else
        echo "  ✓ No drift detected (config matches deployment)"
    fi

    echo "✓ PASS: Status display shows gateway routing"
    echo ""
}

# Test 8: Verify config file integration
test_config_file_formats() {
    echo "Test 8: Configuration File Formats"
    echo "---"

    # Test with custom routing table
    cat > /tmp/gateway-custom-table.json <<EOF
{
  "mode": "egress",
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "gateway": "192.168.1.1",
    "targets": ["8.8.4.4"],
    "routing_table": 150
  }
}
EOF
    sync  # Ensure file is written to disk

    # Verify config file was created correctly
    if [ ! -f /tmp/gateway-custom-table.json ]; then
        echo "✗ FAIL: Config file was not created"
        return 1
    fi

    # Validate custom table config
    echo "  Checking status output for custom routing table 150..."
    local status_output=$(/usr/local/bin/egressctl status --config /tmp/gateway-custom-table.json 2>&1)
    local status_exit_code=$?

    # Check if status command succeeded
    if [ $status_exit_code -ne 0 ]; then
        echo "✗ FAIL: Status command failed with exit code $status_exit_code"
        echo "Output was:"
        echo "$status_output"
        return 1
    fi

    if ! echo "$status_output" | grep -q "150"; then
        echo "✗ FAIL: Custom routing table not recognized"
        echo "Status output was:"
        echo "$status_output"
        return 1
    fi

    echo "  ✓ Custom routing table configuration validated"

    # Test with default routing table (should default to 200)
    cat > /tmp/gateway-default-table.json <<EOF
{
  "mode": "egress",
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "gateway": "10.106.80.2",
    "targets": ["1.1.1.1"]
  }
}
EOF
    sync  # Ensure file is written to disk

    # Verify config file was created correctly
    if [ ! -f /tmp/gateway-default-table.json ]; then
        echo "✗ FAIL: Default config file was not created"
        return 1
    fi

    # Validate default table config
    local default_output=$(/usr/local/bin/egressctl status --config /tmp/gateway-default-table.json 2>&1)
    local default_exit_code=$?

    if [ $default_exit_code -ne 0 ]; then
        echo "✗ FAIL: Default routing table configuration failed with exit code $default_exit_code"
        echo "Output was:"
        echo "$default_output"
        return 1
    fi

    echo "  ✓ Default routing table configuration validated"

    echo "✓ PASS: Configuration file format validation"
    echo ""
}

# Test 9: Verify gateway routing removal
test_gateway_removal() {
    echo "Test 9: Gateway Routing Removal"
    echo "---"

    # Remove gateway routing
    if ! remove_gateway_routing; then
        echo "✗ FAIL: Failed to remove gateway routing"
        return 1
    fi

    echo "  ✓ Gateway routing removed"

    # Verify packet marking rules are removed
    local firewall_type=""
    if command -v nft >/dev/null 2>&1; then
        if nft list tables 2>/dev/null | grep -q "proxyctl_gateway"; then
            echo "✗ FAIL: nftables table still exists after removal"
            nft list table ip proxyctl_gateway
            return 1
        fi
        firewall_type="nftables"
    fi

    if command -v iptables >/dev/null 2>&1; then
        if iptables -t mangle -L PROXYCTL_GATEWAY -n 2>/dev/null; then
            echo "✗ FAIL: iptables chain still exists after removal"
            iptables -t mangle -L PROXYCTL_GATEWAY -n
            return 1
        fi
        firewall_type="iptables"
    fi

    echo "  ✓ Packet marking rules removed ($firewall_type)"

    # Verify policy routing rule is removed (check both decimal 200 and hex 0xc8)
    if ip rule list 2>&1 | grep -qE "fwmark.*(200|0x0*c8)"; then
        echo "✗ FAIL: Policy routing rule still exists"
        ip rule list
        return 1
    fi

    echo "  ✓ Policy routing rule removed"

    # Verify systemd service is removed
    if systemctl is-active --quiet proxyctl-routing.service 2>/dev/null; then
        echo "✗ FAIL: Systemd service still active"
        return 1
    fi

    if [ -f /etc/systemd/system/proxyctl-routing.service ]; then
        echo "✗ FAIL: Systemd service file still exists"
        return 1
    fi

    echo "  ✓ Systemd service removed"

    echo "✓ PASS: Gateway routing removal"
    echo ""
}

# Test 10: Verify invalid configuration detection
test_invalid_config() {
    echo "Test 10: Invalid Configuration Detection"
    echo "---"

    # Test 1: Gateway without gateway IP
    cat > /tmp/gateway-invalid-1.json <<EOF
{
  "mode": "egress",
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "targets": ["8.8.8.8"]
  }
}
EOF

    local output1=$(/usr/local/bin/egressctl firewall apply --config /tmp/gateway-invalid-1.json --dry-run 2>&1)
    if echo "$output1" | grep -qi "gateway.*required"; then
        echo "  ✓ Correctly detected missing gateway IP"
    else
        echo "✗ FAIL: Did not detect missing gateway IP"
        echo "Expected error matching 'gateway.*required', got:"
        echo "$output1"
        return 1
    fi

    # Test 2: Gateway without targets
    cat > /tmp/gateway-invalid-2.json <<EOF
{
  "mode": "egress",
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "gateway": "10.106.80.2"
  }
}
EOF

    local output2=$(/usr/local/bin/egressctl firewall apply --config /tmp/gateway-invalid-2.json --dry-run 2>&1)
    if echo "$output2" | grep -qi "targets"; then
        echo "  ✓ Correctly detected missing targets"
    else
        echo "✗ FAIL: Did not detect missing targets"
        echo "Expected error matching 'targets', got:"
        echo "$output2"
        return 1
    fi

    # Test 3: Invalid routing table
    cat > /tmp/gateway-invalid-3.json <<EOF
{
  "mode": "egress",
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "gateway",
    "gateway": "10.106.80.2",
    "targets": ["8.8.8.8"],
    "routing_table": 255
  }
}
EOF

    local output3=$(/usr/local/bin/egressctl firewall apply --config /tmp/gateway-invalid-3.json --dry-run 2>&1)
    if echo "$output3" | grep -qi "routing.*table"; then
        echo "  ✓ Correctly detected invalid routing table ID"
    else
        echo "✗ FAIL: Did not detect invalid routing table ID"
        echo "Expected error matching 'routing.*table', got:"
        echo "$output3"
        return 1
    fi

    echo "✓ PASS: Invalid configuration detection"
    echo ""
}

# Run all tests
main() {
    local failed=0

    # Ensure clean state
    echo "Cleaning up any existing gateway routing..."
    /usr/local/bin/egressctl firewall remove 2>/dev/null || true
    echo ""

    # Run tests
    test_firewall_detection || ((failed++))
    test_gateway_config_validation || ((failed++))
    test_apply_gateway_routing || ((failed++))
    test_routing_table || ((failed++))
    test_policy_routing_rule || ((failed++))
    test_systemd_persistence || ((failed++))
    test_status_display || ((failed++))
    test_config_file_formats || ((failed++))
    test_gateway_removal || ((failed++))
    test_invalid_config || ((failed++))

    # Final cleanup
    echo "Final cleanup..."
    /usr/local/bin/egressctl firewall remove 2>/dev/null || true
    rm -f /tmp/gateway-*.json
    echo ""

    echo "========================================"
    echo "Test Suite: Gateway Routing"
    echo "Completed: $(date)"
    if [ $failed -eq 0 ]; then
        echo "Result: ALL TESTS PASSED"
        echo "========================================"
        exit 0
    else
        echo "Result: $failed TESTS FAILED"
        echo "========================================"
        exit 1
    fi
}

# Run main
main
