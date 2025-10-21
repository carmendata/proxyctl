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

# Source common helper functions
SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/common-helpers.sh"

# Helper functions for firewall operations with proper error handling

# Apply firewall rules
# Usage: apply_firewall_rules <config_file> [capture_output]
# Returns: 0 on success, 1 on failure
apply_firewall_rules() {
    local config_file="$1"
    local capture_output="${2:-false}"

    if [ "$capture_output" = "true" ]; then
        echo "yes" | /usr/local/bin/egressctl firewall apply --config "$config_file" 2>&1 | tee /tmp/apply-output.log || return 1
    else
        echo "yes" | /usr/local/bin/egressctl firewall apply --config "$config_file" || return 1
    fi

    return 0
}

# Remove firewall rules
# Returns: 0 on success, 1 on failure
remove_firewall_rules() {
    /usr/local/bin/egressctl firewall remove || return 1
    return 0
}

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

# Test 7: INPUT filtering application (v0.8.0)
test_input_filtering_apply() {
    echo "Test 7: INPUT Filtering Application (v0.8.0)"
    echo "---"

    # Detect SSH IP to prevent lockout
    SSH_IP=$(get_ssh_ip) || {
        echo "✗ FAIL: Could not detect SSH IP"
        return 1
    }
    validate_ssh_whitelist "$SSH_IP" || return 1
    echo "  Using SSH IP: $SSH_IP"

    # Create test config with detected SSH IP
    cat > /tmp/test-firewall-input.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["$SSH_IP"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Apply firewall rules (non-interactive, force yes)
    if ! apply_firewall_rules /tmp/test-firewall-input.json; then
        echo "✗ FAIL: Failed to apply INPUT filtering"
        return 1
    fi

    # Verify rules were created
    local rules_found=false

    # Check nftables (primary method)
    if command -v nft >/dev/null 2>&1; then
        # Note: grep -q can cause SIGPIPE (exit 141) with pipefail when it finds a match and exits early
        # We need to handle both success (0) and SIGPIPE (141) as success
        nft list table inet proxyctl_filter 2>/dev/null | grep -q "tcp dport"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✓ nftables: SSH rule created"
            rules_found=true
        fi
    fi

    # Check iptables (fallback)
    if [ "$rules_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_INPUT -n 2>/dev/null | grep -q "tcp dpt:22"; then
            echo "✓ iptables: SSH rule created"
            rules_found=true
        fi
    fi

    if [ "$rules_found" = false ]; then
        echo "✗ FAIL: No INPUT filtering rules found"
        return 1
    fi

    echo "✓ PASS: INPUT filtering applied"
    echo ""
}

# Test 8: OUTPUT redirect partial (v0.8.0)
test_output_redirect_partial() {
    echo "Test 8: OUTPUT Redirect - Partial (v0.8.0)"
    echo "---"

    # Create test config
    cat > /tmp/test-firewall-redirect-partial.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  }
}
EOF

    # Apply redirect rules (non-interactive)
    if ! apply_firewall_rules /tmp/test-firewall-redirect-partial.json; then
        echo "✗ FAIL: Failed to apply partial redirect"
        return 1
    fi

    # Verify redirect rules
    local rules_found=false

    # Check nftables (primary method)
    if command -v nft >/dev/null 2>&1; then
        # Note: grep -q can cause SIGPIPE (exit 141) with pipefail when it finds a match and exits early
        # We need to handle both success (0) and SIGPIPE (141) as success
        nft list table ip proxyctl_redirect 2>/dev/null | grep -q "dnat to"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✓ nftables: Redirect rule created"
            rules_found=true
        fi
    fi

    # Check iptables (fallback)
    if [ "$rules_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -t nat -L PROXYCTL_OUTPUT -n 2>/dev/null | grep -q "DNAT"; then
            echo "✓ iptables: Redirect rule created"
            rules_found=true
        fi
    fi

    if [ "$rules_found" = false ]; then
        echo "✗ FAIL: No redirect rules found"
        return 1
    fi

    echo "✓ PASS: Partial redirect applied"
    echo ""
}

# Test 9: OUTPUT redirect full (v0.8.0)
test_output_redirect_full() {
    echo "Test 9: OUTPUT Redirect - Full (v0.8.0)"
    echo "---"

    # First remove existing rules (cleanup, okay if it fails)
    remove_firewall_rules 2>/dev/null || true

    # Create test config
    cat > /tmp/test-firewall-redirect-full.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
EOF

    # Apply redirect rules (non-interactive)
    if ! apply_firewall_rules /tmp/test-firewall-redirect-full.json; then
        echo "✗ FAIL: Failed to apply full redirect"
        return 1
    fi

    # Verify redirect rules (should redirect ports 80 and 443)
    local rules_found=false

    # Check nftables (primary method)
    if command -v nft >/dev/null 2>&1; then
        # Note: grep -q can cause SIGPIPE (exit 141) with pipefail when it finds a match and exits early
        # We need to handle both success (0) and SIGPIPE (141) as success
        nft list table ip proxyctl_redirect 2>/dev/null | grep -q "tcp dport"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✓ nftables: Full redirect rule created"
            rules_found=true
        fi
    fi

    # Check iptables (fallback)
    if [ "$rules_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -t nat -L PROXYCTL_OUTPUT -n 2>/dev/null | grep -q "tcp dpt:80"; then
            echo "✓ iptables: Full redirect rule created"
            rules_found=true
        fi
    fi

    if [ "$rules_found" = false ]; then
        echo "✗ FAIL: No full redirect rules found"
        return 1
    fi

    echo "✓ PASS: Full redirect applied"
    echo ""
}

# Test 10: Backup creation (v0.8.0)
test_backup_creation() {
    echo "Test 10: Backup Creation (v0.8.0)"
    echo "---"

    # Detect SSH IP to prevent lockout
    SSH_IP=$(get_ssh_ip) || {
        echo "✗ FAIL: Could not detect SSH IP"
        return 1
    }
    validate_ssh_whitelist "$SSH_IP" || return 1
    echo "  Using SSH IP: $SSH_IP"

    # Apply some rules first
    cat > /tmp/test-firewall-backup.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["$SSH_IP"]
  }
}
EOF

    if ! apply_firewall_rules /tmp/test-firewall-backup.json true; then
        echo "✗ FAIL: Failed to apply firewall rules for backup test"
        return 1
    fi

    # Check if backup was created
    if grep -q "Backup created:" /tmp/apply-output.log; then
        echo "✓ Backup file created during apply"
    else
        echo "✗ FAIL: No backup created"
        return 1
    fi

    # Verify backup directory exists
    if [ -d "/var/lib/proxyctl/firewall-backups" ]; then
        echo "✓ Backup directory exists"
    else
        echo "  Warning: Backup directory not found (may not have permissions)"
    fi

    echo "✓ PASS: Backup creation"
    echo ""
}

# Test 11: Firewall removal (v0.8.0)
test_firewall_remove() {
    echo "Test 11: Firewall Removal (v0.8.0)"
    echo "---"

    # Remove all firewall rules
    if ! remove_firewall_rules; then
        echo "✗ FAIL: Failed to remove firewall rules"
        return 1
    fi

    # Verify rules were removed
    local rules_removed=true
    if command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_INPUT -n 2>/dev/null | grep -q "Chain PROXYCTL_INPUT"; then
            echo "✗ iptables: PROXYCTL_INPUT chain still exists"
            rules_removed=false
        else
            echo "✓ iptables: PROXYCTL_INPUT chain removed"
        fi

        if iptables -t nat -L PROXYCTL_OUTPUT -n 2>/dev/null | grep -q "Chain PROXYCTL_OUTPUT"; then
            echo "✗ iptables: PROXYCTL_OUTPUT chain still exists"
            rules_removed=false
        else
            echo "✓ iptables: PROXYCTL_OUTPUT chain removed"
        fi
    fi

    if command -v nft >/dev/null 2>&1; then
        # Note: grep -q can cause SIGPIPE (exit 141) with pipefail
        # We need to handle both success (0) and SIGPIPE (141) as "table found"
        nft list table inet proxyctl_filter 2>/dev/null | grep -q "table inet proxyctl_filter"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✗ nftables: proxyctl_filter table still exists"
            rules_removed=false
        else
            echo "✓ nftables: proxyctl_filter table removed"
        fi

        nft list table ip proxyctl_redirect 2>/dev/null | grep -q "table ip proxyctl_redirect"
        grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✗ nftables: proxyctl_redirect table still exists"
            rules_removed=false
        else
            echo "✓ nftables: proxyctl_redirect table removed"
        fi
    fi

    if [ "$rules_removed" = false ]; then
        echo "✗ FAIL: Some firewall rules were not removed"
        return 1
    fi

    echo "✓ PASS: Firewall removal"
    echo ""
}

# Test 12: FORWARD rules application (v0.4.0)
test_forward_rules_apply() {
    echo "Test 12: FORWARD Rules Application (v0.4.0)"
    echo "---"

    # First remove existing rules (cleanup, okay if it fails)
    remove_firewall_rules 2>/dev/null || true

    # Create test config with FORWARD rules
    cat > /tmp/test-firewall-forward.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "ignore",
    "forward_policy": "drop",
    "allow_forward_from": [
      {
        "sources": ["10.131.0.16/32"],
        "destinations": ["0.0.0.0/0"],
        "protocols": ["tcp", "udp", "icmp"]
      }
    ]
  }
}
EOF

    # Apply firewall rules (non-interactive)
    if ! apply_firewall_rules /tmp/test-firewall-forward.json; then
        echo "✗ FAIL: Failed to apply FORWARD rules"
        return 1
    fi

    # Verify FORWARD rules were created
    local rules_found=false

    # Check nftables (primary method)
    if command -v nft >/dev/null 2>&1; then
        nft list table ip proxyctl_forward 2>/dev/null | grep -q "chain forward"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✓ nftables: FORWARD chain created"
            rules_found=true
        fi
    fi

    # Check iptables (fallback)
    if [ "$rules_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_FORWARD -n 2>/dev/null | grep -q "Chain PROXYCTL_FORWARD"; then
            echo "✓ iptables: FORWARD chain created"
            rules_found=true
        fi
    fi

    if [ "$rules_found" = false ]; then
        echo "✗ FAIL: No FORWARD rules found"
        return 1
    fi

    echo "✓ PASS: FORWARD rules applied"
    echo ""
}

# Test 13: MASQUERADE rules application (v0.4.0)
test_masquerade_rules() {
    echo "Test 13: MASQUERADE Rules Application (v0.4.0)"
    echo "---"

    # First remove existing rules (cleanup, okay if it fails)
    remove_firewall_rules 2>/dev/null || true

    # Create test config with MASQUERADE enabled
    cat > /tmp/test-firewall-masquerade.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "ignore",
    "forward_policy": "drop",
    "allow_forward_from": [
      {
        "sources": ["10.131.0.16/32"],
        "masquerade": true
      }
    ]
  }
}
EOF

    # Apply firewall rules (non-interactive)
    if ! apply_firewall_rules /tmp/test-firewall-masquerade.json; then
        echo "✗ FAIL: Failed to apply MASQUERADE rules"
        return 1
    fi

    # Verify MASQUERADE rules were created
    local rules_found=false

    # Check nftables (primary method)
    if command -v nft >/dev/null 2>&1; then
        nft list table ip proxyctl_forward 2>/dev/null | grep -q "masquerade"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✓ nftables: MASQUERADE rule created"
            rules_found=true
        fi
    fi

    # Check iptables (fallback)
    if [ "$rules_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
            echo "✓ iptables: MASQUERADE rule created"
            rules_found=true
        fi
    fi

    if [ "$rules_found" = false ]; then
        echo "✗ FAIL: No MASQUERADE rules found"
        return 1
    fi

    echo "✓ PASS: MASQUERADE rules applied"
    echo ""
}

# Test 14: IP forwarding enabled (v0.4.0)
test_ip_forwarding() {
    echo "Test 14: IP Forwarding Enabled (v0.4.0)"
    echo "---"

    # IP forwarding should be enabled from previous test
    local forwarding=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")

    if [ "$forwarding" = "1" ]; then
        echo "✓ IP forwarding enabled"
    else
        echo "✗ FAIL: IP forwarding not enabled (got: $forwarding)"
        return 1
    fi

    # Check if it's persistent in /etc/sysctl.conf
    if grep -q "net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf 2>/dev/null; then
        echo "✓ IP forwarding persistent in /etc/sysctl.conf"
    else
        echo "  Warning: IP forwarding may not persist after reboot"
    fi

    echo "✓ PASS: IP forwarding enabled"
    echo ""
}

# Test 15: FORWARD rules removal (v0.4.0)
test_forward_rules_remove() {
    echo "Test 15: FORWARD Rules Removal (v0.4.0)"
    echo "---"

    # Remove all firewall rules
    if ! remove_firewall_rules; then
        echo "✗ FAIL: Failed to remove firewall rules"
        return 1
    fi

    # Verify FORWARD rules were removed
    local rules_removed=true

    # Check iptables
    if command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_FORWARD -n 2>/dev/null | grep -q "Chain PROXYCTL_FORWARD"; then
            echo "✗ iptables: PROXYCTL_FORWARD chain still exists"
            rules_removed=false
        else
            echo "✓ iptables: PROXYCTL_FORWARD chain removed"
        fi
    fi

    # Check nftables
    if command -v nft >/dev/null 2>&1; then
        nft list table ip proxyctl_forward 2>/dev/null | grep -q "table ip proxyctl_forward"
        local grep_exit=$?
        if [ $grep_exit -eq 0 ] || [ $grep_exit -eq 141 ]; then
            echo "✗ nftables: proxyctl_forward table still exists"
            rules_removed=false
        else
            echo "✓ nftables: proxyctl_forward table removed"
        fi
    fi

    if [ "$rules_removed" = false ]; then
        echo "✗ FAIL: Some FORWARD rules were not removed"
        return 1
    fi

    echo "✓ PASS: FORWARD rules removal"
    echo ""
}

# Test 16: Firewall status command (v0.8.0)
test_firewall_status() {
    echo "Test 16: Firewall Status Command (v0.8.0)"
    echo "---"

    # Run status command
    /usr/local/bin/egressctl firewall status || {
        echo "✗ FAIL: Status command failed"
        return 1
    }

    echo "✓ PASS: Firewall status"
    echo ""
}

# Test 17: INPUT (drop policy) + FORWARD with multiple protocols (regression test for v0.4.2 bugs)
# This test catches two critical bugs:
# 1. saveIPTables() failing with exit status 2 when iptables-persistent not installed
# 2. Multiple protocols being added to single iptables command (invalid syntax)
test_input_drop_with_forward_multiprotocol() {
    echo "Test 17: INPUT (drop) + FORWARD Multi-Protocol (v0.4.2 Regression)"
    echo "---"

    # First remove existing rules (cleanup, okay if it fails)
    remove_firewall_rules 2>/dev/null || true

    # Create test config with INPUT drop policy AND FORWARD rules with MULTIPLE protocols
    # This combination triggers both bugs fixed in v0.4.2
    cat > /tmp/test-input-forward-regression.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["0.0.0.0/0"],
    "forward_policy": "drop",
    "allow_forward_from": [
      {
        "sources": ["10.131.0.16/32"],
        "destinations": ["0.0.0.0/0"],
        "protocols": ["tcp", "udp", "icmp"],
        "masquerade": true
      }
    ]
  }
}
EOF

    # Apply firewall rules (non-interactive)
    # Before v0.4.2 fixes, this would fail with:
    # - "failed to apply INPUT filtering: exit status 2" (saveIPTables bug)
    # - "failed to apply FORWARD rules: exit status 2" (multi-protocol bug)
    if ! apply_firewall_rules /tmp/test-input-forward-regression.json; then
        echo "✗ FAIL: Failed to apply INPUT + FORWARD rules"
        echo "   This may indicate regression of v0.4.2 bugs:"
        echo "   - saveIPTables() not handling missing iptables-persistent"
        echo "   - Multiple protocols in single iptables command"
        return 1
    fi

    # Verify INPUT rules were created
    local input_found=false

    # Check nftables (try both possible table names)
    if command -v nft >/dev/null 2>&1; then
        # Try inet family (priority: -1)
        if nft list table inet proxyctl_filter 2>/dev/null | grep -q "type filter hook input"; then
            echo "✓ nftables: INPUT chain created (inet proxyctl_filter)"
            input_found=true
        # Try ip family as fallback
        elif nft list table ip proxyctl_filter 2>/dev/null | grep -q "type filter hook input"; then
            echo "✓ nftables: INPUT chain created (ip proxyctl_filter)"
            input_found=true
        fi
    fi

    # Check iptables
    if [ "$input_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_INPUT -n 2>/dev/null | grep -q "Chain PROXYCTL_INPUT"; then
            echo "✓ iptables: INPUT chain created"
            input_found=true
        fi
    fi

    if [ "$input_found" = false ]; then
        echo "✗ FAIL: No INPUT rules found"
        echo "   Debug: Listing all nftables tables..."
        nft list tables 2>/dev/null || echo "   (nft command failed)"
        return 1
    fi

    # Verify FORWARD rules were created (separate rules for each protocol)
    local forward_found=false
    local protocol_count=0

    # Check nftables
    if command -v nft >/dev/null 2>&1; then
        if nft list table ip proxyctl_forward 2>/dev/null | grep -q "chain forward"; then
            echo "✓ nftables: FORWARD chain created"
            forward_found=true
        fi
    fi

    # Check iptables - verify we have separate rules for tcp, udp, icmp
    if [ "$forward_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -L PROXYCTL_FORWARD -n 2>/dev/null | grep -q "Chain PROXYCTL_FORWARD"; then
            # Count protocol-specific rules (should have 3: tcp, udp, icmp)
            protocol_count=$(iptables -L PROXYCTL_FORWARD -n | grep -c "10.131.0.16" || true)
            if [ "$protocol_count" -ge 3 ]; then
                echo "✓ iptables: FORWARD chain created with $protocol_count protocol rules"
                forward_found=true
            else
                echo "✗ FAIL: Expected 3+ FORWARD rules (tcp/udp/icmp), found $protocol_count"
                echo "   This indicates multi-protocol bug may have regressed"
                return 1
            fi
        fi
    fi

    if [ "$forward_found" = false ]; then
        echo "✗ FAIL: No FORWARD rules found"
        return 1
    fi

    # Verify MASQUERADE rule exists
    local masq_found=false

    # Check nftables
    if command -v nft >/dev/null 2>&1; then
        if nft list table ip proxyctl_forward 2>/dev/null | grep -q "masquerade"; then
            echo "✓ nftables: MASQUERADE rule created"
            masq_found=true
        fi
    fi

    # Check iptables
    if [ "$masq_found" = false ] && command -v iptables >/dev/null 2>&1; then
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE.*10.131.0.16"; then
            echo "✓ iptables: MASQUERADE rule created"
            masq_found=true
        fi
    fi

    if [ "$masq_found" = false ]; then
        echo "✗ FAIL: No MASQUERADE rule found"
        return 1
    fi

    # Verify IP forwarding is enabled
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    if [ "$ip_forward" != "1" ]; then
        echo "✗ FAIL: IP forwarding not enabled (got: $ip_forward)"
        return 1
    fi
    echo "✓ IP forwarding enabled"

    echo "✓ PASS: INPUT (drop) + FORWARD multi-protocol regression test"
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
        test_firewall_syntax \
        test_input_filtering_apply \
        test_output_redirect_partial \
        test_output_redirect_full \
        test_backup_creation \
        test_firewall_remove \
        test_forward_rules_apply \
        test_masquerade_rules \
        test_ip_forwarding \
        test_forward_rules_remove \
        test_firewall_status \
        test_input_drop_with_forward_multiprotocol; do

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
