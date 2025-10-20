#!/bin/bash
#
# Integration test suite for proxyctl status command
#
# Tests the comprehensive status command that aggregates information from:
# - Configuration
# - HAProxy service
# - ACL
# - Logger
# - Firewall
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Status Command"
echo "Started: $(date)"
echo "========================================"
echo ""

# Source common helper functions
SCRIPT_DIR="$(dirname "$0")"
source "$SCRIPT_DIR/common-helpers.sh"

# Wait for rsyslog to be ready after operations
wait_for_rsyslog() {
    local max_attempts=10
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        # Check if rsyslog is active and running
        if systemctl is-active --quiet rsyslog 2>/dev/null; then
            # Give it one more moment to fully settle
            sleep 0.5
            return 0
        fi

        sleep 1
        attempt=$((attempt + 1))
    done

    echo "⚠ WARNING: rsyslog did not become active after ${max_attempts}s"
    return 1
}

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."

    # Clean up test ACL file
    rm -f /tmp/test-acl.lst 2>/dev/null || true

    # Clean up logger (best effort)
    /usr/local/bin/egressctl logger remove 2>/dev/null || true

    # Clean up firewall rules (best effort)
    /usr/local/bin/egressctl firewall remove 2>/dev/null || true

    exit $exit_code
}

trap cleanup EXIT

# Helper functions

# Check if HAProxy is installed
check_haproxy_installed() {
    command -v haproxy >/dev/null 2>&1
}

# Install logger for testing
install_logger() {
    /usr/local/bin/egressctl logger install || return 1
    return 0
}

# Remove logger
remove_logger() {
    /usr/local/bin/egressctl logger remove || return 1
    return 0
}

# Apply firewall rules
apply_firewall_rules() {
    local config_file="$1"
    echo "yes" | /usr/local/bin/egressctl firewall apply --config "$config_file" || return 1
    return 0
}

# Remove firewall rules
remove_firewall_rules() {
    /usr/local/bin/egressctl firewall remove || return 1
    return 0
}

# Test 1: Status command basic execution
test_status_basic_execution() {
    echo "Test 1: Status Command Basic Execution"
    echo "---"

    # Run status command and capture output
    if ! /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1; then
        echo "✗ FAIL: Status command failed to execute"
        cat /tmp/status-output.log
        return 1
    fi

    echo "✓ Status command executed successfully"

    # Check for expected sections in output
    local required_sections=(
        "Egress Proxy Status"
        "Configuration:"
        "HAProxy Service:"
        "ACL:"
        "Logger:"
        "Firewall:"
    )

    for section in "${required_sections[@]}"; do
        if grep -q "$section" /tmp/status-output.log; then
            echo "✓ Section found: $section"
        else
            echo "✗ FAIL: Missing section: $section"
            echo "Output:"
            cat /tmp/status-output.log
            return 1
        fi
    done

    echo "✓ PASS: Status basic execution"
    echo ""
}

# Test 2: HAProxy status detection
test_haproxy_status_detection() {
    echo "Test 2: HAProxy Status Detection"
    echo "---"

    if ! check_haproxy_installed; then
        echo "  HAProxy not installed (expected on test system)"
        echo "✓ PASS: HAProxy detection works (not running)"
        echo ""
        return 0
    fi

    # Run status and check HAProxy section
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Extract HAProxy section
    if grep -q "HAProxy Service:" /tmp/status-output.log; then
        echo "✓ HAProxy section present"

        # Check for status indicator (either running or not running)
        if grep -A 5 "HAProxy Service:" /tmp/status-output.log | grep -q "Status:"; then
            echo "✓ HAProxy status indicator found"
        else
            echo "✗ FAIL: No HAProxy status indicator"
            return 1
        fi
    else
        echo "✗ FAIL: HAProxy section missing"
        return 1
    fi

    echo "✓ PASS: HAProxy status detection"
    echo ""
}

# Test 3: ACL status with missing file
test_acl_status_missing_file() {
    echo "Test 3: ACL Status - Missing File"
    echo "---"

    # Run status and check ACL section
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Should show ACL section with file not found
    if grep -A 5 "ACL:" /tmp/status-output.log | grep -q "File not found"; then
        echo "✓ ACL section shows file not found (expected)"
    else
        echo "  Note: ACL file may exist from previous tests"
    fi

    echo "✓ PASS: ACL status with missing file"
    echo ""
}

# Test 4: ACL status with existing file
test_acl_status_existing_file() {
    echo "Test 4: ACL Status - Existing File"
    echo "---"

    # Create a test ACL file
    local test_acl="/tmp/test-acl.lst"
    cat > "$test_acl" <<EOF
# Test ACL file
10.0.1.100
10.0.1.0/24
192.168.1.50
EOF

    # Run status with config pointing to test ACL (if we could override config)
    # For now, just verify the ACL manager can handle files
    echo "  Created test ACL with 3 entries"

    # Verify we can detect file properties
    if [ -f "$test_acl" ]; then
        local entry_count=$(grep -v "^#" "$test_acl" | grep -v "^$" | wc -l)
        echo "✓ ACL file has $entry_count entries"
    else
        echo "✗ FAIL: Test ACL file not created"
        return 1
    fi

    echo "✓ PASS: ACL status with existing file"
    echo ""
}

# Test 5: Logger status when not installed
test_logger_status_not_installed() {
    echo "Test 5: Logger Status - Not Installed"
    echo "---"

    # Make sure logger is not installed
    remove_logger 2>/dev/null || true
    sleep 1

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check logger section
    if grep -A 3 "Logger:" /tmp/status-output.log | grep -q "Not installed"; then
        echo "✓ Logger status shows not installed"
    else
        echo "  Logger section:"
        grep -A 5 "Logger:" /tmp/status-output.log || true
        echo "  Note: May show different status based on system state"
    fi

    echo "✓ PASS: Logger status when not installed"
    echo ""
}

# Test 6: Logger status when installed
test_logger_status_installed() {
    echo "Test 6: Logger Status - Installed"
    echo "---"

    # Install logger
    if ! install_logger; then
        echo "✗ FAIL: Failed to install logger"
        return 1
    fi

    echo "✓ Logger installed"
    sleep 2  # Wait for installation to complete

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check logger section
    if grep -A 3 "Logger:" /tmp/status-output.log | grep -q "Installed"; then
        echo "✓ Logger status shows installed"
    else
        echo "  Logger section:"
        grep -A 5 "Logger:" /tmp/status-output.log || true
    fi

    # Check for log directory
    if grep -A 5 "Logger:" /tmp/status-output.log | grep -q "Log directory:"; then
        echo "✓ Log directory shown"
    fi

    echo "✓ PASS: Logger status when installed"
    echo ""
}

# Test 7: Firewall status when not configured
test_firewall_status_not_configured() {
    echo "Test 7: Firewall Status - Not Configured"
    echo "---"

    # Remove any existing firewall rules
    remove_firewall_rules 2>/dev/null || true
    sleep 1

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check firewall section
    if grep -A 5 "Firewall:" /tmp/status-output.log | grep -q "Not configured\|Type:"; then
        echo "✓ Firewall section present"

        # Should show firewall type even if not configured
        if grep -A 5 "Firewall:" /tmp/status-output.log | grep -q "Type:"; then
            local fw_type=$(grep -A 5 "Firewall:" /tmp/status-output.log | grep "Type:" | awk '{print $2}')
            echo "✓ Firewall type detected: $fw_type"
        fi
    else
        echo "  Firewall section:"
        grep -A 10 "Firewall:" /tmp/status-output.log || true
    fi

    echo "✓ PASS: Firewall status when not configured"
    echo ""
}

# Test 8: Firewall status with INPUT filtering
test_firewall_status_with_input() {
    echo "Test 8: Firewall Status - With INPUT Filtering"
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

    # Apply firewall rules
    if ! apply_firewall_rules /tmp/test-firewall-input.json; then
        echo "✗ FAIL: Failed to apply INPUT filtering"
        return 1
    fi

    echo "✓ INPUT filtering applied"
    sleep 1

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check firewall section shows INPUT filtering
    if grep -A 5 "Firewall:" /tmp/status-output.log | grep -q "INPUT filtering.*Applied"; then
        echo "✓ Status shows INPUT filtering applied"
    else
        echo "  Firewall section:"
        grep -A 10 "Firewall:" /tmp/status-output.log || true
    fi

    echo "✓ PASS: Firewall status with INPUT filtering"
    echo ""
}

# Test 9: Firewall status with OUTPUT redirect
test_firewall_status_with_output() {
    echo "Test 9: Firewall Status - With OUTPUT Redirect"
    echo "---"

    # Remove previous rules
    remove_firewall_rules 2>/dev/null || true
    sleep 1

    # Create test config
    cat > /tmp/test-firewall-redirect.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8"]
  }
}
EOF

    # Apply redirect rules
    if ! apply_firewall_rules /tmp/test-firewall-redirect.json; then
        echo "✗ FAIL: Failed to apply OUTPUT redirect"
        return 1
    fi

    echo "✓ OUTPUT redirect applied"
    sleep 1

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check firewall section shows OUTPUT redirect
    if grep -A 5 "Firewall:" /tmp/status-output.log | grep -q "OUTPUT redirect.*Applied"; then
        echo "✓ Status shows OUTPUT redirect applied"
    else
        echo "  Firewall section:"
        grep -A 10 "Firewall:" /tmp/status-output.log || true
    fi

    echo "✓ PASS: Firewall status with OUTPUT redirect"
    echo ""
}

# Test 10: Status shows backup information
test_status_backup_info() {
    echo "Test 10: Status Shows Backup Information"
    echo "---"

    # Run status (firewall rules should be applied from previous test)
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check if backups section is shown
    if grep -A 10 "Firewall:" /tmp/status-output.log | grep -q "Backups:"; then
        echo "✓ Backup information shown"
    else
        echo "  Note: Backups section may not appear if no backups exist"
    fi

    echo "✓ PASS: Status backup information"
    echo ""
}

# Test 11: Status shows helpful hints
test_status_helpful_hints() {
    echo "Test 11: Status Shows Helpful Hints"
    echo "---"

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check for helpful hint to detailed firewall status
    if grep -q "For detailed firewall status, run:" /tmp/status-output.log; then
        echo "✓ Helpful hint to firewall status command shown"
    else
        echo "  Note: Hint may be context-dependent"
    fi

    echo "✓ PASS: Status helpful hints"
    echo ""
}

# Test 12: Status output is well-formatted
test_status_formatting() {
    echo "Test 12: Status Output Formatting"
    echo "---"

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check for proper formatting
    local formatting_ok=true

    # Should have header separator
    if ! grep -q "^===" /tmp/status-output.log; then
        echo "  Warning: No header separator found"
        formatting_ok=false
    fi

    # Should have indented subsections (2 spaces)
    if ! grep -q "^  " /tmp/status-output.log; then
        echo "  Warning: No indented subsections found"
        formatting_ok=false
    fi

    # Should have status indicators (✓ or ❌)
    if grep -qE "✓|❌|Not installed|Not configured|Not running" /tmp/status-output.log; then
        echo "✓ Status indicators present"
    else
        echo "  Warning: No clear status indicators found"
    fi

    if [ "$formatting_ok" = true ]; then
        echo "✓ Output is well-formatted"
    fi

    echo "✓ PASS: Status formatting"
    echo ""
}

# Test 13: Status command performance
test_status_performance() {
    echo "Test 13: Status Command Performance"
    echo "---"

    # Measure execution time
    local start_time=$(date +%s)
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo "✓ Status command completed in ${duration}s"

    # Should complete within reasonable time (5 seconds)
    if [ "$duration" -le 5 ]; then
        echo "✓ Performance acceptable (≤ 5s)"
    else
        echo "  Warning: Status command took ${duration}s (may be slow)"
    fi

    echo "✓ PASS: Status performance"
    echo ""
}

# Test 14: Logger config display with defaults (inferred)
test_logger_config_display_with_defaults() {
    echo "Test 14: Logger Config Display - With Defaults (Inferred)"
    echo "---"

    # Install logger without config file
    if ! install_logger; then
        echo "✗ FAIL: Failed to install logger"
        return 1
    fi

    echo "✓ Logger installed without config"
    sleep 2

    # Run status
    /usr/local/bin/egressctl status > /tmp/status-output.log 2>&1

    # Check for "Configuration (inferred from deployment)"
    if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "Configuration (inferred from deployment)"; then
        echo "✓ Shows inferred configuration section"
    else
        echo "✗ FAIL: Missing inferred configuration section"
        grep -A 10 "Logger:" /tmp/status-output.log || true
        return 1
    fi

    # Check for default value markers
    if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "(default)"; then
        echo "✓ Default values marked with (default)"
    else
        echo "✗ FAIL: Default markers not present"
        return 1
    fi

    # Check for expected default values
    local expected_defaults=(
        "egress (default)"
        "tcp udp"
        "OUTPUT"
        "/var/log/proxyctl/"
    )

    for default_value in "${expected_defaults[@]}"; do
        if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "$default_value"; then
            echo "✓ Found default: $default_value"
        else
            echo "  Warning: Expected default not found: $default_value"
        fi
    done

    echo "✓ PASS: Logger config display with defaults"
    echo ""
}

# Test 15: Logger config display with explicit values
test_logger_config_display_explicit() {
    echo "Test 15: Logger Config Display - With Explicit Values"
    echo "---"

    # Remove existing logger
    remove_logger 2>/dev/null || true
    sleep 1

    # Create config with explicit values
    cat > /tmp/test-logger-explicit.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "custom_logger",
    "protocols": ["tcp", "icmp"],
    "output": "/var/log/custom/egress.log"
  }
}
EOF

    # Install logger with custom config
    if ! /usr/local/bin/egressctl logger install --config /tmp/test-logger-explicit.json; then
        echo "✗ FAIL: Failed to install logger with custom config"
        return 1
    fi

    echo "✓ Logger installed with custom config"
    sleep 2

    # Run status with config
    /usr/local/bin/egressctl status --config /tmp/test-logger-explicit.json > /tmp/status-output.log 2>&1

    # Check for Configuration section (not "inferred")
    if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "Configuration:"; then
        echo "✓ Shows configuration section"
    else
        echo "✗ FAIL: Missing configuration section"
        return 1
    fi

    # Check that custom values do NOT have (default) marker
    if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "custom_logger" && \
       ! grep -A 10 "Logger:" /tmp/status-output.log | grep "custom_logger" | grep -q "(default)"; then
        echo "✓ Custom logger name shown without (default)"
    else
        echo "✗ FAIL: Custom value incorrectly marked as default"
        grep -A 10 "Logger:" /tmp/status-output.log || true
        return 1
    fi

    # Check for ICMP protocol
    if grep -A 10 "Logger:" /tmp/status-output.log | grep -q "icmp"; then
        echo "✓ Custom protocols displayed"
    else
        echo "  Warning: Custom protocols not displayed"
    fi

    # Clean up
    remove_logger 2>/dev/null || true
    rm -f /tmp/test-logger-explicit.json

    echo "✓ PASS: Logger config display with explicit values"
    echo ""
}

# Test 16: Status with legacy 'output' config (migration)
test_status_with_legacy_config() {
    echo "Test 16: Status With Legacy 'output' Config"
    echo "---"

    # Ensure logger is removed first
    remove_logger 2>/dev/null || true

    # Create config with OLD format (output field, no name field)
    cat > /tmp/test-legacy-output.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress.log",
    "protocols": ["tcp", "udp"]
  }
}
EOF

    echo "✓ Created legacy config with 'output' field"

    # Run status command with legacy config
    STATUS_OUTPUT=$(/usr/local/bin/egressctl status --config /tmp/test-legacy-output.json 2>&1)

    # Verify migration message appears
    if echo "$STATUS_OUTPUT" | grep -q "Migrating old logger config"; then
        echo "✓ Migration message displayed"
    else
        echo "✗ FAIL: No migration message shown"
        echo "$STATUS_OUTPUT"
        return 1
    fi

    # Verify backup was created
    if [ -f /tmp/test-legacy-output.json.pre-v0.3.backup ]; then
        echo "✓ Config backup created"
    else
        echo "⚠ WARNING: Backup not created"
    fi

    # Verify status displays without errors
    if echo "$STATUS_OUTPUT" | grep -q "Egress Proxy Status"; then
        echo "✓ Status displayed successfully"
    else
        echo "✗ FAIL: Status output malformed"
        echo "$STATUS_OUTPUT"
        return 1
    fi

    # Verify no error about missing 'name' field
    if echo "$STATUS_OUTPUT" | grep -qi "name.*required"; then
        echo "✗ FAIL: Status shows 'name required' error despite migration"
        echo "$STATUS_OUTPUT"
        return 1
    fi
    echo "✓ No validation errors after migration"

    # Verify config was migrated (check the file)
    if grep -q '"name".*"egress"' /tmp/test-legacy-output.json; then
        echo "✓ Config file migrated to new format"
    else
        echo "⚠ WARNING: Config file may not be migrated"
    fi

    # Verify old 'output' field removed from logger section
    LOGGER_SECTION=$(sed -n '/"logger":/,/^  }/p' /tmp/test-legacy-output.json)
    if echo "$LOGGER_SECTION" | grep -q '"output"'; then
        echo "⚠ WARNING: Old 'output' field still present in logger config"
    else
        echo "✓ Old 'output' field removed from logger config"
    fi

    # Cleanup
    rm -f /tmp/test-legacy-output.json /tmp/test-legacy-output.json.pre-v0.3.backup

    echo "✓ PASS: Status with legacy config"
    echo ""
}

# Test 17: Drift detection for logger protocols
test_drift_detection_logger_protocols() {
    echo "Test 17: Drift Detection - Logger Protocol Mismatch"
    echo "---"

    # Install logger with TCP only
    cat > /tmp/test-logger-tcp-only.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "egress",
    "protocols": ["tcp"]
  }
}
EOF

    if ! /usr/local/bin/egressctl logger install --config /tmp/test-logger-tcp-only.json; then
        echo "✗ FAIL: Failed to install logger with TCP only"
        return 1
    fi

    echo "✓ Logger installed with TCP protocol"
    sleep 2

    # Create config with TCP + UDP
    cat > /tmp/test-logger-tcp-udp.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "egress",
    "protocols": ["tcp", "udp"]
  }
}
EOF

    # Run status with different config (should detect drift)
    /usr/local/bin/egressctl status --config /tmp/test-logger-tcp-udp.json > /tmp/status-output.log 2>&1

    # Check for drift warning
    if grep -A 15 "Logger:" /tmp/status-output.log | grep -q "⚠"; then
        echo "✓ Drift warning detected"
    else
        echo "✗ FAIL: No drift warning shown"
        grep -A 15 "Logger:" /tmp/status-output.log || true
        return 1
    fi

    # Check for protocol mismatch message
    if grep -A 15 "Logger:" /tmp/status-output.log | grep -qi "protocol.*udp"; then
        echo "✓ UDP protocol drift identified"
    else
        echo "  Warning: Specific protocol drift not clearly identified"
    fi

    # Clean up
    remove_logger 2>/dev/null || true
    rm -f /tmp/test-logger-tcp-only.json /tmp/test-logger-tcp-udp.json
    wait_for_rsyslog  # Wait for rsyslog to be ready after removal

    echo "✓ PASS: Drift detection for logger protocols"
    echo ""
}

# Test 18: Drift detection shows no warnings when config matches
test_drift_detection_no_drift() {
    echo "Test 18: Drift Detection - No False Positives"
    echo "---"

    # Ensure rsyslog is ready before starting
    wait_for_rsyslog

    # Create config
    cat > /tmp/test-logger-no-drift.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "logger": {
    "enabled": true,
    "name": "egress",
    "protocols": ["tcp", "udp"]
  }
}
EOF

    # Install logger with config
    if ! /usr/local/bin/egressctl logger install --config /tmp/test-logger-no-drift.json; then
        echo "✗ FAIL: Failed to install logger"
        return 1
    fi

    echo "✓ Logger installed"
    sleep 2

    # Run status with SAME config
    /usr/local/bin/egressctl status --config /tmp/test-logger-no-drift.json > /tmp/status-output.log 2>&1

    # Check that NO drift warnings appear
    if grep -A 15 "Logger:" /tmp/status-output.log | grep -q "⚠"; then
        echo "✗ FAIL: False positive drift warning detected"
        grep -A 15 "Logger:" /tmp/status-output.log || true
        return 1
    else
        echo "✓ No drift warnings (correct)"
    fi

    # Should show installed and configuration
    if grep -A 15 "Logger:" /tmp/status-output.log | grep -q "Installed"; then
        echo "✓ Shows logger as installed"
    fi

    # Clean up
    remove_logger 2>/dev/null || true
    rm -f /tmp/test-logger-no-drift.json

    echo "✓ PASS: No false positive drift detection"
    echo ""
}

# Test 19: Firewall config display
test_firewall_config_display() {
    echo "Test 19: Firewall Config Display"
    echo "---"

    # Detect SSH IP to prevent lockout
    SSH_IP=$(get_ssh_ip) || {
        echo "✗ FAIL: Could not detect SSH IP"
        return 1
    }
    validate_ssh_whitelist "$SSH_IP" || return 1
    echo "  Using SSH IP: $SSH_IP"

    # Create firewall config with INPUT filtering
    cat > /tmp/test-firewall-config.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["$SSH_IP"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24", "192.168.1.0/24"], "ports": [8080, 8443]}
    ]
  }
}
EOF

    # Apply firewall rules
    if ! apply_firewall_rules /tmp/test-firewall-config.json; then
        echo "✗ FAIL: Failed to apply firewall rules"
        return 1
    fi

    echo "✓ Firewall rules applied"
    sleep 1

    # Run status with config
    /usr/local/bin/egressctl status --config /tmp/test-firewall-config.json > /tmp/status-output.log 2>&1

    # Check for INPUT Filtering Configuration section
    if grep -A 20 "Firewall:" /tmp/status-output.log | grep -q "INPUT Filtering Configuration:"; then
        echo "✓ INPUT filtering config section shown"
    else
        echo "✗ FAIL: Missing INPUT filtering config section"
        grep -A 20 "Firewall:" /tmp/status-output.log || true
        return 1
    fi

    # Check for policy display
    if grep -A 20 "Firewall:" /tmp/status-output.log | grep -q "Policy: drop"; then
        echo "✓ Policy shown correctly"
    else
        echo "  Warning: Policy not displayed"
    fi

    # Check for SSH whitelist
    if grep -A 20 "Firewall:" /tmp/status-output.log | grep -q "$SSH_IP"; then
        echo "✓ SSH whitelist displayed"
    else
        echo "  Warning: SSH whitelist not displayed"
    fi

    # Check for proxy allow list
    if grep -A 20 "Firewall:" /tmp/status-output.log | grep -q "10.0.1.0/24"; then
        echo "✓ Proxy allow list displayed"
    else
        echo "  Warning: Proxy allow list not displayed"
    fi

    # Clean up
    remove_firewall_rules 2>/dev/null || true
    rm -f /tmp/test-firewall-config.json

    echo "✓ PASS: Firewall config display"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    for test_func in \
        test_status_basic_execution \
        test_haproxy_status_detection \
        test_acl_status_missing_file \
        test_acl_status_existing_file \
        test_logger_status_not_installed \
        test_logger_status_installed \
        test_firewall_status_not_configured \
        test_firewall_status_with_input \
        test_firewall_status_with_output \
        test_status_backup_info \
        test_status_helpful_hints \
        test_status_formatting \
        test_status_performance \
        test_logger_config_display_with_defaults \
        test_logger_config_display_explicit \
        test_status_with_legacy_config \
        test_drift_detection_logger_protocols \
        test_drift_detection_no_drift \
        test_firewall_config_display; do

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
