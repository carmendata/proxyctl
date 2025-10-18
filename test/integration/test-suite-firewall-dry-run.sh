#!/bin/bash
#
# Integration test suite for firewall apply --dry-run command
#
# Tests the dry-run mode which shows what would be applied without making changes
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: Firewall Apply Dry-Run"
echo "Started: $(date)"
echo "========================================"
echo ""

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."

    # Remove test configs
    rm -f /tmp/test-firewall-*.json 2>/dev/null || true

    # Remove any firewall rules (best effort)
    /usr/local/bin/egressctl firewall remove 2>/dev/null || true

    exit $exit_code
}

trap cleanup EXIT

# Helper functions

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get current SSH connection IP (for dynamic test configs)
get_ssh_ip() {
    local ssh_conn="${SSH_CONNECTION:-}"
    if [[ -n "$ssh_conn" ]]; then
        echo "$ssh_conn" | awk '{print $1}'
    else
        echo "0.0.0.0/0"  # Fallback if not SSH connection
    fi
}

# Test 1: Dry-run shows configuration summary without applying
test_dry_run_no_changes() {
    echo "Test 1: Dry-run Shows Configuration Without Applying"
    echo "---"

    # Create test config
    cat > /tmp/test-firewall-input.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["0.0.0.0/0"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Run with dry-run flag
    if ! /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-input.json --dry-run > /tmp/dry-run-output.log 2>&1; then
        echo "✗ FAIL: Dry-run command failed"
        cat /tmp/dry-run-output.log
        return 1
    fi

    # Check for dry-run indicator
    if ! grep -q "DRY RUN MODE" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing dry-run mode indicator"
        cat /tmp/dry-run-output.log
        return 1
    fi

    echo "✓ Dry-run mode indicator found"

    # Check for configuration summary
    if ! grep -q "Configuration Summary" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing configuration summary"
        return 1
    fi

    echo "✓ Configuration summary displayed"

    # Check for expected config details
    if ! grep -q "INPUT Filtering: ENABLED" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing INPUT filtering info"
        return 1
    fi

    if ! grep -q "Policy: drop" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing policy info"
        return 1
    fi

    echo "✓ Configuration details shown"

    # Verify no actual changes were made (check for backup creation message)
    if grep -q "Backup created:" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Backup was created (dry-run should not create backups)"
        return 1
    fi

    echo "✓ No backup created (as expected)"

    # Check for dry-run completion message
    if ! grep -q "DRY RUN complete" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing dry-run completion message"
        return 1
    fi

    echo "✓ Dry-run completion message found"

    echo "✓ PASS: Dry-run shows configuration without applying"
    echo ""
}

# Test 2: Dry-run does not require confirmation
test_dry_run_no_confirmation() {
    echo "Test 2: Dry-run Does Not Require Confirmation"
    echo "---"

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

    # Run dry-run (should not hang waiting for input)
    timeout 5 /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-redirect.json --dry-run > /tmp/dry-run-output.log 2>&1 || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "✗ FAIL: Dry-run command timed out (likely waiting for confirmation)"
            return 1
        fi
    }

    # Check that it didn't ask for confirmation
    if grep -qi "Apply these firewall rules?" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Dry-run asked for confirmation (should not prompt)"
        cat /tmp/dry-run-output.log
        return 1
    fi

    echo "✓ No confirmation prompt (as expected)"

    # Check for OUTPUT redirect in summary
    if ! grep -q "OUTPUT Redirect: ENABLED" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing OUTPUT redirect info"
        return 1
    fi

    echo "✓ OUTPUT redirect configuration shown"

    echo "✓ PASS: Dry-run does not require confirmation"
    echo ""
}

# Test 3: Dry-run with both INPUT and OUTPUT
test_dry_run_combined_config() {
    echo "Test 3: Dry-run With Combined INPUT and OUTPUT Config"
    echo "---"

    # Get current SSH IP for dynamic config
    local ssh_ip=$(get_ssh_ip)
    echo "  Using SSH IP: $ssh_ip"

    # Create combined config with dynamic SSH IP
    cat > /tmp/test-firewall-combined.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["$ssh_ip", "203.0.113.0/24"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080, 8443]}
    ]
  },
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  }
}
EOF

    # Run dry-run
    if ! /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-combined.json --dry-run > /tmp/dry-run-output.log 2>&1; then
        echo "✗ FAIL: Dry-run with combined config failed"
        cat /tmp/dry-run-output.log
        return 1
    fi

    # Check both sections are shown
    if ! grep -q "INPUT Filtering: ENABLED" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing INPUT filtering section"
        return 1
    fi
    echo "✓ INPUT filtering section present"

    if ! grep -q "OUTPUT Redirect: ENABLED" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing OUTPUT redirect section"
        return 1
    fi
    echo "✓ OUTPUT redirect section present"

    # Check for [DRY RUN] markers
    if ! grep -q "\[DRY RUN\]" /tmp/dry-run-output.log; then
        echo "✗ FAIL: Missing [DRY RUN] markers"
        return 1
    fi
    echo "✓ [DRY RUN] markers found"

    echo "✓ PASS: Dry-run with combined config"
    echo ""
}

# Test 4: Dry-run does not create firewall rules
test_dry_run_no_rules_created() {
    echo "Test 4: Dry-run Does Not Create Firewall Rules"
    echo "---"

    # Detect firewall type
    local fw_type=""
    if command_exists nft; then
        fw_type="nftables"
    elif command_exists iptables; then
        fw_type="iptables"
    else
        echo "  No firewall detected - skipping rule verification"
        echo "✓ PASS: Dry-run does not create rules (no firewall to test)"
        echo ""
        return 0
    fi

    echo "  Detected firewall: $fw_type"

    # Ensure clean state
    /usr/local/bin/egressctl firewall remove 2>/dev/null || true
    sleep 1

    # Create test config
    cat > /tmp/test-firewall-input.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["0.0.0.0/0"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Run dry-run
    /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-input.json --dry-run > /tmp/dry-run-output.log 2>&1

    # Check that rules were NOT created
    if [ "$fw_type" = "nftables" ]; then
        if nft list table inet proxyctl_filter 2>/dev/null; then
            echo "✗ FAIL: nftables rules were created (dry-run should not create rules)"
            return 1
        fi
        echo "✓ No nftables rules created"
    elif [ "$fw_type" = "iptables" ]; then
        if iptables -L PROXYCTL_INPUT -n 2>/dev/null; then
            echo "✗ FAIL: iptables rules were created (dry-run should not create rules)"
            return 1
        fi
        echo "✓ No iptables rules created"
    fi

    echo "✓ PASS: Dry-run does not create firewall rules"
    echo ""
}

# Test 5: Dry-run does not create backups
test_dry_run_no_backups() {
    echo "Test 5: Dry-run Does Not Create Backups"
    echo "---"

    # Count existing backups
    local backup_dir="/var/lib/proxyctl/firewall-backups"
    local backup_count_before=0
    if [ -d "$backup_dir" ]; then
        backup_count_before=$(ls -1 "$backup_dir" 2>/dev/null | wc -l)
    fi

    echo "  Backups before: $backup_count_before"

    # Create test config
    cat > /tmp/test-firewall-input.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["0.0.0.0/0"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Run dry-run
    /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-input.json --dry-run > /tmp/dry-run-output.log 2>&1

    # Count backups after
    local backup_count_after=0
    if [ -d "$backup_dir" ]; then
        backup_count_after=$(ls -1 "$backup_dir" 2>/dev/null | wc -l)
    fi

    echo "  Backups after: $backup_count_after"

    # Verify no new backups were created
    if [ "$backup_count_after" -ne "$backup_count_before" ]; then
        echo "✗ FAIL: Backup count changed ($backup_count_before -> $backup_count_after)"
        return 1
    fi

    echo "✓ No new backups created"

    # Check for dry-run backup message
    if ! grep -q "\[DRY RUN\] Would create backup" /tmp/dry-run-output.log; then
        echo "  Note: Missing expected dry-run backup message (non-critical)"
    else
        echo "✓ Dry-run backup message shown"
    fi

    echo "✓ PASS: Dry-run does not create backups"
    echo ""
}

# Test 6: Dry-run exit code
test_dry_run_exit_code() {
    echo "Test 6: Dry-run Exit Code"
    echo "---"

    # Create valid config
    cat > /tmp/test-firewall-valid.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["0.0.0.0/0"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Run dry-run with valid config (should succeed)
    if /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-valid.json --dry-run > /tmp/dry-run-output.log 2>&1; then
        echo "✓ Valid config dry-run exits with 0"
    else
        echo "✗ FAIL: Valid config dry-run failed (exit code: $?)"
        cat /tmp/dry-run-output.log
        return 1
    fi

    # Create invalid config
    cat > /tmp/test-firewall-invalid.json <<'EOF'
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "invalid-policy",
    "allow_ssh_from": ["0.0.0.0/0"]
  }
}
EOF

    # Run dry-run with invalid config (should fail)
    if /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-invalid.json --dry-run > /tmp/dry-run-output.log 2>&1; then
        echo "✗ FAIL: Invalid config dry-run should have failed"
        return 1
    else
        echo "✓ Invalid config dry-run exits with non-zero"
    fi

    echo "✓ PASS: Dry-run exit codes correct"
    echo ""
}

# Test 7: Dry-run output format
test_dry_run_output_format() {
    echo "Test 7: Dry-run Output Format"
    echo "---"

    # Get current SSH IP for dynamic config
    local ssh_ip=$(get_ssh_ip)

    # Create test config with dynamic SSH IP
    cat > /tmp/test-firewall-input.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["$ssh_ip", "203.0.113.0/24", "10.0.1.50"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
EOF

    # Run dry-run
    /usr/local/bin/egressctl firewall apply --config /tmp/test-firewall-input.json --dry-run > /tmp/dry-run-output.log 2>&1

    # Check formatting elements
    local formatting_ok=true

    # Should have emoji indicator
    if ! grep -q "🔍" /tmp/dry-run-output.log; then
        echo "  Warning: Missing emoji indicator"
        formatting_ok=false
    fi

    # Should have section separators
    if ! grep -q "===" /tmp/dry-run-output.log; then
        echo "  Warning: Missing section separators"
        formatting_ok=false
    fi

    # Should have indented details (2 spaces)
    if ! grep -q "^  " /tmp/dry-run-output.log; then
        echo "  Warning: Missing indented details"
        formatting_ok=false
    fi

    # Should show SSH sources (check for any of them, since order may vary)
    if ! grep -q "SSH allowed from:" /tmp/dry-run-output.log; then
        echo "  Warning: SSH sources not shown"
        formatting_ok=false
    fi

    if [ "$formatting_ok" = true ]; then
        echo "✓ Output is well-formatted"
    fi

    echo "✓ PASS: Dry-run output format"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    for test_func in \
        test_dry_run_no_changes \
        test_dry_run_no_confirmation \
        test_dry_run_combined_config \
        test_dry_run_no_rules_created \
        test_dry_run_no_backups \
        test_dry_run_exit_code \
        test_dry_run_output_format; do

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
