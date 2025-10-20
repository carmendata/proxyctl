#!/bin/bash
#
# Upgrade Test Suite for proxyctl
# Tests that upgrades preserve logs and configurations
#
# Usage: ./test-suite-upgrade.sh

set -euo pipefail

echo "=== Test Suite: Upgrade Scenarios ==="
echo ""

# Test 1: Install → Accumulate Logs → Reinstall → Verify Logs Preserved
echo "Test 1: Log preservation during upgrade..."

# Install logger
echo "  Installing logger (simulating v0.1.0)..."
/usr/local/bin/egressctl logger install || {
    echo "FAIL: Initial logger installation failed"
    exit 1
}

# Wait for installation to complete
sleep 2

# Generate some test connections to create logs
echo "  Generating test traffic to create logs..."
curl -s https://example.com > /dev/null 2>&1 || true
curl -s https://google.com > /dev/null 2>&1 || true
ping -c 1 8.8.8.8 > /dev/null 2>&1 || true

# Wait for logs to be written
sleep 3

# Check log file exists and has content (per-chain naming: egress-output.log)
if [ ! -f /var/log/proxyctl/egress-output.log ]; then
    echo "FAIL: Log file not created"
    exit 1
fi

INITIAL_LOG_SIZE=$(stat -f%z /var/log/proxyctl/egress-output.log 2>/dev/null || stat -c%s /var/log/proxyctl/egress-output.log)
if [ "$INITIAL_LOG_SIZE" -eq 0 ]; then
    echo "FAIL: Log file is empty after initial traffic"
    exit 1
fi

echo "  Initial log size: $INITIAL_LOG_SIZE bytes"

# Capture first few log lines
head -5 /var/log/proxyctl/egress-output.log > /tmp/initial-logs.txt

# Reinstall (simulating upgrade to v0.2.0)
echo "  Reinstalling logger (simulating upgrade to v0.2.0)..."
/usr/local/bin/egressctl logger install || {
    echo "FAIL: Upgrade installation failed"
    exit 1
}

# Wait for reinstallation to complete
sleep 2

# Verify log file still exists (per-chain naming)
if [ ! -f /var/log/proxyctl/egress-output.log ]; then
    echo "FAIL: Log file deleted during upgrade"
    exit 1
fi

# Verify log file(s) exist and logs are preserved
# After upgrade with rotation, logs may be split between .log and .log.1
UPGRADED_LOG_SIZE=$(stat -f%z /var/log/proxyctl/egress-output.log 2>/dev/null || stat -c%s /var/log/proxyctl/egress-output.log)

# Check if logs were rotated (old logs in .1, new logs in current file)
if [ -f /var/log/proxyctl/egress-output.log.1 ]; then
    ROTATED_LOG_SIZE=$(stat -f%z /var/log/proxyctl/egress-output.log.1 2>/dev/null || stat -c%s /var/log/proxyctl/egress-output.log.1)
    TOTAL_LOG_SIZE=$((UPGRADED_LOG_SIZE + ROTATED_LOG_SIZE))
    echo "  Logs rotated: egress-output.log ($UPGRADED_LOG_SIZE bytes) + egress-output.log.1 ($ROTATED_LOG_SIZE bytes)"
    echo "  Total size: $TOTAL_LOG_SIZE bytes (initial: $INITIAL_LOG_SIZE bytes)"

    # Verify total size is at least as large as initial (allowing for new logs)
    if [ "$TOTAL_LOG_SIZE" -lt "$INITIAL_LOG_SIZE" ]; then
        echo "FAIL: Combined log size smaller than initial (logs lost)"
        exit 1
    fi
else
    # No rotation - current log should be >= initial size
    if [ "$UPGRADED_LOG_SIZE" -lt "$INITIAL_LOG_SIZE" ]; then
        echo "FAIL: Log file size decreased during upgrade (logs lost)"
        echo "  Initial: $INITIAL_LOG_SIZE bytes"
        echo "  After upgrade: $UPGRADED_LOG_SIZE bytes"
        exit 1
    fi
    echo "  Upgraded log size: $UPGRADED_LOG_SIZE bytes (preserved ✓)"
fi

# Verify original log content still present
# After upgrade with rotation, old logs may be in .1 file
if ! grep -Fq "$(head -1 /tmp/initial-logs.txt)" /var/log/proxyctl/egress-output.log; then
    # Check if logs were rotated to .1 file (expected during upgrade)
    if [ -f /var/log/proxyctl/egress-output.log.1 ] && grep -Fq "$(head -1 /tmp/initial-logs.txt)" /var/log/proxyctl/egress-output.log.1; then
        echo "  Old logs preserved in egress-output.log.1 (rotated during upgrade ✓)"
    else
        echo "FAIL: Original log content missing after upgrade"
        echo "  Checked both egress-output.log and egress-output.log.1"
        exit 1
    fi
fi
echo "PASS: Logs preserved during upgrade"
echo ""

# Test 2: Logrotate configuration preserved
echo "Test 2: Logrotate configuration preserved during upgrade..."

if [ ! -f /etc/logrotate.d/egress-monitor ]; then
    echo "FAIL: Logrotate config missing after upgrade"
    exit 1
fi

# Verify logrotate config has correct settings
if ! grep -q "daily" /etc/logrotate.d/egress-monitor; then
    echo "FAIL: Logrotate config missing 'daily' setting"
    exit 1
fi

if ! grep -q "rotate 14" /etc/logrotate.d/egress-monitor; then
    echo "FAIL: Logrotate config missing 'rotate 14' setting"
    exit 1
fi

echo "PASS: Logrotate configuration preserved"
echo ""

# Test 3: Rsyslog configuration preserved
echo "Test 3: Rsyslog configuration preserved during upgrade..."

if [ ! -f /etc/rsyslog.d/10-egress-monitor.conf ]; then
    echo "FAIL: Rsyslog config missing after upgrade"
    exit 1
fi

# Verify rsyslog config has correct log path (per-chain naming)
if ! grep -q "/var/log/proxyctl/egress-output.log" /etc/rsyslog.d/10-egress-monitor.conf; then
    echo "FAIL: Rsyslog config missing correct log path"
    exit 1
fi

echo "PASS: Rsyslog configuration preserved"
echo ""

# Test 4: New logs still generated after upgrade
echo "Test 4: Logging still works after upgrade..."

# Store current log size before generating traffic (per-chain naming)
BEFORE_TRAFFIC_SIZE=$(stat -f%z /var/log/proxyctl/egress-output.log 2>/dev/null || stat -c%s /var/log/proxyctl/egress-output.log)

# Generate more traffic
echo "  Generating post-upgrade traffic..."
curl -s https://github.com > /dev/null 2>&1 || true
sleep 2

# Verify new logs were added to current log file (not rotated file)
FINAL_LOG_SIZE=$(stat -f%z /var/log/proxyctl/egress-output.log 2>/dev/null || stat -c%s /var/log/proxyctl/egress-output.log)
if [ "$FINAL_LOG_SIZE" -le "$BEFORE_TRAFFIC_SIZE" ]; then
    echo "FAIL: No new logs generated after upgrade"
    echo "  Before test traffic: $BEFORE_TRAFFIC_SIZE bytes"
    echo "  After test traffic: $FINAL_LOG_SIZE bytes"
    exit 1
fi

echo "  Current log grew from $BEFORE_TRAFFIC_SIZE to $FINAL_LOG_SIZE bytes"
echo "PASS: Logging still works after upgrade"
echo ""

# Cleanup
echo "Cleanup: Removing logger..."
/usr/local/bin/egressctl logger remove || {
    echo "WARN: Logger removal failed (non-critical for upgrade tests)"
}

echo "=== All upgrade tests passed ==="
