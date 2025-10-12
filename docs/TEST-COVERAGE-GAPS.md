# Test Coverage Gaps and Recommendations

**Date:** 2025-10-12
**Analysis Based On:** Integration test failures on Ubuntu 22.04 and Debian 12
**Test Environment:** DigitalOcean droplets (Ubuntu 22.04, 24.04, Debian 12, CentOS Stream 9, Rocky 8)

## Executive Summary

While investigating test failures on Ubuntu 22.04 and Debian 12, we discovered that the primary failure was a **test bug** (fixed: `grep -q` → `grep -Fq` in test-suite-upgrade.sh), but the server inspection revealed **10 significant gaps in test coverage** that could lead to production issues.

**Most Critical Finding:** Logrotate silently fails on Ubuntu systems due to missing `su` directive in the configuration. This means logs will never rotate in production, potentially filling disk space.

## Findings and Recommendations

### 1. Logrotate Permissions Bug 🔴 **CRITICAL**

#### Problem
On Ubuntu systems with `syslog` group, logrotate **fails silently** because:
- Directory permissions are `0775 root:syslog` (group-writable)
- Logrotate config is missing the `su` directive
- Logrotate refuses to rotate files in group-writable directories without explicit `su` directive

#### Evidence
```bash
# Ubuntu 22.04 - logrotate dry-run output
$ logrotate -d /etc/logrotate.d/egress-monitor
error: skipping "/var/log/proxyctl/egress.log" because parent directory has
insecure permissions (It's world writable or writable by group which is not "root")
Set "su" directive in config file to tell logrotate which user/group should be
used for rotation.
```

#### Current Test Coverage
- ✅ Checks if `/etc/logrotate.d/egress-monitor` file exists
- ❌ **Does NOT test actual rotation execution**
- ❌ **Does NOT verify rotation succeeds**

#### Impact
- **Production Risk:** HIGH - Logs will fill disk over time (no rotation)
- **Distros Affected:** Ubuntu 22.04, 20.04 (any Ubuntu with syslog user)
- **Debian/CentOS:** NOT affected (rsyslog runs as root, directory is 0755 root:root)

#### Recommendation

**Code Fix Required:** Add `su` directive to logrotate config

**File:** `internal/logger/logger.go:configureLogrotate()`

```go
// Before (BROKEN on Ubuntu):
content := fmt.Sprintf(`%s {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 %s
    sharedscripts
    postrotate
        systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
`, m.LogFile, fileOwner)

// After (FIXED):
content := fmt.Sprintf(`%s {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 %s
    su %s
    sharedscripts
    postrotate
        systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
`, m.LogFile, fileOwner, suDirective)

// Where suDirective is:
// Ubuntu: "syslog adm"
// Debian/CentOS: "root root"
```

**Test to Add:**

```bash
# In test-suite-logger.sh after installation
test_logrotate_functionality() {
    echo "Test: Logrotate Configuration and Execution"
    echo "---"

    # Generate some log content
    curl -s https://example.com >/dev/null 2>&1 || true
    sleep 2

    # Get initial log size
    INITIAL_SIZE=$(stat -c%s /var/log/proxyctl/egress.log)

    # Force rotation
    if ! logrotate -f /etc/logrotate.d/egress-monitor 2>&1; then
        echo "✗ FAIL: Logrotate execution failed"
        return 1
    fi
    echo "✓ Logrotate executed successfully"

    # Verify rotated file exists
    if [ ! -f /var/log/proxyctl/egress.log.1 ]; then
        echo "✗ FAIL: Rotated log file not created"
        return 1
    fi
    echo "✓ Log file rotated to egress.log.1"

    # Verify new log file created
    if [ ! -f /var/log/proxyctl/egress.log ]; then
        echo "✗ FAIL: New log file not created after rotation"
        return 1
    fi
    echo "✓ New log file created"

    # Verify permissions on new file
    NEW_PERMS=$(stat -c%a /var/log/proxyctl/egress.log)
    if [ "$NEW_PERMS" != "640" ]; then
        echo "✗ FAIL: New log file has incorrect permissions: $NEW_PERMS (expected 640)"
        return 1
    fi
    echo "✓ New log file has correct permissions (0640)"

    echo "✓ PASS: Logrotate functionality"
    echo ""
}
```

---

### 2. Systemd Service Cleanup for iptables 🟠 **HIGH**

#### Problem
On systems using iptables (Debian 12), the systemd service for rule persistence is not fully cleaned up on removal:
- Service remains **enabled** after `egressctl logger remove`
- Service file `/etc/systemd/system/egressctl-logger.service` may not be deleted
- `systemctl daemon-reload` might not be called

#### Evidence
```bash
# Debian 12 after removal
$ systemctl is-enabled egressctl-logger
enabled  # <-- Should be disabled/non-existent
```

#### Current Test Coverage
- ✅ Checks iptables rules removed from OUTPUT chain
- ❌ **Does NOT check systemd service status**
- ❌ **Does NOT verify service file deleted**

#### Impact
- **Production Risk:** MEDIUM - Service file lingers, could cause confusion
- **Distros Affected:** Debian 12 and any system using iptables (not nftables)

#### Recommendation

**Test to Add:**

```bash
# In test-suite-logger.sh after removal test
test_systemd_service_cleanup() {
    echo "Test: Systemd Service Cleanup (iptables)"
    echo "---"

    # Only applicable if iptables was used
    if [ -f /etc/systemd/system/egressctl-logger.service ]; then
        echo "✗ FAIL: Systemd service file not removed"
        return 1
    fi
    echo "✓ Systemd service file removed"

    # Check service is not enabled
    if systemctl is-enabled egressctl-logger 2>/dev/null; then
        echo "✗ FAIL: Systemd service still enabled"
        return 1
    fi
    echo "✓ Systemd service not enabled"

    echo "✓ PASS: Systemd service cleanup"
    echo ""
}
```

**Code Review Required:** Verify `internal/logger/logger.go:removeIPTablesSystemdService()` is working correctly.

---

### 3. NFTables Include Directive Cleanup 🟠 **HIGH**

#### Problem
Tests verify that the nftables table is removed, but don't verify that:
- The **include directive** is removed from `/etc/nftables.conf`
- The `/etc/nftables.d/` directory is clean after removal

#### Current Test Coverage
- ✅ Checks `nft list tables` doesn't show `egress_monitor`
- ❌ **Does NOT check include directive removed from `/etc/nftables.conf`**
- ❌ **Does NOT verify config file deleted from `/etc/nftables.d/`**

#### Evidence
During testing, we observed that after removal:
- Table is removed correctly ✓
- Config file `/etc/nftables.d/egress-monitor.nft` is deleted ✓
- Include line is removed from `/etc/nftables.conf` ✓ (verified manually)

But **tests don't verify the include cleanup**.

#### Impact
- **Production Risk:** MEDIUM - Leftover includes could cause nftables service to fail on restart
- **Distros Affected:** Ubuntu 22.04, 24.04, CentOS Stream 9, Rocky 8

#### Recommendation

**Test to Add:**

```bash
# In test-suite-logger.sh removal verification
# Add after checking nftables table removed

# Verify nftables config file removed
if [ -f /etc/nftables.d/egress-monitor.nft ]; then
    echo "✗ FAIL: nftables config file not removed"
    return 1
fi
echo "✓ nftables config file removed"

# Verify include directive removed from main config
for conf in /etc/nftables.conf /etc/sysconfig/nftables.conf; do
    if [ -f "$conf" ]; then
        if grep -q "egress-monitor" "$conf"; then
            echo "✗ FAIL: Include directive still present in $conf"
            return 1
        fi
    fi
done
echo "✓ Include directive removed from nftables config"
```

---

### 4. Rsyslog Log Format Inconsistency 🟡 **MEDIUM**

#### Problem
Different rsyslog versions and distro configurations produce different log formats:

| Distro | Rsyslog Version | Format | Kernel Timestamp |
|--------|----------------|--------|------------------|
| Ubuntu 22.04 | 8.2112.0 | Traditional | `[  148.339027]` ✅ |
| Ubuntu 24.04 | 8.2312.0 | Modern | None ❌ |
| Debian 12 | 8.2302.0 | ISO-8601 | `[   59.808507]` ✅ |

**Examples:**
```bash
# Ubuntu 22.04 (Traditional)
Oct 12 09:05:48 host kernel: [  148.339027] EGRESS_MONITOR: IN= OUT=eth0 ...

# Ubuntu 24.04 (Modern)
2025-10-12T09:04:46.623223+00:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 ...

# Debian 12 (ISO-8601 + Timestamp)
2025-10-12T09:04:10.705360+00:00 host kernel: [   59.808507] EGRESS_MONITOR: ...
```

#### Current Test Coverage
- ✅ Tests verify logs contain `EGRESS_MONITOR` prefix
- ❌ **Does NOT document format variations**
- ❌ **Does NOT test log parsing works with all formats**

#### Impact
- **Production Risk:** LOW-MEDIUM - Log analysis tools may break on format differences
- **Distros Affected:** All (different formats on each)

#### Recommendation

**Documentation to Add:**

1. **Update docs/TESTING.md** with a section on log format variations
2. **Add to CLAUDE.md** in "Common Development Tasks" → "Working with Logs"

**Test Enhancement:**

```bash
# In test-suite-logger.sh
# Add format verification in test_log_generation()

echo "Detected log format:"
FIRST_LOG=$(head -1 /var/log/proxyctl/egress.log)
echo "  $FIRST_LOG"

if echo "$FIRST_LOG" | grep -q "^[A-Z][a-z][a-z] [0-9]"; then
    echo "  Format: Traditional (Ubuntu 22.04 style)"
elif echo "$FIRST_LOG" | grep -q "^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}T"; then
    echo "  Format: ISO-8601 (Modern rsyslog)"
else
    echo "  ⚠ WARNING: Unknown log format"
fi

# Verify log contains essential fields
if ! echo "$FIRST_LOG" | grep -q "EGRESS_MONITOR.*SRC=.*DST=.*PROTO="; then
    echo "✗ FAIL: Log missing expected fields (SRC, DST, PROTO)"
    return 1
fi
echo "✓ Log contains expected connection fields"
```

---

### 5. Rsyslog Filter Accuracy Test 🟡 **MEDIUM**

#### Problem
We verify that EGRESS_MONITOR messages appear in `/var/log/proxyctl/egress.log`, but don't verify:
- **Only** EGRESS_MONITOR messages go there (no other kernel messages)
- The `stop` directive prevents duplication in `/var/log/kern.log` or `/var/log/syslog`

#### Current Test Coverage
- ✅ Verifies log file exists and contains EGRESS_MONITOR
- ❌ **Does NOT verify no non-EGRESS_MONITOR messages**
- ❌ **Does NOT verify messages aren't duplicated**

#### Impact
- **Production Risk:** LOW - Incorrect filtering could bloat log files
- **User Experience:** Could make log analysis confusing

#### Recommendation

**Test to Add:**

```bash
# In test-suite-logger.sh after test_log_generation()
test_rsyslog_filter_accuracy() {
    echo "Test: Rsyslog Filter Accuracy"
    echo "---"

    # Verify all lines in egress.log contain EGRESS_MONITOR
    if grep -v "EGRESS_MONITOR" /var/log/proxyctl/egress.log | grep -q "kernel:"; then
        echo "✗ FAIL: Non-EGRESS_MONITOR kernel messages found in egress.log"
        return 1
    fi
    echo "✓ Only EGRESS_MONITOR messages in dedicated log"

    # Count EGRESS_MONITOR messages in egress.log
    COUNT_EGRESS=$(grep -c "EGRESS_MONITOR" /var/log/proxyctl/egress.log)

    # Check if duplicated in syslog/kern.log (should NOT be present)
    # Note: Some distros may not have kern.log
    if [ -f /var/log/kern.log ]; then
        COUNT_KERN=$(grep -c "EGRESS_MONITOR" /var/log/kern.log 2>/dev/null || echo 0)
        if [ "$COUNT_KERN" -gt 0 ]; then
            echo "⚠ WARNING: EGRESS_MONITOR messages also in /var/log/kern.log (duplication)"
            echo "  This may be expected on some distros"
        fi
    fi

    echo "✓ PASS: Rsyslog filter accuracy"
    echo ""
}
```

---

### 6. Logrotate Compression and Retention 🟢 **LOW**

#### Problem
We don't test that the logrotate directives actually work:
- `compress` - Old logs are gzipped
- `delaycompress` - Most recent rotation not compressed
- `rotate 14` - Only 14 days of logs kept

#### Current Test Coverage
- ❌ **Does NOT test compression**
- ❌ **Does NOT test retention policy**

#### Impact
- **Production Risk:** LOW - Misconfigured retention could waste disk space
- **User Experience:** Unexpected log deletion/size

#### Recommendation

**Test to Add (Future Enhancement):**

```bash
# This would require multiple rotations - may be too slow for integration tests
# Consider as a manual test or separate "extended" test suite

test_logrotate_retention() {
    echo "Test: Logrotate Compression and Retention"
    echo "---"

    # Force multiple rotations
    for i in {1..3}; do
        echo "Generating logs..." >&2
        curl -s https://example.com >/dev/null 2>&1
        sleep 1
        logrotate -f /etc/logrotate.d/egress-monitor
    done

    # Check for compressed files
    if ! ls /var/log/proxyctl/egress.log.*.gz >/dev/null 2>&1; then
        echo "⚠ WARNING: No compressed log files found"
        echo "  delaycompress may prevent immediate compression"
    else
        echo "✓ Old logs are compressed"
    fi

    # Most recent rotation should NOT be compressed (delaycompress)
    if [ -f /var/log/proxyctl/egress.log.1.gz ]; then
        echo "⚠ WARNING: Most recent rotation is compressed (expected uncompressed)"
    fi

    echo "✓ PASS: Logrotate compression"
    echo ""
}
```

**Note:** This test may be better suited for manual testing or a dedicated "extended test suite" due to time requirements.

---

### 7. File Permissions Verification 🟢 **LOW**

#### Problem
Directory and file permissions differ by distro but aren't explicitly tested:
- Ubuntu: `0775 root:syslog` (directory), `0640 syslog:adm` (files)
- Debian/CentOS: `0755 root:root` (directory), `0640 root:root` (files)

#### Current Test Coverage
- ❌ **Does NOT verify directory permissions**
- ❌ **Does NOT verify file ownership matches distro expectations**

#### Impact
- **Production Risk:** LOW - Wrong permissions could prevent rsyslog from writing
- **Distros Affected:** All (different expectations)

#### Recommendation

**Test to Add:**

```bash
# In test-suite-logger.sh after installation
test_file_permissions() {
    echo "Test: File Permissions and Ownership"
    echo "---"

    # Check log directory permissions
    DIR_PERMS=$(stat -c%a /var/log/proxyctl/)
    DIR_OWNER=$(stat -c%U:%G /var/log/proxyctl/)

    echo "  Directory: $DIR_PERMS $DIR_OWNER"

    # Verify directory is at least group-writable or owner-writable
    if [ "$DIR_PERMS" != "755" ] && [ "$DIR_PERMS" != "775" ]; then
        echo "⚠ WARNING: Unexpected directory permissions: $DIR_PERMS"
    fi

    # Check log file permissions (after logs generated)
    if [ -f /var/log/proxyctl/egress.log ]; then
        FILE_PERMS=$(stat -c%a /var/log/proxyctl/egress.log)
        FILE_OWNER=$(stat -c%U:%G /var/log/proxyctl/egress.log)

        echo "  Log file: $FILE_PERMS $FILE_OWNER"

        # Verify file is readable by owner/group but not world-readable
        if [ "${FILE_PERMS:2:1}" != "0" ]; then
            echo "⚠ WARNING: Log file is world-readable (privacy concern)"
        fi
    fi

    echo "✓ PASS: File permissions"
    echo ""
}
```

---

### 8. Service Persistence Across Reboots ⚫ **BLOCKED**

#### Problem
We cannot test reboot persistence in ephemeral droplets without significant infrastructure changes:
- nftables rules persist via `/etc/nftables.conf` include
- iptables rules persist via systemd service
- Rsyslog configuration loads on boot
- Log directory permissions restored

#### Current Test Coverage
- ❌ **Cannot test without actual reboot**

#### Impact
- **Production Risk:** HIGH if persistence fails
- **Test Feasibility:** LOW - requires infrastructure changes

#### Recommendation

**Option 1: Manual Testing Procedure**

Document a manual test procedure for release validation:

```bash
# Manual Reboot Test (run before major releases)

# 1. Install on test VM
egressctl logger install

# 2. Generate some logs
curl -s https://example.com

# 3. Verify logs present
tail /var/log/proxyctl/egress.log

# 4. Reboot
sudo reboot

# 5. After reboot, verify:
#    - Firewall rules active
#    - Rsyslog configuration loaded
#    - New logs being generated
#    - Log directory exists with correct permissions
```

**Option 2: Snapshot-Based Testing (Future)**

Use DigitalOcean snapshots to create, snapshot, restore, test:
- More expensive (~$0.05 per snapshot)
- Slower (snapshots take 1-2 minutes)
- More realistic test environment

**Option 3: Smoke Test After Reboot**

Add a simple post-reboot smoke test to CI/CD that:
1. Deploys to a persistent test VM (not ephemeral droplet)
2. Reboots weekly
3. Runs basic connectivity test
4. Alerts if rules not active

**Recommendation:** Document manual testing procedure for now. Consider snapshot-based testing for v1.0 release.

---

### 9. Firewall Rule Priority and Conflicts 🟢 **LOW**

#### Problem
We don't test that our firewall rules:
- Execute at the correct priority (before other OUTPUT rules)
- Don't conflict with Docker/Kubernetes/VPN rules
- Private IP exclusions actually work (we log but don't verify exclusions)

#### Current Test Coverage
- ✅ Verifies rules are created
- ❌ **Does NOT test rule priority**
- ❌ **Does NOT test private IP exclusion**
- ❌ **Does NOT test conflict scenarios**

#### Impact
- **Production Risk:** LOW - Most systems won't have conflicting rules
- **Edge Cases:** Could fail in complex network environments

#### Recommendation

**Test to Add:**

```bash
# In test-suite-logger.sh
test_private_ip_exclusion() {
    echo "Test: Private IP Exclusion"
    echo "---"

    # Before test: Count current log entries
    BEFORE_COUNT=$(grep -c "EGRESS_MONITOR" /var/log/proxyctl/egress.log 2>/dev/null || echo 0)

    # Generate traffic to private IPs (should NOT be logged)
    ping -c 1 10.0.0.1 >/dev/null 2>&1 || true
    ping -c 1 172.16.0.1 >/dev/null 2>&1 || true
    ping -c 1 192.168.1.1 >/dev/null 2>&1 || true

    # Generate traffic to public IP (SHOULD be logged)
    ping -c 1 8.8.8.8 >/dev/null 2>&1 || true

    sleep 2

    # Count new entries
    AFTER_COUNT=$(grep -c "EGRESS_MONITOR" /var/log/proxyctl/egress.log 2>/dev/null || echo 0)
    NEW_ENTRIES=$((AFTER_COUNT - BEFORE_COUNT))

    # We should have at least 1 new entry (for 8.8.8.8)
    if [ "$NEW_ENTRIES" -lt 1 ]; then
        echo "✗ FAIL: Public IP traffic not logged"
        return 1
    fi

    # Verify no private IPs in new logs
    if tail -$NEW_ENTRIES /var/log/proxyctl/egress.log | grep -E "DST=(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"; then
        echo "✗ FAIL: Private IP traffic was logged (should be excluded)"
        return 1
    fi

    echo "✓ Private IPs excluded from logging"
    echo "✓ Public IPs logged correctly"
    echo "✓ PASS: Private IP exclusion"
    echo ""
}
```

---

### 10. Upgrade Test - Log Content Verification ✅ **FIXED**

#### Problem
The upgrade test used regex `grep -q` instead of fixed-string `grep -Fq`, causing failures when log lines contained regex special characters (square brackets).

#### Status
**FIXED** in commit fixing test-suite-upgrade.sh lines 97 and 99.

---

## Implementation Priority

### Immediate (Before Next Release)
1. ✅ **Fix upgrade test grep bug** - COMPLETED
2. 🔴 **Fix logrotate permissions bug** - Add `su` directive to config
3. 🟠 **Add logrotate execution test** - Verify rotation actually works

### Short Term (Next Sprint)
4. 🟠 **Add systemd service cleanup test** - Verify iptables service removed
5. 🟠 **Add nftables include cleanup test** - Verify config artifacts removed
6. 🟡 **Document log format variations** - Update TESTING.md and CLAUDE.md

### Medium Term (Next Quarter)
7. 🟡 **Add rsyslog filter accuracy test** - Verify no duplicate logging
8. 🟢 **Add file permissions test** - Verify correct ownership by distro
9. 🟢 **Add private IP exclusion test** - Verify filtering works

### Long Term (Future)
10. ⚫ **Reboot persistence testing** - Requires infrastructure changes
11. 🟢 **Logrotate retention test** - May need extended test suite

---

## Testing Strategy Notes

### Test Execution Time
Current integration tests run in ~2-3 minutes per distro. Adding the recommended tests:
- Logrotate execution: +10 seconds
- Service cleanup verification: +5 seconds
- Config cleanup: +5 seconds
- Private IP exclusion: +10 seconds

**Total additional time:** ~30 seconds per distro (acceptable)

### Parallel Execution
Current tests run 5 distros in parallel. Recommended tests can continue this pattern.

### Cost Impact
DigitalOcean droplets cost ~$0.01 per test run. Additional test time has negligible cost impact.

---

## Related Issues

- See `docs/TESTING.md` for overall testing strategy
- See `test/integration/README.md` for integration test instructions
- See `docs/UPGRADE.md` for upgrade scenarios and log preservation

---

## Conclusion

The test failures on Ubuntu 22.04 and Debian 12 revealed both a test bug (now fixed) and significant gaps in our integration test coverage. The **most critical finding** is the logrotate permissions bug on Ubuntu systems, which will prevent log rotation in production.

Implementing the recommended tests will:
1. Catch the logrotate bug before production
2. Verify complete cleanup on removal
3. Ensure cross-distro compatibility
4. Improve confidence in production deployments

**Next Steps:**
1. Fix logrotate permissions bug (code + test)
2. Add high-priority tests (systemd cleanup, config cleanup)
3. Update documentation with log format variations
4. Consider snapshot-based reboot testing for v1.0 release
