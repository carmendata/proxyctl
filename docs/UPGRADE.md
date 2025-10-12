# Upgrading proxyctl

This guide covers upgrading proxyctl from one version to another while preserving your connection logs and configurations.

## Quick Upgrade

**TL;DR**: Download new binary, reinstall. Logs are automatically preserved.

```bash
# 1. Download latest release
curl -fsSL https://raw.githubusercontent.com/carmendata/proxyctl/main/install.sh | bash

# 2. Reinstall logger (idempotent, preserves logs)
sudo egressctl logger install

# Done! Your logs are preserved.
```

## What Gets Preserved

✅ **Automatically Preserved** (no action needed):
- Connection logs in `/var/log/egress-connections.log`
- Rotated logs (`/var/log/egress-connections.log.*.gz`)
- Log rotation continues without interruption

✅ **Automatically Updated** (safe):
- Binary in `/usr/local/bin/proxyctl` (and symlinks)
- Rsyslog configuration (`/etc/rsyslog.d/99-egress-monitor.conf`)
- Logrotate configuration (`/etc/logrotate.d/egress-monitor`)
- Firewall rules (recreated with same behavior)

❌ **Not Automatically Migrated** (if you have custom configs):
- Custom JSON configs in `/etc/proxyctl/` (manual merge required)
- Manual firewall rule modifications

## Detailed Upgrade Process

### Step 1: Check Current Version

```bash
egressctl version
```

Output:
```
proxyctl version v0.1.3
Git commit: abc123d
Build date: 2025-10-09T10:30:00Z
```

### Step 2: Backup (Optional but Recommended)

While logs are preserved automatically, you may want backups for safety:

```bash
# Backup logs
sudo mkdir -p /root/proxyctl-backup
sudo cp -r /var/log/egress-connections.log* /root/proxyctl-backup/

# Backup configs (if you customized them)
sudo cp /etc/rsyslog.d/99-egress-monitor.conf /root/proxyctl-backup/
sudo cp /etc/logrotate.d/egress-monitor /root/proxyctl-backup/

# List backed up files
ls -lh /root/proxyctl-backup/
```

### Step 3: Download New Version

**Option A: Install Script** (recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/carmendata/proxyctl/main/install.sh | sudo bash
```

**Option B: Manual Download**
```bash
# Download specific version
VERSION=v0.2.0
wget https://github.com/carmendata/proxyctl/releases/download/${VERSION}/proxyctl-linux-amd64

# Install binary
sudo mv proxyctl-linux-amd64 /usr/local/bin/proxyctl
sudo chmod +x /usr/local/bin/proxyctl

# Recreate symlinks
cd /usr/local/bin
sudo ln -sf proxyctl egressctl
sudo ln -sf proxyctl ingressctl
```

### Step 4: Verify New Version

```bash
egressctl version
```

### Step 5: Reinstall Logger

The `logger install` command is **idempotent** - it can be run multiple times safely:

```bash
sudo egressctl logger install
```

Output:
```
✓ Firewall detected: nftables
✓ Rsyslog configuration updated
✓ Logrotate configuration updated
✓ Firewall rules updated
✓ Logger installed successfully

Logs: /var/log/egress-connections.log
```

**What happens during reinstall:**
- ✅ Existing log file is **NOT deleted**
- ✅ New logs continue appending to existing file
- ✅ Rotated logs remain untouched
- ✅ Rsyslog/logrotate configs updated with latest templates
- ✅ Firewall rules recreated (same behavior)

### Step 6: Verify Logs Preserved

```bash
# Check log file still exists and has content
ls -lh /var/log/egress-connections.log

# Verify old logs still present
sudo head -20 /var/log/egress-connections.log

# Verify new logs being generated
sudo tail -f /var/log/egress-connections.log
# (generate some traffic, then Ctrl+C)
```

### Step 7: Test Logging

Generate test traffic to verify logging still works:

```bash
# Generate outbound connections
curl -s https://example.com > /dev/null
ping -c 1 8.8.8.8

# Wait 2-3 seconds, then check logs
sleep 3
sudo tail -5 /var/log/egress-connections.log
```

You should see new log entries with timestamps from after the upgrade.

## Upgrade Scenarios

### Scenario 1: Minor Version Upgrade (v0.1.3 → v0.1.4)

**Risk Level**: Low
**Downtime**: None
**Log Preservation**: Automatic

```bash
# Download and install new version
curl -fsSL https://raw.githubusercontent.com/carmendata/proxyctl/main/install.sh | sudo bash

# Reinstall logger
sudo egressctl logger install

# Done
```

### Scenario 2: Major Version Upgrade (v0.x → v1.0)

**Risk Level**: Medium
**Downtime**: Brief (rsyslog restart only)
**Log Preservation**: Automatic

Follow the detailed upgrade process above. Major versions may include:
- New features
- Configuration format changes (with automatic migration)
- Breaking changes (documented in release notes)

**Before upgrading:**
1. Read the release notes: `https://github.com/carmendata/proxyctl/releases/tag/vX.Y.Z`
2. Check for breaking changes
3. Take backups (Step 2 above)

### Scenario 3: Upgrading with Custom Configurations

If you've manually modified configs in `/etc/`:

**Before upgrade:**
```bash
# Backup your custom configs
sudo cp /etc/rsyslog.d/99-egress-monitor.conf /etc/rsyslog.d/99-egress-monitor.conf.backup
sudo cp /etc/logrotate.d/egress-monitor /etc/logrotate.d/egress-monitor.backup
```

**After upgrade:**
```bash
# Compare your customizations
sudo diff /etc/rsyslog.d/99-egress-monitor.conf.backup /etc/rsyslog.d/99-egress-monitor.conf

# Merge customizations if needed
sudo vi /etc/rsyslog.d/99-egress-monitor.conf

# Restart rsyslog
sudo systemctl restart rsyslog
```

## Rollback

If the upgrade causes issues:

### Quick Rollback

```bash
# 1. Download previous version
VERSION=v0.1.3  # Your previous working version
wget https://github.com/carmendata/proxyctl/releases/download/${VERSION}/proxyctl-linux-amd64

# 2. Replace binary
sudo mv proxyctl-linux-amd64 /usr/local/bin/proxyctl
sudo chmod +x /usr/local/bin/proxyctl

# 3. Reinstall logger with old version
sudo egressctl logger install

# 4. Verify
egressctl version
sudo tail /var/log/egress-connections.log
```

### Restore from Backup

If you need to restore configs:

```bash
# Restore backed up configs
sudo cp /root/proxyctl-backup/99-egress-monitor.conf /etc/rsyslog.d/
sudo cp /root/proxyctl-backup/egress-monitor /etc/logrotate.d/

# Restart services
sudo systemctl restart rsyslog
```

## Verification Checklist

After any upgrade:

- [ ] `egressctl version` shows new version
- [ ] `/var/log/egress-connections.log` exists and has content
- [ ] Old log entries still present (check timestamps before upgrade)
- [ ] New traffic generates new logs (test with `curl` and check log)
- [ ] Rsyslog config exists: `ls /etc/rsyslog.d/99-egress-monitor.conf`
- [ ] Logrotate config exists: `ls /etc/logrotate.d/egress-monitor`
- [ ] Firewall rules active (iptables or nftables, depending on your system)

## Troubleshooting

### Logs Missing After Upgrade

This should **never happen** (upgrade is designed to preserve logs), but if it does:

```bash
# Check if log file was moved
sudo find /var/log -name "egress-connections.log*"

# Check rsyslog for errors
sudo journalctl -u rsyslog -n 50

# Verify rsyslog config
sudo cat /etc/rsyslog.d/99-egress-monitor.conf

# Restart rsyslog
sudo systemctl restart rsyslog
```

### New Logs Not Appearing

```bash
# Check rsyslog status
sudo systemctl status rsyslog

# Check firewall rules
sudo iptables -L EGRESS_LOG -n -v  # For iptables systems
sudo nft list table inet egress_monitor  # For nftables systems

# Generate test traffic
curl -s https://example.com

# Check kernel logs
sudo dmesg | grep EGRESS_MONITOR
```

## Automated Upgrade (Advanced)

For production environments, you can automate upgrades:

```bash
#!/bin/bash
# automated-upgrade.sh

set -euo pipefail

# Backup
sudo mkdir -p /var/backups/proxyctl-$(date +%Y%m%d)
sudo cp /var/log/egress-connections.log* /var/backups/proxyctl-$(date +%Y%m%d)/

# Upgrade
curl -fsSL https://raw.githubusercontent.com/carmendata/proxyctl/main/install.sh | sudo bash

# Reinstall
sudo egressctl logger install

# Verify
if ! sudo tail -1 /var/log/egress-connections.log; then
    echo "ERROR: Logs not working after upgrade"
    exit 1
fi

echo "Upgrade successful"
```

## Future: Dropping iptables Support

**Current Status**: proxyctl supports both iptables and nftables to accommodate legacy production servers.

**Migration Plan**: Once all production servers are upgraded to nftables-based distributions, we can simplify the codebase:

**Target Distributions for nftables-only:**
- Ubuntu 22.04+ (nftables by default)
- Debian 12+ (nftables by default)
- RHEL 9+ / CentOS Stream 9+ (nftables by default)
- Rocky Linux 9+ (nftables by default)

**When to Drop iptables Support:**

Before dropping iptables, verify all production servers are on nftables:

```bash
# Check firewall type on each server
egressctl logger install --dry-run 2>&1 | grep "Firewall detected"

# Should show: "Firewall detected: nftables"
# If shows "iptables", upgrade that server first
```

**After Migration (for maintainers):**

Search codebase for "MIGRATION PLAN" to find all iptables code to remove:

```bash
# Find all migration notes
grep -r "MIGRATION PLAN" --include="*.go" --include="*.md" .

# Key files to modify:
# - internal/firewall/firewall.go (remove iptables functions)
# - internal/logger/logger.go (remove iptables methods)
# - test/integration/run-integration-tests.sh (remove Rocky 8)
# - docs/TESTING.md (update firewall coverage notes)
```

This will reduce code complexity, improve maintainability, and eliminate legacy firewall code.

## Support

If you encounter issues during upgrade:

1. Check the [troubleshooting section](#troubleshooting) above
2. Review release notes: https://github.com/carmendata/proxyctl/releases
3. Open an issue: https://github.com/carmendata/proxyctl/issues

Include in your issue:
- Current version (before upgrade)
- Target version (attempted upgrade)
- Output of `egressctl version`
- Relevant logs from `/var/log/syslog` or `journalctl`
