# Immediate Implementation: Firewall Helper Commands

**About This Document:**
- All commands use `egressctl` for brevity (the egress mode symlink)
- These are equivalent: `egressctl cmd` = `proxyctl egress cmd`
- The `proxyctl` binary detects its invocation name and auto-selects mode
- See [CLAUDE.md](../CLAUDE.md#operating-modes-symlink-detection) for details

**Status**: Implementation Plan for v0.8.0
**Timeline**: This Week (Before Production Deployment)
**Goal**: Abstract iptables/nftables complexity behind simple commands

---

## Command Invocation Model

This document uses `egressctl` for brevity, but understand the relationship:

```bash
# These are equivalent (symlink detection):
egressctl firewall secure ...
proxyctl egress firewall secure ...

# Similarly:
ingressctl backend add ...
proxyctl ingress backend add ...

# The proxyctl binary detects its invocation name and auto-selects mode
```

**In this document:** All examples use `egressctl` for readability.
**In practice:** Users can use either form interchangeably.

---

## Principle

**Users shouldn't need to know whether their server uses iptables or nftables.**

proxyctl should:
1. Auto-detect firewall type
2. Execute correct commands for that type
3. Provide consistent interface regardless of underlying system
4. Handle persistence automatically

---

## Commands to Implement

### 1. Partial Redirect (Phase 2 Testing)

**Purpose**: Redirect only specific destination IPs through egress proxy

**Command:**
```bash
# Add partial redirect
egressctl server configure-partial <PROXY_IP> --targets <IP1>,<IP2>,<IP3> [--port PORT]
# Or equivalently: proxyctl egress server configure-partial ...

# Examples:
egressctl server configure-partial 10.16.0.5 --targets 8.8.8.8,1.1.1.1
egressctl server configure-partial 10.16.0.5 --targets 203.0.113.0/24 --port 8080

# Remove partial redirect
egressctl server remove-partial

# Show partial redirect status
egressctl server status
```

**What it does:**
- Detects iptables or nftables
- Creates EGRESS_PARTIAL chain (iptables) or egress_partial table (nftables)
- Adds DNAT rules for specified targets only
- Persists rules (netfilter-persistent or nftables service)
- All other traffic remains direct (unaffected)

**Implementation:**
- File: `cmd/proxyctl/server.go`
- Command: `egressctl server configure-partial` (alias: `proxyctl egress server configure-partial`)
- Methods: `runServerConfigurePartial()`, `runServerRemovePartial()`
- Firewall: `internal/firewall/firewall.go:ConfigurePartialEgressProxy()`

---

### 2. INPUT Filtering (Security Hardening)

**Purpose**: Block all incoming traffic except SSH and proxy port from trusted sources

**Command:**
```bash
# Configure INPUT filtering for egress proxy
# (Note: egressctl = proxyctl egress for all commands below)
egressctl firewall secure \
  --allow-ssh-from 203.0.113.50,203.0.113.51 \
  --allow-port 8080 --from 10.0.1.100,10.0.1.101 \
  [--allow-port 9000 --from 203.0.113.50]

# Or simpler shorthand for egress proxy:
egressctl firewall secure-egress \
  --admin-ips 203.0.113.50,203.0.113.51 \
  --worker-ips 10.0.1.100,10.0.1.101

# Remove INPUT filtering (restore permissive)
egressctl firewall unsecure

# Show INPUT filter status
egressctl firewall status
```

**What it does:**
- Detects iptables or nftables
- Sets INPUT policy to DROP
- Allows loopback (lo)
- Allows established connections
- Allows SSH from specified admin IPs
- Allows proxy port from specified worker IPs
- Allows optional stats port from admin IPs
- Persists rules

**Implementation:**
- File: `cmd/proxyctl/firewall.go` (new file)
- Methods: `runFirewallSecure()`, `runFirewallUnsecure()`, `runFirewallStatus()`
- Firewall: `internal/firewall/firewall.go:ConfigureInputFiltering()`

---

### 3. Firewall Status (Visibility)

**Purpose**: Show current firewall configuration in human-readable format

**Command:**
```bash
egressctl firewall status

# Or for specific aspect:
egressctl firewall status --input
egressctl firewall status --output
egressctl firewall status --nat
```

**Example Output:**
```
Firewall Type: nftables
Firewall Status: Active

INPUT Chain:
  Policy: DROP
  SSH (22): Allowed from 203.0.113.50, 203.0.113.51
  Proxy (8080): Allowed from 10.0.1.100, 10.0.1.101
  Stats (9000): Allowed from 203.0.113.50

OUTPUT Chain:
  Policy: ACCEPT

NAT (OUTPUT):
  EGRESS_PARTIAL: Redirecting 8.8.8.8, 1.1.1.1 to 10.16.0.5:8080

Persistence: Enabled (nftables.service)
```

**Implementation:**
- Parses iptables or nftables output
- Presents in consistent format
- Shows human-readable summary

---

## Command Design Philosophy

### 1. Simple by Default

**Bad** (too many options):
```bash
egressctl firewall add-rule --chain INPUT --protocol tcp --dport 22 --source 203.0.113.50 --jump ACCEPT
```

**Good** (sensible defaults):
```bash
egressctl firewall secure-egress --admin-ips 203.0.113.50 --worker-ips 10.0.1.100
```

### 2. Named Parameters

**Bad** (positional):
```bash
egressctl server configure-partial 10.16.0.5 8080 8.8.8.8 1.1.1.1
```

**Good** (named):
```bash
egressctl server configure-partial 10.16.0.5 --targets 8.8.8.8,1.1.1.1 --port 8080
```

### 3. Consistent Invocation

**Mode-specific commands are always scoped:**

```bash
# Mode is explicit in command structure
egressctl server configure-partial ...   # Egress-specific
ingressctl backend add ...               # Ingress-specific

# Equivalent long-form (useful for scripts):
proxyctl egress server configure-partial ...
proxyctl ingress backend add ...
```

**Why both forms exist:**
- **Symlinks** (`egressctl`, `ingressctl`): Shorter, role-specific, preferred for interactive use
- **Explicit mode** (`proxyctl egress`, `proxyctl ingress`): Clear intent, better for scripts/docs

### 4. Safety First

**Always ask for confirmation when:**
- Changing INPUT policy to DROP (could lock out user)
- Removing security rules
- Flushing firewall

```bash
egressctl firewall secure-egress --admin-ips 203.0.113.50

WARNING: This will block all incoming traffic except SSH from 203.0.113.50
Make sure you can access the server from this IP before proceeding.

Continue? (yes/no): █
```

### 5. Dry Run

**All commands support --dry-run:**
```bash
egressctl firewall secure-egress --admin-ips 203.0.113.50 --dry-run

# Output:
Would execute (nftables):
  - Set INPUT policy to DROP
  - Allow SSH from 203.0.113.50
  - Allow loopback
  - Allow established connections
  - Create config: /etc/nftables.d/input-filter.nft
  - Reload: systemctl reload nftables
```

---

## Implementation Details

### File Structure

```
cmd/proxyctl/
  main.go             # Mode detection via symlink (egressctl → egress mode)
  server.go           # Egress commands (add configure-partial, remove-partial)
  firewall.go         # NEW (secure, unsecure, status commands)

internal/firewall/
  firewall.go         # Existing (add new methods)
  partial.go          # NEW (partial redirect logic)
  input.go            # NEW (INPUT filtering logic)
```

### New Methods in `internal/firewall/firewall.go`

```go
// Partial Redirect
func (m *Manager) ConfigurePartialEgressProxy(proxyIP string, proxyPort int, targets []string) error
func (m *Manager) RemovePartialEgressProxyRules() error

// INPUT Filtering
func (m *Manager) ConfigureInputFiltering(config InputFilterConfig) error
func (m *Manager) RemoveInputFiltering() error
func (m *Manager) GetInputFilterStatus() (InputFilterStatus, error)

// Types
type InputFilterConfig struct {
    AdminIPs    []string  // IPs allowed for SSH
    WorkerIPs   []string  // IPs allowed for proxy port
    ProxyPort   int       // Default 8080
    StatsPort   int       // Optional, default 0 (disabled)
}

type InputFilterStatus struct {
    Enabled     bool
    Policy      string    // ACCEPT or DROP
    SSHAllowed  []string
    PortRules   []PortRule
}
```

---

## Usage Examples

### Example 1: Egress Proxy Setup

```bash
# Step 1: Install proxyctl (creates proxyctl + egressctl + ingressctl symlinks)
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Step 2: Configure ACL (using egressctl alias)
sudo egressctl acl add 10.0.1.100
# Or: sudo proxyctl egress acl add 10.0.1.100

# Step 3: Install logger
sudo egressctl logger install

# Step 4: Secure firewall (NEW!)
sudo egressctl firewall secure-egress \
  --admin-ips 203.0.113.50,203.0.113.51 \
  --worker-ips 10.0.1.100,10.0.1.101

# Step 5: Verify
sudo egressctl firewall status
```

**Result**: Fully secured egress proxy with 4 simple commands

### Example 2: Worker Server (Phase 2 Testing)

```bash
# Step 1: Install proxyctl (creates egressctl symlink)
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Step 2: Configure partial redirect (NEW!)
sudo egressctl server configure-partial 10.16.0.5 --targets 8.8.8.8,1.1.1.1

# Step 3: Test
curl -v http://8.8.8.8        # Should go through proxy
curl -v http://example.com    # Should go direct

# Step 4: When ready, upgrade to full
sudo egressctl server remove-partial
sudo egressctl server configure 10.16.0.5
```

**Result**: Smooth Phase 2 → Phase 3 transition

### Example 3: Troubleshooting

```bash
# Show current firewall state
sudo egressctl firewall status

# Example output:
Firewall Type: nftables
INPUT: DROP policy
  - SSH allowed from: 203.0.113.50, 203.0.113.51
  - Port 8080 allowed from: 10.0.1.100, 10.0.1.101

OUTPUT NAT:
  - EGRESS_PARTIAL active
  - Redirecting: 8.8.8.8, 1.1.1.1 → 10.16.0.5:8080

# Check if rules persisted
sudo egressctl firewall status --verbose
# Shows: Rules will persist (nftables.service enabled)
```

---

## Safety Features

### 1. Confirmation Prompts

For dangerous operations:
```bash
sudo egressctl firewall secure-egress --admin-ips 203.0.113.50

⚠️  WARNING: Changing INPUT Policy to DROP
This will block all incoming connections except:
  - SSH from: 203.0.113.50
  - Proxy port from: (ACL-based)

If 203.0.113.50 is not your current IP, you may be locked out!

Your current IP: 203.0.113.99

Type 'yes' to continue, or Ctrl+C to abort: █
```

### 2. Current IP Detection

```bash
sudo egressctl firewall secure-egress --admin-ips 203.0.113.50

⚠️  DANGER: Your current SSH connection is from 203.0.113.99
This IP is NOT in the admin IPs list!

If you proceed, your current session will likely be terminated.

Options:
  1. Add your current IP to admin list
  2. Continue anyway (dangerous!)
  3. Abort

Choice: █
```

### 3. Rollback on Failure

If INPUT filtering fails (nftables syntax error, etc.):
```bash
Error applying firewall rules: nftables syntax error

Rolling back changes...
✓ INPUT policy restored to ACCEPT
✓ Previous rules restored

Your connection is safe.
```

### 4. Test Mode

Apply rules temporarily (auto-rollback after 60 seconds unless confirmed):
```bash
sudo egressctl firewall secure-egress --test --admin-ips 203.0.113.50

Rules applied temporarily. They will auto-rollback in 60 seconds.

Test your SSH access from 203.0.113.50 NOW.

If it works, run: sudo egressctl firewall confirm
If not, wait 60 seconds for auto-rollback.

Time remaining: 60s █████████████████████░░░
```

---

## Error Handling

### Scenario 1: No Firewall Detected

```bash
sudo egressctl firewall secure-egress --admin-ips 203.0.113.50

Error: No firewall detected (iptables or nftables required)

Attempting to install nftables...
✓ nftables installed successfully

Retry command? (yes/no): █
```

### Scenario 2: Conflicting Firewall Manager

```bash
sudo egressctl firewall secure-egress --admin-ips 203.0.113.50

Error: UFW is active on this system

proxyctl cannot manage firewall rules while UFW is active.
(Note: This applies to all invocation forms: egressctl, ingressctl, proxyctl)

Options:
  1. Disable UFW and use proxyctl (recommended)
     sudo ufw disable

  2. Keep UFW and configure manually
     See: docs/MANUAL-FIREWALL-SETUP.md

  3. Use proxyctl mode system (future: v0.9.0)
```

### Scenario 3: Partial Existing Rules

```bash
sudo egressctl firewall secure-egress --admin-ips 203.0.113.50

Warning: Existing INPUT rules detected

Found custom rules:
  - Allow port 3000 from 10.0.2.0/24
  - Allow port 5432 from 10.0.3.0/24

Options:
  1. Preserve existing rules and add proxyctl rules
  2. Replace all INPUT rules (will remove custom rules)
  3. Abort

Choice: █
```

---

## Testing Plan

### Unit Tests

```go
// Test partial redirect logic
func TestConfigurePartialEgressProxy(t *testing.T) {
    // Test iptables
    // Test nftables
    // Test IP validation
    // Test CIDR validation
}

// Test INPUT filtering logic
func TestConfigureInputFiltering(t *testing.T) {
    // Test policy change
    // Test rule generation
    // Test persistence
}
```

### Integration Tests

Run on actual VMs with iptables and nftables:

```bash
# Test partial redirect
./test/integration/test-partial-redirect.sh --os ubuntu-22-04
./test/integration/test-partial-redirect.sh --os debian-12

# Test INPUT filtering
./test/integration/test-input-filtering.sh --os ubuntu-22-04
./test/integration/test-input-filtering.sh --os centos-stream-9
```

### Manual Testing Checklist

**Partial Redirect:**
- [ ] Configure partial redirect
- [ ] Test redirected IP goes through proxy
- [ ] Test non-redirected IP goes direct
- [ ] Remove partial redirect
- [ ] Verify all traffic direct again

**INPUT Filtering:**
- [ ] Configure INPUT filtering
- [ ] SSH from allowed IP works
- [ ] SSH from disallowed IP blocked
- [ ] Proxy connection from allowed IP works
- [ ] Proxy connection from disallowed IP blocked
- [ ] Remove INPUT filtering
- [ ] Verify permissive access restored

---

## Documentation Updates

### Update DEPLOYMENT.md

**Replace:**
- Step 1.11: Manual iptables/nftables commands
- Step 2.2: Bash script for partial redirect

**With:**
- Step 1.11: `egressctl firewall secure-egress` command
- Step 2.2: `egressctl server configure-partial` command

### Update README.md

Add new commands to quick start:
```bash
# Secure egress proxy
egressctl firewall secure-egress --admin-ips 203.0.113.50 --worker-ips 10.0.1.100

# Partial redirect (testing)
egressctl server configure-partial 10.16.0.5 --targets 8.8.8.8,1.1.1.1
```

---

## Timeline

### Day 1 (Today)
- [x] Document future mode system
- [ ] Design firewall helper commands (this doc)
- [ ] Review and approve design

### Day 2
- [ ] Implement partial redirect
  - `cmd/proxyctl/server.go`: Add commands
  - `internal/firewall/partial.go`: Add logic
  - Unit tests

### Day 3
- [ ] Implement INPUT filtering
  - `cmd/proxyctl/firewall.go`: Add commands
  - `internal/firewall/input.go`: Add logic
  - Safety features (confirmation, rollback)
  - Unit tests

### Day 4
- [ ] Integration testing
  - Test on Ubuntu, Debian, CentOS
  - Test iptables and nftables
  - Test safety features

### Day 5
- [ ] Documentation updates
  - Update DEPLOYMENT.md
  - Update README.md
  - Add command examples
  - Update DEPLOYMENT-CAPABILITY-VERIFICATION.md

### Day 6
- [ ] Final testing and release
  - Manual testing of full deployment workflow
  - Tag v0.8.0
  - Update release notes

---

## Success Criteria

✅ **Deployment simplification:**
- Egress proxy setup: 4 commands (down from 15+ manual steps)
- Worker setup: 2 commands for Phase 2, 1 command for Phase 3

✅ **User experience:**
- No need to know iptables vs nftables
- Clear error messages with solutions
- Safety confirmations prevent lockouts

✅ **Maintainability:**
- Code reuses existing firewall detection
- Tests cover both firewall types
- Documentation updated

---

**Document Status**: Implementation Plan
**Last Updated**: 2025-10-14
**Target Version**: v0.8.0
