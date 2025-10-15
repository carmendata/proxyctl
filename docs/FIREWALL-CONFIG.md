# Firewall Configuration via proxyctl

**Status**: Implementation Plan for v0.8.0
**Timeline**: This Week (Before Production Deployment)
**Goal**: Simple, config-driven firewall management for egress proxy infrastructure

---

## Philosophy

**Configuration over commands.** Users define intent in config files, `proxyctl` applies it.

**Benefits:**
- ✅ Self-documenting: Config file shows complete state
- ✅ Version controllable: Check configs into git
- ✅ Testable: Easy to diff and validate
- ✅ Consistent: Same commands everywhere, behavior driven by config
- ✅ Simple: Three commands total (`apply`, `remove`, `status`)
- ✅ Coexists with manual rules: Uses named chains, doesn't modify policies

## Rule Management Strategy

**Named Chains for Isolation:**
- All proxyctl rules use dedicated chains: `PROXYCTL_INPUT`, `PROXYCTL_OUTPUT`
- iptables: Creates separate chains, jumps from INPUT/OUTPUT
- nftables: Creates separate tables with highest priority

**Priority:**
- proxyctl rules are processed **first** (highest priority)
- If no match, behavior controlled by `input_policy`:
  - `"ignore"`: Continue to other firewall rules (coexistence mode)
  - `"drop"`: Silently drop traffic (strict mode)
  - `"block"`: Reject traffic with ICMP response (strict + informative)
- Never modifies base INPUT/OUTPUT chain policies (remain ACCEPT)

**Clean Removal:**
- `egressctl remove` deletes only proxyctl chains/tables
- Manual rules unaffected
- Complete cleanup without touching other firewall configuration

---

## Two Use Cases

### 1. Egress Proxy Server - INPUT Filtering

**Problem**: Egress proxy is exposed to public internet, needs to accept connections only from trusted sources.

**Solution**: Define allowed IPs and policy in config. `proxyctl` creates high-priority INPUT rules that accept trusted traffic. Unmatched traffic is handled per `input_policy`.

### 2. Worker Server - Partial Redirect

**Problem**: Worker needs to route specific destination IPs through egress proxy, all other traffic direct.

**Solution**: Define redirect targets in config, `proxyctl` creates OUTPUT DNAT rules.

---

## Commands (Minimal)

```bash
# Apply configuration (creates/updates firewall rules)
egressctl apply
# Or: proxyctl egress apply

# Remove all proxyctl-managed rules (restore to permissive)
egressctl remove

# Show current configuration and firewall state
egressctl status

# Dry-run: show what would be applied without making changes
egressctl apply --dry-run
```

**That's it.** No complex subcommands, no flag soup. Config drives behavior.

---

## Configuration Examples

### Example 1: Egress Proxy Server

**File**: `/etc/proxyctl/egress.json`

```json
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080,
    "stats_port": 9000
  },
  "acl": {
    "file": "/etc/haproxy/egress-acl.lst"
  },
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": [
      "203.0.113.50",
      "203.0.113.51"
    ],
    "allow_proxy_from": [
      {
        "sources": ["10.0.1.100", "10.0.1.101"],
        "ports": [8080]
      },
      {
        "sources": ["10.0.1.0/24"],
        "ports": [8080, 9000]
      },
      {
        "sources": ["192.168.1.0/24"]
      }
    ]
  },
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress.log"
  }
}
```

**What `egressctl apply` does:**
1. Detects firewall type (iptables or nftables)
2. Creates PROXYCTL_INPUT chain (highest priority)
3. Adds rules to PROXYCTL_INPUT:
   - Allow SSH (port 22) from 203.0.113.50, 203.0.113.51
   - Allow ports 8080 from 10.0.1.100, 10.0.1.101
   - Allow ports 8080, 9000 from 10.0.1.0/24
   - Allow all ports from 192.168.1.0/24
   - Final rule based on `input_policy`:
     - `"drop"`: Adds `DROP` rule (silently drops unmatched traffic)
     - `"block"`: Adds `REJECT` rule (rejects with ICMP response)
     - `"ignore"`: No final rule (returns to INPUT chain)
4. Inserts jump to PROXYCTL_INPUT at top of INPUT chain (highest priority)
5. Persists rules (netfilter-persistent or nftables.service)
6. Does NOT modify base INPUT chain policy (remains ACCEPT)

**Deployment:**
```bash
# On egress proxy server (10.16.0.5)
sudo vim /etc/proxyctl/egress.json  # Add firewall config
sudo egressctl apply                 # Apply rules
sudo egressctl status                # Verify
```

---

### Example 2: Worker Server (Partial Redirect)

**File**: `/etc/proxyctl/egress.json`

```json
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": [
      "8.8.8.8",
      "1.1.1.1",
      "208.67.222.222"
    ]
  }
}
```

**What `egressctl apply` does:**
1. Detects firewall type (iptables or nftables)
2. Creates OUTPUT DNAT chain (EGRESS_PARTIAL)
3. For each target IP:
   - DNAT to 10.16.0.5:8080
   - Kernel preserves original destination port (3306, 443, etc.)
4. All other traffic unaffected (goes direct)
5. Persists rules

**Transparent Proxy Note:**
- **Port 8080** = Where HAProxy **receives** connections
- **Port 3306/443/etc** = Where HAProxy **forwards** connections (preserved by kernel)
- Example: Worker accesses `8.8.8.8:3306` → DNAT to `10.16.0.5:8080` → HAProxy queries kernel for original destination → HAProxy connects to `8.8.8.8:3306`
- Same target IP works with any port (MySQL 3306, HTTPS 443, PostgreSQL 5432, etc.)

**Deployment:**
```bash
# On worker server (10.0.1.100)
sudo vim /etc/proxyctl/egress.json  # Add redirect config
sudo egressctl apply                 # Apply rules
curl -v http://8.8.8.8               # Should go through proxy
curl -v http://example.com           # Should go direct
```

---

### Example 3: Worker Server (Full Redirect)

**File**: `/etc/proxyctl/egress.json`

```json
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
```

**What `egressctl apply` does:**
1. Creates OUTPUT DNAT chain (EGRESS_FULL)
2. Redirects ALL HTTP/HTTPS traffic to proxy
3. Excludes local networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
4. Persists rules

---

## Configuration Schema

### Firewall Section (Egress Proxy Servers)

```json
{
  "firewall": {
    "enabled": true,                              // Enable INPUT filtering
    "input_policy": "drop|block|ignore",          // REQUIRED: unmatched traffic policy
    "allow_ssh_from": ["IP", ...],                // IPs allowed to SSH (port 22)
    "allow_proxy_from": [                         // Port-specific or all-port access
      {
        "sources": ["IP", ...],                   // IPs/CIDRs
        "ports": [PORT, ...]                      // Optional: specific ports
      },
      {
        "sources": ["IP", ...]                    // If ports omitted: all ports allowed
      }
    ]
  }
}
```

**Validation:**
- `enabled` (boolean, required): Enable/disable INPUT filtering
- `input_policy` (string, required when `enabled: true`): Controls unmatched traffic
  - `"drop"`: Silently drop unmatched traffic (strict mode)
  - `"block"`: Reject unmatched traffic with ICMP host-prohibited (strict + informative)
  - `"ignore"`: Return to INPUT chain, let other firewall rules decide (coexistence mode)
- `allow_ssh_from` (array, **strongly recommended**): IPs/CIDRs allowed for SSH (port 22)
  - **If empty/missing**: User prompted with critical warning, must type "yes" to continue
  - **If set**: User's current SSH IP checked against list, warned if not included
  - Omitting this field risks SSH lockout
- `allow_proxy_from` (array, optional): Port-specific or all-port access rules
  - Each entry has:
    - `sources` (array, required): IPs/CIDRs
    - `ports` (array, optional): Port numbers. If omitted, all ports allowed from these sources
- At least one entry in `allow_ssh_from` or `allow_proxy_from` required when `enabled: true`

**Examples:**

**Strict mode** (drop all unmatched):
```json
{
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["203.0.113.50"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
```

**Coexistence mode** (let other rules decide):
```json
{
  "firewall": {
    "enabled": true,
    "input_policy": "ignore",
    "allow_ssh_from": ["203.0.113.50"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
```

**When to use each `input_policy`:**

| Policy | Use Case | Behavior |
|--------|----------|----------|
| `"drop"` | **Production egress proxy** - Maximum security, no other firewall rules needed | Silently drops all unmatched traffic. Only configured IPs can connect. |
| `"block"` | **Development/testing** - Want informative rejections for debugging | Rejects unmatched traffic with ICMP response. Helps diagnose connection issues. |
| `"ignore"` | **Coexistence with existing firewall** - Adding proxyctl rules to existing setup | Returns to INPUT chain. Existing firewall rules continue to work. |

**Recommendation:** Start with `"ignore"` for testing, move to `"drop"` for production.

### Redirect Section (Worker Servers)

```json
{
  "proxy": "IP[:PORT]",                 // Egress proxy address (string format)
  // OR
  "proxy": {                             // Object format (alternative)
    "ip": "IP",
    "port": PORT                         // Optional, defaults to 8080
  },
  "redirect": {
    "enabled": true,                     // Enable OUTPUT redirect
    "type": "partial",                   // "partial" or "full"
    "targets": ["IP", ...]               // Required for "partial", ignored for "full"
  }
}
```

**Validation:**

**Proxy field** (required when `redirect.enabled: true`):
- **Format 1 (simplest)**: `"proxy": "10.16.0.5"` - String without port, defaults to 8080
- **Format 2 (with port)**: `"proxy": "10.16.0.5:8888"` - String with explicit port
- **Format 3 (object)**: `"proxy": { "ip": "10.16.0.5", "port": 8888 }` - Object format
- If port omitted, defaults to 8080 (standard HAProxy egress port)
- Port specifies where HAProxy listens, NOT the destination service port

**Redirect field**:
- `enabled` (boolean, required): Enable/disable OUTPUT redirect
- `type` (string, required): Must be `"partial"` or `"full"`
- `targets` (array): Required when `type: "partial"`, ignored when `type: "full"`
  - Can be IPs (`8.8.8.8`) or CIDR blocks (`203.0.113.0/24`)
  - At least one target required for partial redirect

**Examples:**

**Simplest (default port 8080)**:
```json
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8"]
  }
}
```

**Custom port (string format)**:
```json
{
  "proxy": "10.16.0.5:9999",
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8"]
  }
}
```

**Custom port (object format)**:
```json
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 9999
  },
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8"]
  }
}
```

---

## Implementation Plan

### Phase 1: Core Logic (Days 1-2)

**File**: `internal/firewall/apply.go`

```go
// Apply configuration-driven firewall rules
func (m *Manager) Apply(cfg *config.Config) error {
    // Detect firewall type
    if err := m.Detect(); err != nil {
        return err
    }

    // 1. ALWAYS backup existing rules first (before any changes)
    if err := m.backupCurrentRules(); err != nil {
        log.Warn("Failed to create backup: %v", err)
        // Continue anyway - backup failure shouldn't block apply
    }

    // Safety checks BEFORE applying
    if cfg.Firewall != nil && cfg.Firewall.Enabled {
        // 2. Check for priority conflicts
        if err := m.checkPriorityConflict(); err != nil {
            return fmt.Errorf("priority conflict: %w", err)
        }

        // 3. Check for missing SSH configuration (CRITICAL)
        if len(cfg.Firewall.AllowSSHFrom) == 0 {
            if err := m.confirmNoSSHAccess(); err != nil {
                return fmt.Errorf("aborted: %w", err)
            }
        }

        // 4. Verify current SSH IP is in allow list
        if err := m.verifyCurrentSSHIP(cfg.Firewall.AllowSSHFrom); err != nil {
            // Warning only, not a hard error
            log.Warn(err)
        }
    }

    // Apply INPUT filtering if configured
    if cfg.Firewall != nil && cfg.Firewall.Enabled {
        if err := m.applyInputFiltering(cfg.Firewall); err != nil {
            return err
        }
    }

    // Apply OUTPUT redirect if configured
    if cfg.Redirect != nil && cfg.Redirect.Enabled {
        if err := m.applyOutputRedirect(cfg.Redirect, cfg.Proxy); err != nil {
            return err
        }
    }

    // Persist rules
    return m.Persist()
}
```

**Methods to implement:**
- `backupCurrentRules()` - Backs up current firewall rules to `/etc/proxyctl/backups/firewall-TIMESTAMP.rules`
- `checkPriorityConflict()` - Verifies highest priority is available
- `confirmNoSSHAccess()` - Prompts user if allow_ssh_from is empty, requires "yes" to continue
- `verifyCurrentSSHIP(allowList []string)` - Warns if current SSH IP not in allow list
- `applyInputFiltering(cfg *FirewallConfig)` - Creates PROXYCTL_INPUT chain with rules
- `applyOutputRedirect(cfg *RedirectConfig, proxy *ProxyConfig)` - Creates PROXYCTL_OUTPUT chain with DNAT
- `Remove()` - Removes all proxyctl-managed chains (PROXYCTL_*)
- `Status()` - Returns current state

**Implementation Details for Named Chains:**

**iptables approach:**
```bash
# Create our chain
iptables -N PROXYCTL_INPUT

# Add accept rules
iptables -A PROXYCTL_INPUT -s 203.0.113.50 -p tcp --dport 22 -j ACCEPT
iptables -A PROXYCTL_INPUT -s 10.0.1.0/24 -p tcp --dport 8080 -j ACCEPT

# Add final rule based on input_policy
# input_policy: "drop"
iptables -A PROXYCTL_INPUT -j DROP

# input_policy: "block"
iptables -A PROXYCTL_INPUT -j REJECT --reject-with icmp-host-prohibited

# input_policy: "ignore"
# (no final rule, returns to INPUT chain)

# Insert jump to our chain at position 1 (highest priority)
iptables -I INPUT 1 -j PROXYCTL_INPUT

# Removal is simple: delete jump and flush our chain
iptables -D INPUT -j PROXYCTL_INPUT
iptables -F PROXYCTL_INPUT
iptables -X PROXYCTL_INPUT
```

**nftables approach:**
```bash
# Create our table with highest priority (-1)
nft add table inet proxyctl_filter
nft add chain inet proxyctl_filter input \
  { type filter hook input priority -1 \; }

# Add accept rules
nft add rule inet proxyctl_filter input \
  ip saddr 203.0.113.50 tcp dport 22 accept
nft add rule inet proxyctl_filter input \
  ip saddr 10.0.1.0/24 tcp dport 8080 accept

# Add final rule based on input_policy
# input_policy: "drop"
nft add rule inet proxyctl_filter input drop

# input_policy: "block"
nft add rule inet proxyctl_filter input reject with icmp type host-prohibited

# input_policy: "ignore"
# (no final rule, returns to next priority chain)

# Removal is simple: delete our table
nft delete table inet proxyctl_filter
```

**Priority Conflict Detection:**

**iptables - Check position 1:**
```bash
# List INPUT chain with line numbers
iptables -L INPUT -n --line-numbers | head -5

# Expected output if no conflicts:
# Chain INPUT (policy ACCEPT)
# num  target     prot opt source               destination

# Expected output if proxyctl already applied:
# Chain INPUT (policy ACCEPT)
# num  target     prot opt source               destination
# 1    PROXYCTL_INPUT  all  --  0.0.0.0/0            0.0.0.0/0

# Error condition - position 1 taken by something else:
# Chain INPUT (policy ACCEPT)
# num  target     prot opt source               destination
# 1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED

# Detection logic:
# - Parse output
# - If line 1 exists and target != "PROXYCTL_INPUT" → fail
# - If line 1 is "PROXYCTL_INPUT" → safe (reapplication)
# - If no line 1 → safe (first application)
```

**nftables - Check priority < 0:**
```bash
# List all chains with priorities
nft -a list chains | grep "type filter hook input"

# Expected output if no conflicts:
# (no output or only priority 0 and above)

# Expected output if proxyctl already applied:
# table inet proxyctl_filter {
#   chain input { # handle 1
#     type filter hook input priority -1; policy accept;
#   }
# }

# Error condition - another table at priority -1 or higher:
# table inet some_other_tool {
#   chain input { # handle 1
#     type filter hook input priority -10; policy accept;
#   }
# }

# Detection logic:
# - List all input hooks
# - Find any with priority < 0 (higher than ours)
# - If found and table name != "proxyctl_filter" → fail
# - If "proxyctl_filter" exists at -1 → safe (reapplication)
# - If no chains at priority < 0 → safe (first application)
```

**Key points:**
- iptables: Use custom chain + jump at position 1
- nftables: Use custom table with priority -1 (processed before priority 0)
- **MUST check for priority conflicts before applying**
- Both approaches: Final rule in chain controls unmatched traffic
- `input_policy: "ignore"` = no final rule, traffic continues to other rules
- Easy removal by deleting our chains/tables only
- Never modify base INPUT/OUTPUT chain policies

### Phase 2: Commands (Day 3)

**File**: `cmd/proxyctl/apply.go`

```go
func runApply(globalFlags GlobalFlags, args []string) error {
    // Load config
    cfg, err := config.Load("egress", globalFlags.ConfigPath)
    if err != nil {
        return fmt.Errorf("failed to load config: %w", err)
    }

    // Validate
    if err := cfg.Validate(); err != nil {
        return fmt.Errorf("invalid config: %w", err)
    }

    // Apply
    fwMgr, err := firewall.NewManager()
    if err != nil {
        return err
    }

    return fwMgr.Apply(cfg)
}
```

**Commands:**
- `cmd/proxyctl/apply.go` - Apply configuration
- `cmd/proxyctl/remove.go` - Remove rules
- `cmd/proxyctl/status.go` - Show state

### Phase 3: Safety Features (Day 4)

**Safety checks for INPUT filtering:**

**Order of execution:**
1. **Backup existing firewall rules** (automatic before any changes)
2. Priority conflict detection (fail fast if position/priority taken)
3. Missing SSH configuration check (**requires explicit "yes"**)
4. Current SSH IP verification (warning if not in allow list)
5. All checks pass → proceed with applying rules

**Critical safety net:** All prompts that could cause lockout require typing "yes" exactly (not "y", not default). This prevents accidental confirmation via Enter key or single-character typos.

---

1. **Automatic Backup (Always)**
   ```bash
   sudo egressctl apply

   Backing up existing firewall rules...
   ✓ Backup saved: /etc/proxyctl/backups/firewall-20251014-143052.rules

   Firewall Type: nftables
   Applying configuration...
   ```

   **Backup details:**
   - Automatically created **before every apply**
   - Stored in `/etc/proxyctl/backups/`
   - Filename format: `firewall-YYYYMMDD-HHMMSS.rules`
   - Contains complete ruleset (iptables or nftables)
   - Can be used for manual restoration if needed

   **Backup contents:**
   ```bash
   # iptables backup format
   $ cat /etc/proxyctl/backups/firewall-20251014-143052.rules
   # Generated by proxyctl v0.8.0
   # Backup created: 2025-10-14 14:30:52
   # Firewall type: iptables

   *filter
   :INPUT ACCEPT [0:0]
   :FORWARD ACCEPT [0:0]
   :OUTPUT ACCEPT [0:0]
   -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
   -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
   COMMIT
   ```

   **Manual restoration (if needed):**
   ```bash
   # Restore from backup (iptables)
   sudo iptables-restore < /etc/proxyctl/backups/firewall-20251014-143052.rules

   # Restore from backup (nftables)
   sudo nft -f /etc/proxyctl/backups/firewall-20251014-143052.rules
   ```

2. **Priority Conflict Detection**
   ```bash
   sudo egressctl apply

   Error: Cannot apply INPUT filtering

   Detected non-proxyctl rules at highest priority:

   iptables:
     Position 1 in INPUT chain: ACCEPT all -- anywhere anywhere state RELATED,ESTABLISHED
     (Created by: unknown)

   proxyctl requires position 1 to ensure rules are processed first.

   Options:
     1. Remove conflicting rules manually
     2. Use input_policy: "ignore" to coexist (rules processed after existing)
     3. Contact administrator if rules are managed by another tool
   ```

   **Detection logic:**
   - **iptables**: Check if position 1 in INPUT chain is a jump to PROXYCTL_INPUT
     - If position 1 exists and is NOT our jump → fail
     - If position 1 is our jump → safe to proceed (reapplication)
   - **nftables**: Check for tables with priority < 0 (higher than our -1)
     - List all input hooks with priority < 0
     - If any exist that are NOT `proxyctl_filter` → fail
     - If `proxyctl_filter` exists → safe to proceed (reapplication)

3. **Missing SSH Configuration (Critical)**
   ```bash
   sudo egressctl apply

   ⚠️  CRITICAL: No SSH access configured!

   Your firewall configuration does not include "allow_ssh_from".
   This means NO SSH access will be explicitly allowed.

   Current configuration:
     allow_ssh_from: (empty)
     input_policy: drop

   ⚠️  With input_policy "drop", you will lose SSH access after applying!

   To fix this, add your admin IPs to the config:
     "allow_ssh_from": ["203.0.113.50", "203.0.113.51"]

   Type "yes" to continue anyway (NOT RECOMMENDED): _
   ```

   **Validation:**
   - If `firewall.enabled: true` AND `allow_ssh_from` is empty/missing
   - Require user to type exactly "yes" (not "y", not default)
   - Abort on any other input
   - This prevents accidental lockouts

4. **SSH IP Verification**
   ```bash
   sudo egressctl apply

   Applying INPUT filtering rules (highest priority)...

   SSH access configured for:
     - 203.0.113.50
     - 203.0.113.51

   Your current SSH connection is from: 203.0.113.99
   ⚠️  Your IP is not in the allow_ssh_from list.

   Note: proxyctl rules do not change INPUT policy, but if other firewall
   rules block your IP, you may lose access after applying.

   Options:
     1. Add your IP to allow_ssh_from and retry (recommended)
     2. Continue anyway
     3. Cancel

   Choice [1/2/3]: _
   ```

5. **Dry-run mode**
   ```bash
   sudo egressctl apply --dry-run

   Firewall Type: nftables
   Would create:

   PROXYCTL_INPUT chain (priority: -1, highest):
     ✓ Allow SSH (port 22) from 203.0.113.50, 203.0.113.51
     ✓ Allow port 8080 from 10.0.1.100, 10.0.1.101
     ✓ Allow ports 8080, 9000 from 10.0.1.0/24
     ✓ Allow all ports from 192.168.1.0/24
     ✓ Final rule: drop (input_policy: "drop")

   Note: Base INPUT chain policy remains ACCEPT (not modified by proxyctl)

   Persistence: /etc/nftables.d/proxyctl-filter.nft
   ```

6. **Rollback on failure**
   - Take snapshot before changes
   - Restore on error
   - Confirm changes applied successfully

### Phase 4: Testing (Day 5)

**Unit Tests:**
- Config validation
- INPUT rule generation
- OUTPUT DNAT rule generation
- Rollback logic

**Integration Tests:**
- Ubuntu 22.04 (nftables)
- Debian 12 (nftables)
- CentOS Stream 9 (nftables)
- Ubuntu 20.04 (iptables)

**Test scenarios:**
- Apply INPUT filtering → verify SSH restricted
- Apply partial redirect → verify target goes through proxy, others direct
- Apply full redirect → verify all traffic through proxy
- Remove rules → verify permissive state restored
- Rollback on error → verify no partial state

---

## File Structure

```
cmd/proxyctl/
  main.go              # Existing (mode detection)
  apply.go             # NEW: Apply config-driven rules
  remove.go            # NEW: Remove all proxyctl rules
  status.go            # NEW: Show current state

internal/firewall/
  firewall.go          # Existing (detection, manager)
  apply.go             # NEW: Apply logic
  backup.go            # NEW: Backup/restore functionality
  input.go             # NEW: INPUT filtering implementation
  output.go            # NEW: OUTPUT redirect implementation
  iptables.go          # Existing (iptables implementation)
  nftables.go          # Existing (nftables implementation)
  persist.go           # NEW: Rule persistence

internal/config/
  config.go            # Extend with firewall + redirect schemas
  validate.go          # Add validation for new fields
```

---

## Usage Examples

### Scenario 1: Initial Egress Proxy Setup

```bash
# On egress proxy server (10.16.0.5)

# Step 1: Install proxyctl
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Step 2: Create config
sudo tee /etc/proxyctl/egress.json <<EOF
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
  },
  "acl": {
    "file": "/etc/haproxy/egress-acl.lst"
  },
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["203.0.113.50", "203.0.113.51"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  },
  "logger": {
    "enabled": true
  }
}
EOF

# Step 3: Dry-run to verify
sudo egressctl apply --dry-run

# Step 4: Apply
sudo egressctl apply

# Step 5: Add worker to ACL
sudo egressctl acl add 10.0.1.100

# Step 6: Install logger
sudo egressctl logger install

# Step 7: Verify
sudo egressctl status
```

---

### Scenario 2: Worker Server (Partial Redirect for Testing)

```bash
# On worker server (10.0.1.100)

# Step 1: Install proxyctl
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Step 2: Create config (partial redirect for testing)
sudo tee /etc/proxyctl/egress.json <<EOF
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  }
}
EOF

# Step 3: Apply
sudo egressctl apply

# Step 4: Test
curl -v http://8.8.8.8        # Should go through proxy
curl -v http://example.com    # Should go direct

# Step 5: When ready for full redirect, update config
sudo tee /etc/proxyctl/egress.json <<EOF
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
EOF

# Step 6: Apply full redirect
sudo egressctl apply
```

---

### Scenario 3: Disable Firewall Temporarily

```bash
# On egress proxy server

# Option 1: Edit config and reapply
sudo vim /etc/proxyctl/egress.json  # Set firewall.enabled: false
sudo egressctl apply

# Option 2: Remove all rules (faster for testing)
sudo egressctl remove

# Restore later
sudo egressctl apply  # Reads config, reapplies rules
```

---

## Error Handling

### Missing Config

```bash
sudo egressctl apply

Error: No configuration file found

Searched paths:
  - /etc/proxyctl/egress.json
  - ~/.config/proxyctl/egress.json
  - ./egress.json

Create a config file or use --config flag.
See: docs/FIREWALL-CONFIG.md
```

### Invalid Config

```bash
sudo egressctl apply

Error: Invalid configuration

/etc/proxyctl/egress.json:6: firewall.input_policy must be "drop", "block", or "ignore"
/etc/proxyctl/egress.json:8: firewall.allow_proxy_from[0] missing required field "sources"
/etc/proxyctl/egress.json:12: redirect.targets must contain at least one IP when type is "partial"

Fix errors and try again.
```

### Conflicting Firewall Manager

```bash
sudo egressctl apply

Error: UFW is active on this system

proxyctl cannot manage firewall rules while UFW is active.

Options:
  1. Disable UFW: sudo ufw disable
  2. Configure manually: docs/MANUAL-FIREWALL-SETUP.md
```

### Priority Conflict (Highest Priority Taken)

```bash
sudo egressctl apply

Error: Cannot apply INPUT filtering

Detected non-proxyctl rules at highest priority:

iptables INPUT chain position 1:
  target: DOCKER-USER
  source: all
  destination: all

proxyctl requires the highest priority (position 1) to ensure rules are processed first.

Options:
  1. Remove conflicting rules: sudo iptables -D INPUT 1
  2. Change input_policy to "ignore" in config (proxyctl rules will be lower priority)
  3. If rules are managed by Docker/other tool, consider using input_policy: "ignore"

Note: With input_policy: "ignore", proxyctl rules are still evaluated but unmatched
traffic continues to other rules instead of being dropped.
```

**Common causes:**
- Docker: Creates DOCKER-USER chain at high priority
- Container runtimes: Kubernetes, LXD, Podman create high-priority chains
- Security tools: fail2ban, CSF, custom firewall scripts
- Other infrastructure tools managing firewall

**Resolution:**
- If rules are from Docker/containers and you need strict security: Remove Docker rules, use `input_policy: "drop"`
- If you need to coexist: Use `input_policy: "ignore"`, accept lower priority
- If rules are critical: Don't use proxyctl INPUT filtering, manage firewall manually

---

## Status Output

### Example 1: Egress Proxy with INPUT Filtering

```bash
sudo egressctl status

Configuration: /etc/proxyctl/egress.json
Mode: egress
Firewall Type: nftables

INPUT Filtering: ENABLED (chain: PROXYCTL_INPUT, priority: -1)
  Policy: drop (unmatched traffic dropped)
  SSH (port 22): 203.0.113.50, 203.0.113.51
  Port 8080: 10.0.1.100, 10.0.1.101
  Ports 8080, 9000: 10.0.1.0/24
  All ports: 192.168.1.0/24

OUTPUT Redirect: DISABLED

Logger: ENABLED
  Output: /var/log/proxyctl/egress.log
  Active: yes (3452 connections today)

Persistence: /etc/nftables.d/proxyctl-filter.nft
```

### Example 2: Worker with Partial Redirect

```bash
sudo egressctl status

Configuration: /etc/proxyctl/egress.json
Mode: egress
Firewall Type: iptables

INPUT Filtering: DISABLED

OUTPUT Redirect: ENABLED (partial)
  Proxy: 10.16.0.5:8080
  Targets:
    - 8.8.8.8
    - 1.1.1.1
  Other traffic: Direct (not redirected)

Persistence: /etc/iptables/rules.v4 (via netfilter-persistent)
```

---

## Dry-Run Output

```bash
sudo egressctl apply --dry-run

Configuration: /etc/proxyctl/egress.json
Firewall Type: nftables

Would apply:

INPUT Filtering:
  ✓ Create table: inet proxyctl_filter (priority: -1)
  ✓ Create chain: input hook
  ✓ Allow SSH (port 22) from: 203.0.113.50, 203.0.113.51
  ✓ Allow port 8080 from: 10.0.1.100, 10.0.1.101
  ✓ Allow ports 8080, 9000 from: 10.0.1.0/24
  ✓ Allow all ports from: 192.168.1.0/24
  ✓ Final rule: drop (input_policy: "drop")

OUTPUT Redirect:
  (none configured)

Note: Base INPUT chain policy remains ACCEPT (not modified)

Persistence:
  ✓ Write: /etc/nftables.d/proxyctl-filter.nft
  ✓ Reload: systemctl reload nftables

No changes made (dry-run mode).
Run without --dry-run to apply.
```

---

## Configuration Tips

### Tip 1: Understanding Transparent Proxy (Port 8080 vs Service Ports)

**The proxy port is NOT the service port!**

When you configure `"proxy": "10.16.0.5"` (default port 8080), this is where **HAProxy listens**, not where your services run.

**Example: Same external IP, multiple service ports**

```json
{
  "proxy": "10.16.0.5",
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["203.0.113.100"]
  }
}
```

**This single config enables access to ALL ports on that IP:**

```bash
# MySQL
mysql -h 203.0.113.100 -P 3306
# Flow: worker → DNAT to 10.16.0.5:8080 → HAProxy → 203.0.113.100:3306

# HTTPS API
curl https://203.0.113.100/api
# Flow: worker → DNAT to 10.16.0.5:8080 → HAProxy → 203.0.113.100:443

# PostgreSQL
psql -h 203.0.113.100 -p 5432
# Flow: worker → DNAT to 10.16.0.5:8080 → HAProxy → 203.0.113.100:5432
```

**How it works:**
1. Kernel DNAT redirects traffic to proxy port (8080)
2. Kernel remembers original destination port (3306, 443, 5432, etc.)
3. HAProxy queries kernel: `getsockopt(SO_ORIGINAL_DST)`
4. HAProxy connects to original destination with original port

**When to specify a custom port:**
- **Default (8080)**: `"proxy": "10.16.0.5"` - Standard HAProxy setup
- **Custom port**: `"proxy": "10.16.0.5:9999"` - HAProxy listens on non-standard port
- **Multiple proxies**: Different HAProxy instances for different traffic types

### Tip 2: Use CIDR Blocks for Worker IPs

**Instead of:**
```json
{
  "firewall": {
    "allow_proxy_from": [
      {"sources": ["10.0.1.100"], "ports": [8080]},
      {"sources": ["10.0.1.101"], "ports": [8080]},
      {"sources": ["10.0.1.102"], "ports": [8080]},
      {"sources": ["10.0.1.103"], "ports": [8080]}
    ]
  }
}
```

**Use:**
```json
{
  "firewall": {
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  }
}
```

Easier to manage, fewer firewall rules.

### Tip 3: Version Control Your Configs

```bash
# Store configs in git
cd /etc/proxyctl
git init
git add egress.json
git commit -m "Initial egress proxy config"

# Track changes
vim egress.json
git diff
git commit -am "Add worker subnet to allow_proxy_from"
```

### Tip 4: Test with Partial Before Full Redirect

Always test with `type: "partial"` first:
1. Add one or two test IPs to `targets`
2. Apply and verify those IPs route through proxy
3. When confident, change to `type: "full"`

### Tip 4: Keep Admin IPs Current

If your admin IP changes (VPN reconnect, ISP change):
```bash
# Quick fix to avoid lockout
sudo egressctl remove              # Restore permissive INPUT
vim /etc/proxyctl/egress.json      # Update allow_ssh_from
sudo egressctl apply               # Reapply with new IP
```

---

## Migration from Manual iptables/nftables

If you've manually configured firewall rules, proxyctl makes migration safe and easy:

**Automatic Backups**: proxyctl automatically backs up your existing firewall rules to `/etc/proxyctl/backups/` before making any changes. You can always restore from these backups if needed.

```bash
# Step 1: Create proxyctl config matching current setup
sudo vim /etc/proxyctl/egress.json

# Step 2: Dry-run to compare
sudo egressctl apply --dry-run

# Step 3: Apply (backup created automatically, then proxyctl rules applied)
sudo egressctl apply

# Example output:
# Backing up existing firewall rules...
# ✓ Backup saved: /etc/proxyctl/backups/firewall-20251014-143052.rules
# Applying configuration...

# Step 4: Test thoroughly
# Your manual rules still exist - proxyctl adds its own named chains
# Test SSH access, proxy connectivity, etc.

# Step 5: (Optional) Remove manual rules once satisfied
sudo iptables -F  # Or appropriate nftables commands
sudo egressctl apply  # Reapply to ensure proxyctl rules active

# Step 6: Check backups directory for reference
ls -lh /etc/proxyctl/backups/
# firewall-20251014-143052.rules  (backup before first apply)
# firewall-20251014-145230.rules  (backup before manual rule removal)
```

**Restoration if needed:**
```bash
# If something goes wrong, restore from the most recent backup
sudo iptables-restore < /etc/proxyctl/backups/firewall-20251014-143052.rules
# Or for nftables:
sudo nft -f /etc/proxyctl/backups/firewall-20251014-143052.rules
```

---

## Future Enhancements (Post v0.8.0)

Possible additions based on user feedback:

### Port-Based Redirect
```json
{
  "redirect": {
    "type": "selective",
    "ports": [80, 443],           // Only HTTP/HTTPS through proxy
    "targets": "all"              // All destinations
  }
}
```

### Multiple Proxies
```json
{
  "redirect": {
    "rules": [
      {"targets": ["8.8.8.8"], "proxy": "10.16.0.5:8080"},
      {"targets": ["1.1.1.1"], "proxy": "10.16.0.6:8080"}
    ]
  }
}
```

### IPv6 Support
```json
{
  "firewall": {
    "allow_ssh_from": [
      "203.0.113.50",
      "2001:db8::1"               // IPv6 address
    ]
  }
}
```

### Time-Based Rules
```json
{
  "firewall": {
    "allow_proxy_from": ["10.0.1.0/24"],
    "schedule": {
      "days": ["mon", "tue", "wed", "thu", "fri"],
      "hours": "09:00-17:00"
    }
  }
}
```

**But:** Only add these if users actually need them. Start simple.

---

## Timeline

### Day 1: Config Schema & Validation
- [ ] Extend `internal/config/config.go` with firewall and redirect structs
- [ ] Add validation methods
- [ ] Update example configs
- [ ] Unit tests for validation

### Day 2: Firewall Logic (INPUT)
- [ ] Implement `internal/firewall/input.go`
- [ ] Support both iptables and nftables
- [ ] Persistence logic
- [ ] Unit tests

### Day 3: Firewall Logic (OUTPUT)
- [ ] Implement `internal/firewall/output.go`
- [ ] Partial redirect logic
- [ ] Full redirect logic
- [ ] Unit tests

### Day 4: Commands & Safety
- [ ] Implement `internal/firewall/backup.go` (automatic backup functionality)
- [ ] Implement `cmd/proxyctl/apply.go`
- [ ] Implement `cmd/proxyctl/remove.go`
- [ ] Implement `cmd/proxyctl/status.go`
- [ ] Add safety checks (SSH IP detection, confirmation prompts)
- [ ] Add dry-run support

### Day 5: Integration Testing
- [ ] Test on Ubuntu 22.04 (nftables)
- [ ] Test on Debian 12 (nftables)
- [ ] Test on Ubuntu 20.04 (iptables)
- [ ] Test INPUT filtering + SSH restriction
- [ ] Test partial redirect
- [ ] Test full redirect
- [ ] Test rollback on failure

### Day 6: Documentation & Release
- [ ] Update DEPLOYMENT.md with config examples
- [ ] Update README.md with new commands
- [ ] Update CLAUDE.md with config schema
- [ ] Tag v0.8.0
- [ ] Release notes

---

## Success Criteria

✅ **Simplicity:**
- 3 commands total (apply, remove, status)
- All behavior driven by config
- No complex flag combinations

✅ **Safety:**
- Automatic backup before every apply
- SSH lockout warnings
- Dry-run mode
- Rollback on failure
- Config validation before apply

✅ **Maintainability:**
- Config files in version control
- Easy to audit (cat config file)
- Easy to test (change config, apply, verify)

✅ **Extensibility:**
- Add features by extending config schema
- No CLI redesign required
- Backward compatible (add optional fields)

---

**Document Status**: Revised Implementation Plan (Config-Driven)
**Last Updated**: 2025-10-14
**Target Version**: v0.8.0
