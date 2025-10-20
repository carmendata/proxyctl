# Configuration Examples

This directory contains configuration examples for **proxyctl** showing only features that are **currently implemented and working**.

## Quick Reference

| File | Server Type | Use Case | Commands Used |
|------|-------------|----------|---------------|
| `egress-acl.json.example` | Egress Proxy | ACL management only | `egressctl acl`, `egressctl server check` |
| `egress-firewall.json.example` | Egress Proxy | Firewall INPUT filtering | `egressctl firewall` |
| `egress-full.json.example` | Egress Proxy | ACL + Firewall + Logger | All egress commands |
| `worker-redirect-partial.json.example` | Worker Server | Selective traffic redirect (DNAT) | `egressctl firewall apply` |
| `worker-redirect-full.json.example` | Worker Server | Full traffic redirect (DNAT) | `egressctl firewall apply` |
| `worker-gateway.json.example` | Worker Server | Policy routing via gateway | `egressctl firewall apply` |

## Configuration Format

**V2 format** (introduced in v0.8.0) is the only supported configuration format:

```json
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080,
    "stats_port": 9000
  },
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["203.0.113.50"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ]
  },
  "redirect": {
    "enabled": true,
    "type": "partial",  // Options: "partial", "full", or "gateway"
    "targets": ["8.8.8.8", "1.1.1.1"],
    // For "gateway" type only:
    "gateway": "10.106.80.2",  // Gateway IP for policy routing
    "routing_table": 200  // Optional: Custom routing table ID (1-252)
  },
  "logger": {
    "enabled": true,
    "name": "egress",
    "log_path": "/var/log/proxyctl/"
  }
}
```

**Available Commands:**
- **ACL Management**: `egressctl acl add|remove|list|reload`
- **Server Check**: `egressctl server check <IP>`
- **Firewall**: `egressctl firewall apply|remove|status|restore`
- **Logger**: `egressctl logger install|remove|analyze`
- **Status**: `egressctl status`

## Deployment Scenarios

### 1. Egress Proxy Server (ACL Only)
**Config:** `egress-acl.json.example`

Minimal setup for managing which internal servers can use the proxy.

```bash
# Deploy config
sudo cp configs/egress-acl.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Update IPs

# Manage ACL
egressctl acl add 10.0.1.100
egressctl acl list
```

### 2. Egress Proxy Server (Firewall Protected)
**Config:** `egress-firewall.json.example`

Secure egress proxy with INPUT filtering to restrict access.

```bash
# Deploy config
sudo cp configs/egress-firewall.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Configure IPs

# Apply firewall rules
egressctl firewall apply
egressctl firewall status
```

### 3. Egress Proxy Server (Full Featured)
**Config:** `egress-full.json.example`

Combines both ACL management and firewall protection.

```bash
# Deploy config
sudo cp configs/egress-full.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Configure all settings

# Use all features
egressctl acl add 10.0.1.100
egressctl firewall apply
egressctl logger install
egressctl status
```

### 4. Worker Server (Partial Redirect)
**Config:** `worker-redirect-partial.json.example`

Worker server that routes only specific destinations through egress proxy (Phase 2 testing).

```bash
# Deploy config on worker
sudo cp configs/worker-redirect-partial.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Update proxy IP and targets

# Apply redirect rules
egressctl firewall apply
```

### 5. Worker Server (Full Redirect)
**Config:** `worker-redirect-full.json.example`

Worker server that routes ALL outbound traffic through egress proxy (Phase 3 production).

```bash
# Deploy config on worker
sudo cp configs/worker-redirect-full.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Update proxy IP

# Apply redirect rules
egressctl firewall apply --dry-run  # Test first
egressctl firewall apply            # Apply for real
```

### 6. Worker Server (Gateway Routing)
**Config:** `worker-gateway.json.example`

Worker server that uses policy routing to route specific destinations via a gateway IP (alternative to DNAT).

**Use Case:** When you need to route traffic via a specific gateway instead of using DNAT redirect.

**How It Works:**
- Marks packets destined for target IPs with fwmark
- Uses policy routing (`ip rule` + `ip route`) to send marked packets via gateway
- Persists across reboots using systemd service

```bash
# Deploy config on worker
sudo cp configs/worker-gateway.json.example /etc/proxyctl/egress.json
sudo nano /etc/proxyctl/egress.json  # Update gateway IP and targets

# Apply gateway routing
egressctl firewall apply --dry-run  # Test first
egressctl firewall apply            # Apply for real

# Verify routing
egressctl status                    # Shows routing config and drift
ip rule list                        # Shows policy routing rule
ip route show table egress          # Shows gateway route
```

## Field Reference

### Proxy Section
| Field | Type | Format | Description |
|-------|------|--------|-------------|
| `ip` or string | string/object | `"10.16.0.5"` or `{"ip":"10.16.0.5"}` | Proxy server IP |
| `port` | int | - | Proxy port (default: 8080) |
| `stats_port` | int | - | HAProxy stats port |

### Firewall Section
| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `enabled` | bool | - | Enable firewall rules |
| `input_policy` | string | `drop`, `block`, `ignore` | Default INPUT policy |
| `allow_ssh_from` | array | IPs/CIDRs | Allow SSH from these sources |
| `allow_proxy_from` | array | Rule objects | Allow proxy access rules |

### Redirect Section
| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `enabled` | bool | - | Enable traffic redirect/routing |
| `type` | string | `partial`, `full`, `gateway` | Redirect/routing type |
| `targets` | array | IPs/CIDRs | Destinations to redirect/route (required for `partial` and `gateway`) |
| `gateway` | string | IP address | Gateway IP address (required for `gateway` type only) |
| `routing_table` | int | 1-252 | Custom routing table ID (optional for `gateway` type, default: 200) |

**Redirect Types:**
- `partial`: DNAT redirect for specific targets only
- `full`: DNAT redirect for all traffic
- `gateway`: Policy routing via gateway IP (uses fwmark + `ip rule` + `ip route`)

### Logger Section
| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enabled` | bool | Yes | - | Enable connection logging |
| `name` | string | Yes | - | Logger name (used for log files, prefixes, identifiers) |
| `log_path` | string | No | `/var/log/proxyctl/` | Directory for log files |
| `protocols` | array | No | `["tcp", "udp"]` | Protocols to monitor: `tcp`, `udp`, `icmp` |
| `include_private` | bool | No | `false` | Monitor private IP ranges (RFC1918) |
| `include_ranges` | array | No | `[]` | Whitelist specific IPs/CIDRs (if set, only these are monitored) |
| `exclude_ranges` | array | No | `[]` | Blacklist specific IPs/CIDRs |

**Logger Examples:**
```json
// Default logger
{"enabled": true, "name": "egress"}

// Custom logger for specific database traffic
{"enabled": true, "name": "db-primary", "protocols": ["tcp"], "include_ranges": ["10.0.10.5"]}

// Custom log directory
{"enabled": true, "name": "mylogger", "log_path": "/custom/path/"}
```

**Logger Naming:**
- Allowed characters: `a-z`, `A-Z`, `0-9`, `_`, `-`
- Max 32 characters
- Cannot start with hyphen or dot
- Reserved names: `all`, `test`, `tmp`, `temp`, `con`, `prn`, `aux`, `nul`
- Name determines all file paths and identifiers (e.g., `db-primary` creates `/var/log/proxyctl/db-primary.log`)

**Migration Note:** Configs with old `output` field are automatically migrated to new `name` + `log_path` format

## Important Notes

1. **Not Implemented Yet:**
   - `haproxy`, `daemon`, `logging`, `alerts` sections (defined but not used)
   - All `ingressctl` commands
   - Daemon mode

2. **Firewall Safety:**
   - Always use `--dry-run` first when applying firewall rules
   - Keep SSH access configured to avoid lockouts
   - Backups are created automatically before changes

3. **Default Config Location:**
   - `/etc/proxyctl/egress.json` (system-wide)
   - `~/.config/proxyctl/egress.json` (user-specific)
   - Override with `--config` flag

## Archive

Old configuration examples with unimplemented features have been moved to `archive/` for reference.
