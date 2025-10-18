# Configuration Examples

This directory contains configuration examples for **proxyctl** showing only features that are **currently implemented and working**.

## Quick Reference

| File | Server Type | Use Case | Commands Used |
|------|-------------|----------|---------------|
| `egress-acl.json.example` | Egress Proxy | ACL management only | `egressctl acl`, `egressctl server check` |
| `egress-firewall.json.example` | Egress Proxy | Firewall INPUT filtering | `egressctl firewall` |
| `egress-full.json.example` | Egress Proxy | ACL + Firewall + Logger | All egress commands |
| `worker-redirect-partial.json.example` | Worker Server | Selective traffic redirect | `egressctl firewall apply` |
| `worker-redirect-full.json.example` | Worker Server | Full traffic redirect | `egressctl firewall apply` |

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
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  },
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress.log"
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
| `enabled` | bool | - | Enable traffic redirect |
| `type` | string | `partial`, `full` | Redirect type |
| `targets` | array | IPs/CIDRs | Destinations to redirect (partial only) |

### Logger Section
| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable connection logging |
| `output` | string | Log file path |

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
