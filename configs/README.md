# Configuration Examples

This directory contains configuration examples for **proxyctl** showing only features that are **currently implemented and working**.

## Quick Reference

| File | Server Type | Use Case | Commands Used |
|------|-------------|----------|---------------|
| `egress-acl.json.example` | Egress Proxy | ACL management only | `egressctl acl`, `egressctl server check` |
| `egress-firewall.json.example` | Egress Proxy | Firewall INPUT filtering | `egressctl firewall` |
| `egress-combined.json.example` | Egress Proxy | ACL + Firewall combined | All egress commands |
| `worker-redirect-partial.json.example` | Worker Server | Selective traffic redirect | `egressctl firewall apply` |
| `worker-redirect-full.json.example` | Worker Server | Full traffic redirect | `egressctl firewall apply` |

## Configuration Formats

### V1 Format (Legacy - ACL Management)
Used for ACL management and server health checks. Only these fields are actually used:

```json
{
  "egress": {
    "private_ip": "10.16.0.5",
    "public_ip": "203.0.113.100",
    "port": 8080,
    "acl_file": "/etc/haproxy/acl.lst",
    "auto_reload": true
  }
}
```

**Working Commands:**
- `egressctl acl add <IP>` - Add IP to ACL
- `egressctl acl remove <IP>` - Remove IP from ACL
- `egressctl acl list` - List ACL entries
- `egressctl acl reload` - Reload HAProxy
- `egressctl server check <IP>` - Check remote server config
- `egressctl status` - Show proxy status

### V2 Format (Modern - Firewall & Redirect)
Used for firewall rules and traffic redirection (v0.8.0+):

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

**Working Commands:**
- `egressctl firewall apply` - Apply firewall rules
- `egressctl firewall remove` - Remove firewall rules
- `egressctl firewall status` - Show firewall status
- `egressctl firewall restore` - Restore from backup
- `egressctl logger install` - Install connection logger
- `egressctl logger remove` - Remove connection logger
- `egressctl logger analyze` - Analyze logs

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
**Config:** `egress-combined.json.example`

Combines both ACL management and firewall protection.

```bash
# Deploy config
sudo cp configs/egress-combined.json.example /etc/proxyctl/egress.json
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

### Egress Section (V1)
| Field | Type | Required | Used By | Description |
|-------|------|----------|---------|-------------|
| `private_ip` | string | ✓ | `server check` | Private IP of egress proxy |
| `public_ip` | string | - | `server check` | Public IP (fallback) |
| `port` | int | ✓ | `server check` | Proxy port (default: 8080) |
| `acl_file` | string | ✓ | `acl`, `status` | ACL file path |
| `auto_reload` | bool | - | `acl` | Auto-reload HAProxy on ACL changes |

### Proxy Section (V2)
| Field | Type | Format | Description |
|-------|------|--------|-------------|
| `ip` or string | string/object | `"10.16.0.5"` or `{"ip":"10.16.0.5"}` | Proxy server IP |
| `port` | int | - | Proxy port (default: 8080) |
| `stats_port` | int | - | HAProxy stats port |

### Firewall Section (V2)
| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `enabled` | bool | - | Enable firewall rules |
| `input_policy` | string | `drop`, `block`, `ignore` | Default INPUT policy |
| `allow_ssh_from` | array | IPs/CIDRs | Allow SSH from these sources |
| `allow_proxy_from` | array | Rule objects | Allow proxy access rules |

### Redirect Section (V2)
| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `enabled` | bool | - | Enable traffic redirect |
| `type` | string | `partial`, `full` | Redirect type |
| `targets` | array | IPs/CIDRs | Destinations to redirect (partial only) |

### Logger Section (V2)
| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable connection logging |
| `output` | string | Log file path |

## Important Notes

1. **V1 vs V2 Can Coexist**: You can use both formats in the same config file (see `egress-combined.json.example`)

2. **Not Implemented Yet:**
   - `haproxy`, `daemon`, `logging`, `alerts` sections (defined but not used)
   - All `ingressctl` commands
   - Daemon mode

3. **Firewall Safety:**
   - Always use `--dry-run` first when applying firewall rules
   - Keep SSH access configured to avoid lockouts
   - Backups are created automatically before changes

4. **Default Config Location:**
   - `/etc/proxyctl/egress.json` (system-wide)
   - `~/.config/proxyctl/egress.json` (user-specific)
   - Override with `--config` flag

## Archive

Old configuration examples with unimplemented features have been moved to `archive/` for reference.
