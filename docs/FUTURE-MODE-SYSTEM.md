# Future Development: Server Mode System

**Status**: Future Enhancement (v0.9.0+)
**Priority**: Medium
**Estimated Effort**: 2-3 weeks

---

## Vision

Transform proxyctl from a collection of discrete firewall management commands into a **server role management system** where a single "mode" declaration configures all firewall aspects for that server's role in the infrastructure.

## Current State (v0.x.x)

Users must manually configure multiple aspects:
- INPUT filtering (SSH access, service ports)
- OUTPUT NAT (egress proxy routing)
- Logging (connection monitoring)
- IP forwarding (proxy functionality)

**Pain points:**
- Easy to forget steps (INPUT filtering commonly missed)
- No holistic view of server's security posture
- Inconsistent configurations across fleet
- Manual tracking of what rules exist

## Proposed State (v0.9.0+)

**Single command configures everything:**
```bash
# Egress proxy server
proxyctl mode egress --admin-ips 203.0.113.50,203.0.113.51

# Internal worker server
proxyctl mode internal --egress-proxy 10.16.0.5 --admin-ips 203.0.113.50
```

All INPUT, OUTPUT, NAT, logging, and service configuration handled automatically.

---

## Mode Definitions

### 1. Egress Mode

**Purpose**: Server acts as transparent egress proxy for internal servers

**Firewall Configuration:**
- **INPUT**:
  - Allow: SSH from admin IPs
  - Allow: Port 8080 from worker IPs (ACL-based)
  - Block: Everything else
- **OUTPUT**: Normal (unrestricted to internet)
- **FORWARD**: Allow (enables IP forwarding)
- **NAT**: None (server doesn't route through another proxy)
- **Logging**: Monitor outbound connections from workers

**Services Required:**
- HAProxy listening on port 8080
- IP forwarding enabled: `net.ipv4.ip_forward=1`
- ACL file: `/etc/haproxy/acl.lst`

**Use Case:** Permanent egress proxy servers with stable IPs

---

### 2. Internal Mode

**Purpose**: Worker server that routes outbound traffic through egress proxy

**Firewall Configuration:**
- **INPUT**:
  - Allow: SSH from admin IPs
  - Allow: Service-specific ports (configurable)
  - Block: Everything else
- **OUTPUT**: Redirect ports 80/443/22 to egress proxy via DNAT
- **FORWARD**: Block (not routing for others)
- **NAT**: OUTPUT DNAT for specific ports/destinations
- **Logging**: Optional (monitor own outbound connections)

**Variants:**
- **Full Redirect**: All HTTP/HTTPS/SSH → egress proxy
- **Partial Redirect**: Only specific IPs → egress proxy (testing mode)

**Use Case:** Application servers, database servers, worker nodes

---

### 3. Standalone Mode

**Purpose**: Regular server with direct internet access

**Firewall Configuration:**
- **INPUT**:
  - Allow: SSH from admin IPs
  - Allow: Service-specific ports (configurable)
  - Block: Everything else
- **OUTPUT**: Normal (direct internet access)
- **FORWARD**: Block
- **NAT**: None
- **Logging**: Optional

**Use Case:** Servers that don't need proxy (monitoring, logging, etc.)

---

### 4. Dual Mode

**Purpose**: Server acts as both egress and ingress proxy

**Firewall Configuration:**
- **INPUT**:
  - Allow: SSH from admin IPs
  - Allow: Port 8080 from worker IPs (egress)
  - Allow: Port 80/443 from internet (ingress)
  - Block: Everything else
- **OUTPUT**: Normal
- **FORWARD**: Allow (proxy for both directions)
- **NAT**: Ingress DNAT for backend routing
- **Logging**: Both egress and ingress traffic

**Services Required:**
- HAProxy with both egress and ingress frontends
- Separate ACL files for egress/ingress
- Backend health checking

**Use Case:** Small deployments, cost optimization

---

### 5. Ingress Mode

**Purpose**: Server acts as ingress proxy/load balancer

**Firewall Configuration:**
- **INPUT**:
  - Allow: SSH from admin IPs
  - Allow: Port 80/443 from internet
  - Allow: Port 9000 for stats (optional)
  - Block: Everything else
- **OUTPUT**: Allow to backend servers
- **FORWARD**: Allow (proxying to backends)
- **NAT**: DNAT for backend routing
- **Logging**: Ingress traffic monitoring

**Services Required:**
- HAProxy with ingress configuration
- SSL certificate management
- Backend health checking
- Consul/Vault integration (for ephemeral deployments)

**Use Case:** Load balancers, API gateways, ephemeral web frontends

---

## Configuration Schema

### Config File Format

```json
{
  "admin_ips": [
    "203.0.113.50",
    "203.0.113.51"
  ],
  "egress": {
    "private_ip": "10.16.0.5",
    "public_ip": "203.0.113.100",
    "port": 8080,
    "acl_file": "/etc/haproxy/acl.lst",
    "auto_reload": true
  },
  "haproxy": {
    "config_file": "/etc/haproxy/haproxy.cfg"
  }
}
```

### Mode-Specific Fields

**Egress Mode:**
```json
{
  "mode": "egress",
  "admin_ips": ["..."],
  "egress": {
    "private_ip": "10.16.0.5",
    "port": 8080,
    "acl_file": "/etc/haproxy/acl.lst"
  }
}
```

**Internal Mode (Full):**
```json
{
  "mode": "internal",
  "admin_ips": ["..."],
  "internal": {
    "egress_proxy_ip": "10.16.0.5",
    "egress_proxy_port": 8080,
    "redirect_ports": [80, 443, 22],
    "service_ports": [3000, 5432]  // Allow inbound for services
  }
}
```

**Internal Mode (Partial - Testing):**
```json
{
  "mode": "internal",
  "admin_ips": ["..."],
  "internal": {
    "egress_proxy_ip": "10.16.0.5",
    "egress_proxy_port": 8080,
    "partial_redirect": {
      "enabled": true,
      "targets": ["8.8.8.8", "1.1.1.1", "203.0.113.0/24"]
    }
  }
}
```

**Standalone Mode:**
```json
{
  "mode": "standalone",
  "admin_ips": ["..."],
  "standalone": {
    "allow_inbound_ports": [80, 443, 3000]
  }
}
```

---

## Command Interface

### Mode Management

```bash
# Apply mode from config file
proxyctl mode apply [--config /path/to/config.json]

# Apply mode via command line
proxyctl mode egress --admin-ips 203.0.113.50,203.0.113.51
proxyctl mode internal --egress-proxy 10.16.0.5 --admin-ips 203.0.113.50

# Show current mode
proxyctl mode status

# Remove all mode configuration (cleanup)
proxyctl mode remove

# Validate mode config without applying
proxyctl mode validate
```

### Mode Transitions

```bash
# Switch from internal (partial) to internal (full)
proxyctl mode internal --egress-proxy 10.16.0.5 --admin-ips 203.0.113.50

# Switch from standalone to internal
proxyctl mode internal --egress-proxy 10.16.0.5 --admin-ips 203.0.113.50

# Decommission (remove all proxyctl firewall rules)
proxyctl mode remove
```

---

## Implementation Details

### Architecture

```
cmd/proxyctl/
  mode.go                    // Mode command handlers
  mode_egress.go            // Egress mode configuration
  mode_internal.go          // Internal mode configuration
  mode_standalone.go        // Standalone mode configuration

internal/
  firewall/
    mode.go                 // Mode configuration logic
    mode_egress.go         // Egress-specific firewall setup
    mode_internal.go       // Internal-specific firewall setup
  config/
    mode.go                 // Mode configuration schema
```

### Mode State Management

**Option 1: Config File**
- Store mode in `/etc/proxyctl/{mode}.json`
- Field: `"mode": "egress"`
- Pro: Single source of truth
- Con: Manual editing could break mode

**Option 2: Separate State File**
- Store mode in `/var/lib/proxyctl/mode`
- Pro: Separate from user config
- Con: Another file to manage

**Option 3: Detect from Firewall Rules**
- Inspect existing rules to determine mode
- Pro: No state file needed
- Con: Detection could be fragile

**Recommendation**: Option 1 (config file)

### Backward Compatibility

**Existing commands continue to work:**
```bash
# These still function as before:
egressctl acl add 10.0.1.100
egressctl logger install
egressctl server configure 10.16.0.5
```

**Mode is optional:**
- Can use low-level commands without mode
- Can use mode for high-level configuration
- Mode doesn't replace existing commands, enhances them

**Migration path:**
```bash
# Existing deployment (no mode)
egressctl acl add 10.0.1.100
egressctl logger install

# Migrate to mode (idempotent)
proxyctl mode apply  # Detects existing setup, fills in gaps
```

---

## Benefits

### 1. Reduced Complexity

**Before (10+ manual steps):**
```bash
# Setup egress proxy
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -p tcp --dport 22 -s 203.0.113.50 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.100 -j ACCEPT
sudo sysctl -w net.ipv4.ip_forward=1
sudo egressctl logger install
sudo egressctl acl add 10.0.1.100
# ... more steps
```

**After (1 command):**
```bash
proxyctl mode egress --admin-ips 203.0.113.50
proxyctl acl add 10.0.1.100  # Day-to-day operations
```

### 2. Security by Default

- INPUT filtering configured automatically (currently often forgotten)
- Principle of least privilege enforced
- All modes include admin IP restrictions
- No partially configured servers

### 3. Clear Intent

```bash
# Instead of inspecting 50+ firewall rules:
proxyctl mode status

# Output:
Mode: egress
Admin IPs: 203.0.113.50, 203.0.113.51
Worker IPs in ACL: 12
IP Forwarding: Enabled
Logging: Active
```

### 4. Consistent Fleet

- All egress proxies configured identically
- All internal servers configured identically
- Infrastructure as Code friendly
- Ansible/Terraform integration easier

### 5. Easier Troubleshooting

```bash
# Instead of: "Why can't I SSH to this server?"
# Now: Check mode status, see allowed IPs

proxyctl mode status
# Shows exactly what's allowed/blocked
```

---

## Challenges

### 1. Mode Transitions

**Question**: What happens when switching modes?

**Answer**: Full cleanup, then reapply
```bash
# Internally:
1. Flush all proxyctl-managed rules
2. Apply new mode configuration
3. Verify services match mode requirements
```

### 2. Partial Configurations

**Question**: Can user override mode defaults?

**Answer**: Yes, via config file
```json
{
  "mode": "egress",
  "admin_ips": ["..."],
  "custom_input_rules": [
    {"port": 8443, "sources": ["10.0.2.0/24"]}
  ]
}
```

### 3. Service Dependencies

**Question**: Mode requires HAProxy, but it's not installed?

**Answer**: Pre-flight checks
```bash
proxyctl mode egress
# Error: HAProxy not found
# Suggestion: sudo apt-get install haproxy
```

### 4. Existing Rules

**Question**: Server has existing iptables rules?

**Answer**: Two options:
- **Safe mode**: Refuse to apply (default)
- **Force mode**: `--force` flag (dangerous)

---

## Testing Strategy

### Unit Tests

- Config validation
- Rule generation logic
- Mode transition logic
- State management

### Integration Tests

- Apply each mode on fresh VMs
- Verify all firewall rules created
- Test service functionality
- Test mode transitions
- Test rollback

### Acceptance Tests

```bash
# Egress mode acceptance:
1. SSH from allowed IP → success
2. SSH from disallowed IP → blocked
3. Worker connection on 8080 → success
4. Random connection on 8080 → blocked
5. Outbound internet → works
```

---

## Migration from v0.x.x to v0.9.0

### For Existing Deployments

**Egress Proxy Servers:**
```bash
# Current state (v0.x.x):
# - ACL configured: egressctl acl list shows IPs
# - Logger installed: egressctl logger analyze works
# - No INPUT filtering (missing!)

# Migrate to mode system:
proxyctl mode apply --detect --admin-ips 203.0.113.50

# Result:
# - Detects existing ACL, logger
# - Adds missing INPUT filtering
# - Writes mode to config
```

**Internal Worker Servers:**
```bash
# Current state (v0.x.x):
# - OUTPUT NAT configured: egressctl server configure ran
# - No INPUT filtering (missing!)

# Migrate to mode system:
proxyctl mode apply --detect --admin-ips 203.0.113.50

# Result:
# - Detects existing OUTPUT NAT
# - Adds missing INPUT filtering
# - Writes mode to config
```

### Zero Downtime Migration

1. Install new proxyctl version
2. Run `proxyctl mode apply --detect --dry-run`
3. Review proposed changes
4. Apply: `proxyctl mode apply --detect`
5. Verify: `proxyctl mode status`

---

## Roadmap

### v0.8.0 (Immediate - This Week)
- ✅ Add `server configure-partial` for Phase 2 testing
- ✅ Add basic INPUT filtering helpers
- ✅ Abstract iptables/nftables complexity

### v0.9.0 (Post-Deployment - 1-2 months)
- Implement `mode` command
- Support `egress` and `internal` modes
- Add `mode apply`, `mode status`, `mode remove`
- Migration support for existing deployments
- Comprehensive testing

### v1.0.0 (Production Ready - 3-4 months)
- All modes implemented (dual, standalone, ingress)
- Mode transitions fully supported
- Production hardening
- Full documentation
- Integration with IaC tools

---

## Design Questions (To Be Resolved)

1. **Service Management**: Should mode system manage HAProxy config too?
   - Pro: Complete server role management
   - Con: Too opinionated, users may want custom HAProxy configs

2. **Multi-tenant**: Can one server be in multiple modes?
   - Example: egress + monitoring + bastion?
   - Or: Force single mode per server?

3. **Cloud Integration**: Should mode system configure cloud firewalls too?
   - AWS Security Groups
   - DigitalOcean Firewalls
   - GCP Firewall Rules

4. **Rollback**: Should mode changes be transactional?
   - Snapshot before change
   - Auto-rollback on failure
   - Manual rollback: `proxyctl mode rollback`

5. **Auditability**: Log all mode changes?
   - `/var/log/proxyctl-mode.log`
   - Include timestamp, user, old mode, new mode
   - Integration with system audit logs

---

## References

### Similar Systems

- **UFW**: High-level firewall manager (but opinionated)
- **firewalld**: Zone-based firewall (similar concept to modes)
- **Docker network modes**: bridge, host, overlay (inspiration)

### Design Principles

1. **Convention over Configuration**: Sensible defaults for each mode
2. **Progressive Disclosure**: Simple by default, complex when needed
3. **Fail-Safe**: Refuse to apply dangerous configurations
4. **Idempotent**: Can run mode apply multiple times safely
5. **Transparent**: Always show what's being changed

---

## Conclusion

The mode system transforms proxyctl from a **tool** into a **platform** for managing server roles in proxy infrastructure. It significantly reduces complexity, improves security, and provides clear intent.

**Key Decision**: Implement post-deployment (v0.9.0) after gathering production usage feedback on current implementation.

---

**Document Status**: Proposal for future development
**Last Updated**: 2025-10-14
**Version**: 1.0
