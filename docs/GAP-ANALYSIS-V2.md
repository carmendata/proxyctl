# Gap Analysis: v1.x → v2.0 Configuration

**Date**: 2025-10-17
**Status**: Analysis Phase
**Target**: v0.9.0 release

## Executive Summary

This document analyzes the gap between the current v1.x implementation and the proposed v2.0 configuration schema. It identifies what exists, what needs to be modified, and what needs to be built from scratch.

---

## Current State (v1.x)

### Config Schema (`internal/config/config.go`)

**Existing Structs**:
```go
type Config struct {
    Mode     string         // "egress" or "ingress"
    Proxy    *ProxyConfig   // v0.8.0+
    Firewall *FirewallConfig // v0.8.0+
    Redirect *RedirectConfig // v0.8.0+ (worker server OUTPUT redirect)
    Logger   *LoggerConfig  // v0.8.0+
    // Legacy fields: Egress, Ingress, HAProxy, Daemon, Logging, Alerts
}

type ProxyConfig struct {
    IP        string // Proxy server IP
    Port      int    // Proxy server port
    StatsPort int    // Optional stats port
}

type FirewallConfig struct {
    Enabled        bool
    InputPolicy    string  // "drop", "block", "ignore"
    AllowSSHFrom   []string
    AllowProxyFrom []AllowProxyFromRule
}

type AllowProxyFromRule struct {
    Sources []string  // IPs or CIDR blocks
    Ports   []int     // Optional ports
}

type RedirectConfig struct {
    Enabled bool
    Type    string    // "partial" or "full"
    Targets []string  // For "partial" type
}
```

### Firewall Implementation (`internal/firewall/`)

**Existing Files**:
- `firewall.go` - Manager, detection, HAProxy installation
- `input.go` - INPUT filtering (creates PROXYCTL_INPUT chain)
- `output.go` - OUTPUT redirect for worker servers (creates PROXYCTL_OUTPUT chain)
- `backup.go` - Automatic backups before changes

**Capabilities**:
- ✅ Dual support: iptables + nftables
- ✅ INPUT filtering with customizable policy
- ✅ SSH allow rules from specified IPs
- ✅ Proxy port allow rules with optional port restrictions
- ✅ Automatic HAProxy installation
- ✅ Automatic backups
- ✅ SSH lockout detection and prevention
- ❌ No interface-aware rules
- ❌ No routing/MASQUERADE support
- ❌ No HAProxy configuration generation

### Routing Implementation

**Status**: ❌ **Does not exist**

**Current Limitation**: No IP forwarding or MASQUERADE support in proxyctl.

### Proxy (HAProxy) Implementation

**Status**: ⚠️ **Partial**

**What Exists**:
- HAProxy installation (`EnsureHAProxy()` in `firewall.go`)
- HAProxy service enabled but NOT configured
- ❌ No HAProxy config generation
- ❌ No transparent proxy setup
- ❌ No PREROUTING redirect rules
- ❌ No ingress reverse proxy config

### Commands (`cmd/proxyctl/`)

**Existing Commands**:
- `firewall apply` - Applies INPUT filtering only
- `firewall remove` - Removes INPUT filtering
- `firewall status` - Shows firewall status (basic)
- `firewall restore` - Restores from backup

**What's Missing**:
- No routing commands
- No proxy configuration commands
- No interface management
- No admin section support

---

## Target State (v2.0)

### New Config Schema

**Required Structs** (See [CONFIG-V2-SCHEMA.md](CONFIG-V2-SCHEMA.md)):
```go
type ConfigV2 struct {
    Admin      AdminConfig
    Interfaces InterfacesConfig
    Firewall   FirewallConfigV2
    Routing    RoutingConfig
    Proxy      ProxyConfigV2
}

type AdminConfig struct {
    Sources []string // Admin IPs with automatic SSH access
    Ports   []int    // Optional, defaults to [22]
}

type InterfacesConfig map[string]string // logical_name -> interface_name

type FirewallConfigV2 struct {
    Enabled       bool
    DefaultPolicy string // "drop", "block", "accept"
    Rules         []FirewallRule
}

type FirewallRule struct {
    Name         string
    Interface    string   // References InterfacesConfig key
    Sources      []string
    Destinations []string // Optional
    Protocol     string   // "tcp", "udp", "icmp", "all"
    Ports        []int    // Optional
    Action       string   // "accept", "drop", "reject"
}

type RoutingConfig struct {
    Enabled   bool
    IPForward bool
    Masquerade MasqueradeConfig
}

type MasqueradeConfig struct {
    Enabled   bool
    Interface string // References InterfacesConfig key
}

type ProxyConfigV2 struct {
    Enabled bool
    Mode    string // "egress", "ingress"
    Type    string // "transparent", "reverse"
    Bind    BindConfig
    Intercept *InterceptConfig // For egress transparent
    Backends  *BackendsConfig  // For ingress reverse
    Logging   *LoggingConfig
}

type BindConfig struct {
    Interface string // References InterfacesConfig key
    Port      int
}

type InterceptConfig struct {
    Ports         []int
    FromInterface string // References InterfacesConfig key
}

type BackendsConfig struct {
    Interface   string // References InterfacesConfig key
    Servers     []BackendServer
    HealthCheck *HealthCheckConfig
    LoadBalance string // "roundrobin", "leastconn", "source"
}

type BackendServer struct {
    IP     string
    Port   int
    Weight int // Optional
}
```

---

## Gap Analysis by Component

### 1. Configuration Parsing

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| JSON unmarshaling | ✅ Exists | ✅ Required | 🔶 **MODIFY** - New structs |
| Validation | ✅ Partial | ✅ Enhanced | 🔶 **MODIFY** - New rules |
| Admin section | ❌ None | ✅ Required | 🔴 **BUILD** - New |
| Interfaces section | ❌ None | ✅ Required | 🔴 **BUILD** - New |
| Firewall v2 rules | ❌ None | ✅ Required | 🔴 **BUILD** - New |
| Routing config | ❌ None | ✅ Required | 🔴 **BUILD** - New |
| Proxy v2 config | ❌ None | ✅ Required | 🔴 **BUILD** - New |
| Interface validation | ❌ None | ✅ Required | 🔴 **BUILD** - Runtime check |
| Config file location | ✅ Exists | ✅ Same | ✅ **KEEP** |

### 2. Firewall Implementation

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| INPUT filtering | ✅ Exists | ✅ Required | 🔶 **MODIFY** - Interface-aware |
| Admin auto-rules | ❌ None | ✅ Required | 🔴 **BUILD** - Generate from admin config |
| Interface-aware rules | ❌ None | ✅ Required | 🔴 **BUILD** - Per-interface filtering |
| Rule naming | ❌ None | ✅ Required | 🔴 **BUILD** - For debugging |
| Destination filtering | ❌ None | ✅ Optional | 🔴 **BUILD** - For advanced rules |
| iptables support | ✅ Exists | ✅ Required | ✅ **KEEP** |
| nftables support | ✅ Exists | ✅ Required | ✅ **KEEP** |
| Backup system | ✅ Exists | ✅ Required | ✅ **KEEP** |
| SSH lockout check | ✅ Exists | ✅ Required | 🔶 **MODIFY** - Use admin config |

### 3. Routing Implementation

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| IP forwarding | ❌ None | ✅ Required | 🔴 **BUILD** - Enable sysctl |
| MASQUERADE (iptables) | ❌ None | ✅ Required | 🔴 **BUILD** - POSTROUTING rule |
| MASQUERADE (nftables) | ❌ None | ✅ Required | 🔴 **BUILD** - NAT table |
| Interface-specific | ❌ None | ✅ Required | 🔴 **BUILD** - Output interface |
| Persistence | ❌ None | ✅ Required | 🔴 **BUILD** - Save rules |
| Remove routing | ❌ None | ✅ Required | 🔴 **BUILD** - Cleanup |

### 4. Proxy (HAProxy) Configuration

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| HAProxy installation | ✅ Exists | ✅ Required | ✅ **KEEP** |
| Config generation | ❌ None | ✅ Required | 🔴 **BUILD** - All modes |
| Transparent egress | ❌ None | ✅ Required | 🔴 **BUILD** - TCP mode |
| PREROUTING redirect | ❌ None | ✅ Required | 🔴 **BUILD** - Intercept ports |
| Reverse ingress | ❌ None | ✅ Required | 🔴 **BUILD** - HTTP/HTTPS LB |
| SSL/TLS support | ❌ None | ✅ Optional | 🔴 **BUILD** - For ingress |
| Health checks | ❌ None | ✅ Optional | 🔴 **BUILD** - For ingress |
| Logging config | ❌ None | ✅ Required | 🔴 **BUILD** - Custom paths |
| Reload HAProxy | ✅ Exists (ACL) | ✅ Required | 🔶 **REUSE** - Extend |

### 5. Commands

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| `firewall apply` | ✅ Exists | ✅ Required | 🔶 **MODIFY** - Support v2 config |
| `firewall remove` | ✅ Exists | ✅ Required | 🔶 **MODIFY** - Remove routing too |
| `firewall status` | ✅ Exists | ✅ Required | 🔶 **MODIFY** - Show routing status |
| `routing apply` | ❌ None | ⚠️ Maybe | 🔴 **BUILD** - Separate command? |
| `routing remove` | ❌ None | ⚠️ Maybe | 🔴 **BUILD** - Separate command? |
| `proxy configure` | ❌ None | ✅ Required | 🔴 **BUILD** - Generate HAProxy config |
| `proxy reload` | ❌ None | ✅ Required | 🔴 **BUILD** - Reload HAProxy |
| `proxy status` | ❌ None | ✅ Required | 🔴 **BUILD** - Show HAProxy status |
| `apply` (unified) | ❌ None | ⚠️ Maybe | 🔴 **BUILD** - Apply all (firewall+routing+proxy) |

### 6. Testing

| Feature | v1.x Status | v2.0 Required | Gap |
|---------|-------------|---------------|-----|
| Unit tests (config) | ❌ 0% coverage | ✅ Required | 🔴 **BUILD** - Validation tests |
| Unit tests (firewall) | ⚠️ 5.4% coverage | ✅ Required | 🔶 **EXPAND** - Rule generation |
| Integration tests | ✅ Exists | ✅ Required | 🔶 **MODIFY** - New scenarios |
| Routing tests | ❌ None | ✅ Required | 🔴 **BUILD** - New suite |
| Proxy tests | ❌ None | ✅ Required | 🔴 **BUILD** - New suite |

---

## Priority Matrix

### P0: Critical Path (Must Have for MVP)

**Goal**: Get egress proxy working on server

1. 🔴 **Config v2 parsing** (admin, interfaces, firewall v2, routing, proxy egress)
2. 🔴 **Routing implementation** (IP forward + MASQUERADE)
3. 🔴 **HAProxy transparent config generation** (egress mode)
4. 🔴 **PREROUTING redirect rules** (intercept ports to HAProxy)
5. 🔴 **Admin auto-rules generation** (SSH lockout prevention)
6. 🔶 **Modify firewall apply** (support v2 config)
7. 🔶 **Modify firewall remove** (cleanup routing + proxy)
8. 🔴 **Apply to egress-proxy-01.carmendata.net** (real server test)

**Estimated Effort**: 2-3 days

### P1: Important (Should Have)

**Goal**: Production-ready egress proxy

9. 🔴 **Unit tests for config v2** (validation logic)
10. 🔴 **Integration tests for routing** (MASQUERADE verification)
11. 🔴 **Integration tests for transparent proxy** (HAProxy + intercept)
12. 🔶 **Enhanced status command** (show all components)
13. 🔴 **Worker server configuration** (route through proxy)
14. 🔴 **End-to-end testing** (worker → egress → internet)

**Estimated Effort**: 1-2 days

### P2: Nice to Have (Future)

**Goal**: Complete v2.0 feature set

15. 🔴 **Ingress reverse proxy support** (HAProxy LB config)
16. 🔴 **SSL/TLS support** (ingress mode)
17. 🔴 **Health checks** (backend monitoring)
18. 🔴 **Destination filtering** (firewall destinations field)
19. 🔴 **Unified `apply` command** (one command for all)
20. 🔶 **CLAUDE.md update** (document v2.0 architecture)

**Estimated Effort**: 2-3 days

---

## Implementation Risks

### High Risk

1. **Interface validation at runtime**
   - Risk: Config references non-existent interfaces
   - Mitigation: Validate on `apply`, provide clear error messages

2. **HAProxy transparent proxy complexity**
   - Risk: HAProxy doesn't properly handle transparent TCP forwarding
   - Mitigation: Test thoroughly, fallback to pure IP/nftables routing if needed (disable proxy section)

3. **MASQUERADE vs conntrack conflicts**
   - Risk: Existing Docker/firewall rules conflict with MASQUERADE
   - Mitigation: Check for conflicts, provide clear error messages

### Medium Risk

4. **Breaking changes adoption**
   - Risk: Users confused by v2.0 config format
   - Mitigation: Clear documentation, migration examples

5. **Multiple interface complexity**
   - Risk: Users misconfigure interface mappings
   - Mitigation: Validation, clear error messages, examples

### Low Risk

6. **Backwards compatibility**
   - Risk: N/A (breaking changes accepted for MVP)

---

## Dependencies

### External

- **HAProxy**: Must support transparent TCP proxying
- **Kernel**: Must support IP forwarding and MASQUERADE (conntrack)
- **iptables/nftables**: Already validated in v1.x

### Internal

- **Firewall manager**: Extend to support routing and PREROUTING rules
- **Config loader**: Rewrite for v2.0 schema
- **Validation logic**: New validation for interfaces, admin, routing

---

## Success Criteria

### MVP Success (P0 Complete)

- ✅ Egress proxy server configured with v2.0 config
- ✅ Worker server routes all traffic through egress proxy
- ✅ HTTP/HTTPS traffic intercepted by HAProxy (logged)
- ✅ Other traffic forwarded directly (not intercepted)
- ✅ All outbound traffic shows egress proxy's public IP
- ✅ Admin SSH access works from office IPs
- ✅ Firewall blocks unauthorized traffic

### Production Ready (P1 Complete)

- ✅ Integration tests pass on multiple distros
- ✅ Unit tests cover all validation logic
- ✅ Status commands show accurate state
- ✅ Documentation updated

### Feature Complete (P2 Complete)

- ✅ Ingress reverse proxy supported
- ✅ SSL/TLS termination working
- ✅ Health checks monitoring backends
- ✅ All documented features implemented

---

## Next Steps

1. Review this gap analysis with stakeholders
2. Create detailed implementation plan
3. Begin P0 implementation
4. Test on egress-proxy-01.carmendata.net
5. Iterate based on real-world testing

---

## See Also

- [CONFIG-V2-SCHEMA.md](CONFIG-V2-SCHEMA.md) - Complete v2.0 schema documentation
- [CLAUDE.md](../CLAUDE.md) - Current architecture (v1.x)
- [FIREWALL-CONFIG.md](FIREWALL-CONFIG.md) - Current firewall implementation
