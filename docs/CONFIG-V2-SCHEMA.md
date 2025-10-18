# Configuration Schema v2.0

**Status**: Design Phase
**Version**: 2.0.0
**Breaking Changes**: Yes (from v1.x)
**Target Release**: v0.9.0

## Overview

Version 2.0 of the configuration schema introduces a unified, interface-aware configuration model that supports three independent operational modes:

1. **Firewall** - INPUT filtering and access control
2. **Routing** - IP forwarding with MASQUERADE (transparent egress)
3. **Proxy** - HAProxy configuration (egress transparent or ingress reverse)

## Design Principles

- **Interface-Aware**: All modes explicitly specify network interfaces
- **Unlimited Interfaces**: Support physical, virtual, VPN, Docker, bonded, VLAN interfaces
- **Admin Section**: Automatic SSH lockout prevention via global admin rules
- **Mode Independence**: Firewall, routing, and proxy can be enabled/disabled independently
- **Explicit Configuration**: No auto-detection, user specifies everything
- **Breaking Changes OK**: Pre-production MVP, no backwards compatibility required

---

## Schema Sections

### 1. Admin Section

**Purpose**: Global SSH access rules to prevent lockout. Automatically creates highest-priority SSH allow rules on all interfaces.

```json
{
  "admin": {
    "sources": ["213.48.12.11/32", "149.241.32.219/32"],
    "ports": [22]
  }
}
```

**Fields**:
- `sources` (required): Array of IP addresses or CIDR blocks with admin access
- `ports` (optional): Array of ports for admin access. Defaults to `[22]`

**Behavior**:
- Creates rules with **highest priority** (processed first)
- Applies to **all interfaces** defined in the `interfaces` section
- Always allows ESTABLISHED,RELATED connections from these sources
- Equivalent to: `iptables -I INPUT 1 -s <source> -p tcp --dport 22 -j ACCEPT` (per source, per interface)

**Validation**:
- At least one source IP/CIDR required
- Sources must be valid IP addresses or CIDR notation
- Ports must be in range 1-65535

---

### 2. Interfaces Section

**Purpose**: Define logical names for physical and virtual network interfaces.

```json
{
  "interfaces": {
    "public": "eth0",
    "private": "eth1",
    "docker": "docker0",
    "vpn": "tun0",
    "management": "eth2"
  }
}
```

**Fields**:
- Key: Logical name (referenced in firewall/routing/proxy rules)
- Value: Actual Linux interface name (e.g., `eth0`, `ens3`, `docker0`)

**Supported Interface Types**:
- Physical: `eth0`, `eth1`, `ens3`, `enp0s3`
- Virtual: `docker0`, `br-xxx`, `veth-xxx`
- VPN: `tun0`, `wg0`, `vpn0`
- Bonded: `bond0`, `bond1`
- VLAN: `eth0.10`, `eth0.20`
- Loopback: `lo` (special case for proxy bind)

**Validation**:
- At least one interface required if any mode is enabled
- Interface names must exist on the system at runtime
- Interface names referenced in rules must be defined
- Logical names must be valid identifiers (alphanumeric + underscore)

**Special Interface**:
- `loopback`: Always maps to `lo` (127.0.0.1), used for transparent proxy binding

---

### 3. Firewall Section

**Purpose**: INPUT filtering and access control rules. Interface-aware for fine-grained control.

```json
{
  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "allow-workers",
        "interface": "private",
        "sources": ["178.62.33.58/32", "10.0.1.0/24"],
        "protocol": "all",
        "action": "accept"
      },
      {
        "name": "allow-mysql-from-private",
        "interface": "private",
        "sources": ["10.0.1.0/24"],
        "protocol": "tcp",
        "ports": [3306],
        "action": "accept"
      },
      {
        "name": "allow-https-public",
        "interface": "public",
        "sources": ["0.0.0.0/0"],
        "protocol": "tcp",
        "ports": [443, 80],
        "action": "accept"
      }
    ]
  }
}
```

**Fields**:
- `enabled` (required): Boolean to enable/disable firewall
- `default_policy` (required): Default action for unmatched traffic
  - Values: `"drop"`, `"block"`, `"accept"`
  - `drop`: Silently drop packets (recommended)
  - `block`: Reject with ICMP host-prohibited
  - `accept`: Allow (not recommended for production)
- `rules` (optional): Array of firewall rules

**Rule Fields**:
- `name` (required): Human-readable identifier for the rule
- `interface` (required): Logical interface name from `interfaces` section
- `sources` (required): Array of source IPs or CIDR blocks
- `destinations` (optional): Array of destination IPs or CIDR blocks
- `protocol` (required): Protocol to match
  - Values: `"tcp"`, `"udp"`, `"icmp"`, `"all"`
- `ports` (optional): Array of destination ports (only valid for tcp/udp)
- `action` (required): Action to take
  - Values: `"accept"`, `"drop"`, `"reject"`

**Rule Processing Order**:
1. Admin rules (highest priority, auto-generated)
2. Loopback traffic (always allowed)
3. ESTABLISHED,RELATED connections (always allowed)
4. User-defined rules (in order specified)
5. Default policy

**Implementation**:
- iptables: Creates `PROXYCTL_INPUT` chain at position 1 in INPUT
- nftables: Creates `proxyctl_filter` table with priority -1

---

### 4. Routing Section

**Purpose**: Enable IP forwarding and MASQUERADE for transparent egress proxying.

```json
{
  "routing": {
    "enabled": true,
    "ip_forward": true,
    "masquerade": {
      "enabled": true,
      "interface": "public"
    }
  }
}
```

**Fields**:
- `enabled` (required): Boolean to enable/disable routing
- `ip_forward` (required): Enable kernel IP forwarding (`net.ipv4.ip_forward=1`)
- `masquerade` (required): MASQUERADE configuration
  - `enabled` (required): Boolean to enable/disable MASQUERADE
  - `interface` (required): Logical interface name for outbound MASQUERADE

**Behavior**:
- Sets `net.ipv4.ip_forward=1` in sysctl
- Creates MASQUERADE rule in POSTROUTING: `iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE`
- All outbound traffic via specified interface gets source IP rewritten to interface's IP
- Return traffic automatically handled by conntrack (reverse NAT)

**Use Cases**:
- Transparent egress proxy (workers route through this server)
- NAT gateway for private networks
- VPN gateway

**Implementation**:
- iptables: `iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE`
- nftables: `nft add rule ip nat postrouting oifname "<interface>" masquerade`
- Persistence: Rules saved to `/etc/iptables/rules.v4` or `/etc/nftables.d/proxyctl-routing.nft`

---

### 5. Proxy Section

**Purpose**: HAProxy configuration for transparent egress or reverse ingress proxying.

#### 5a. Egress Transparent Proxy

**Use Case**: Intercept HTTP/HTTPS from worker servers for logging/inspection, forward all other traffic.

```json
{
  "proxy": {
    "enabled": true,
    "mode": "egress",
    "type": "transparent",
    "bind": {
      "interface": "loopback",
      "port": 3128
    },
    "intercept": {
      "ports": [80, 443],
      "from_interface": "private"
    },
    "logging": {
      "enabled": true,
      "path": "/var/log/haproxy/egress.log",
      "format": "combined"
    }
  }
}
```

**Fields**:
- `enabled` (required): Boolean to enable/disable proxy
- `mode` (required): Operating mode
  - Values: `"egress"`, `"ingress"`
- `type` (required): Proxy type
  - For egress: `"transparent"`
  - For ingress: `"reverse"`
- `bind` (required): Binding configuration
  - `interface` (required): Logical interface name (usually `loopback` for transparent)
  - `port` (required): Port to listen on
- `intercept` (required for egress): Traffic interception rules
  - `ports` (required): Array of ports to intercept (e.g., `[80, 443]`)
  - `from_interface` (required): Logical interface name for incoming traffic
- `logging` (optional): Logging configuration
  - `enabled` (required): Boolean to enable/disable logging
  - `path` (required): Log file path
  - `format` (optional): Log format. Values: `"combined"`, `"json"`. Defaults to `"combined"`

**Behavior**:
- HAProxy binds to `127.0.0.1:<port>` (loopback interface)
- PREROUTING rules redirect intercepted ports to HAProxy:
  - `iptables -t nat -A PREROUTING -i <from_interface> -p tcp --dport <port> -j REDIRECT --to-port <bind_port>`
- HAProxy forwards to original destination (transparent mode)
- Traffic not matching intercept ports bypasses HAProxy (goes through routing/MASQUERADE)

**Generated HAProxy Config**:
```haproxy
frontend http_transparent
    bind 127.0.0.1:3128
    mode tcp
    default_backend http_forward

backend http_forward
    mode tcp
    server forward 0.0.0.0:0
```

#### 5b. Ingress Reverse Proxy

**Use Case**: Load balancing for backend application servers.

```json
{
  "proxy": {
    "enabled": true,
    "mode": "ingress",
    "type": "reverse",
    "bind": {
      "interface": "public",
      "port": 443
    },
    "ssl": {
      "enabled": true,
      "cert_dir": "/etc/ssl/certs"
    },
    "backends": {
      "interface": "private",
      "servers": [
        {"ip": "10.0.1.10", "port": 8080},
        {"ip": "10.0.1.11", "port": 8080}
      ],
      "health_check": {
        "enabled": true,
        "interval": "5s",
        "timeout": "3s",
        "path": "/health"
      },
      "load_balance": "roundrobin"
    },
    "logging": {
      "enabled": true,
      "path": "/var/log/haproxy/ingress.log"
    }
  }
}
```

**Additional Fields**:
- `ssl` (optional): SSL/TLS configuration
  - `enabled` (required): Boolean to enable/disable SSL
  - `cert_dir` (required): Directory containing SSL certificates
- `backends` (required for ingress): Backend server configuration
  - `interface` (required): Logical interface for backend communication
  - `servers` (required): Array of backend servers
    - `ip` (required): Backend server IP
    - `port` (required): Backend server port
    - `weight` (optional): Load balancing weight (1-256)
  - `health_check` (optional): Health check configuration
    - `enabled` (required): Boolean to enable/disable health checks
    - `interval` (required): Check interval (e.g., `"5s"`, `"10s"`)
    - `timeout` (required): Check timeout
    - `path` (required): HTTP path for health checks
  - `load_balance` (optional): Load balancing algorithm
    - Values: `"roundrobin"`, `"leastconn"`, `"source"`
    - Default: `"roundrobin"`

---

## Complete Examples

### Example 1: Egress Proxy with Hybrid Mode

**Scenario**: Transparent egress proxy that intercepts HTTP/HTTPS for logging, forwards all other traffic.

```json
{
  "admin": {
    "sources": ["213.48.12.11/32", "149.241.32.219/32"]
  },

  "interfaces": {
    "public": "eth0",
    "private": "eth1"
  },

  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "allow-worker-all-traffic",
        "interface": "private",
        "sources": ["178.62.33.58/32"],
        "protocol": "all",
        "action": "accept"
      }
    ]
  },

  "routing": {
    "enabled": true,
    "ip_forward": true,
    "masquerade": {
      "enabled": true,
      "interface": "public"
    }
  },

  "proxy": {
    "enabled": true,
    "mode": "egress",
    "type": "transparent",
    "bind": {
      "interface": "loopback",
      "port": 3128
    },
    "intercept": {
      "ports": [80, 443],
      "from_interface": "private"
    },
    "logging": {
      "enabled": true,
      "path": "/var/log/haproxy/egress.log"
    }
  }
}
```

**Traffic Flow**:
```
Worker (178.62.33.58)
  ↓
Egress Proxy (165.22.116.193)
  ├─ Port 80, 443 → HAProxy (log) → Internet
  └─ Other ports → Direct forward → Internet

All outbound: Source IP = 165.22.116.193
```

### Example 2: Ingress Load Balancer

**Scenario**: HTTPS load balancer for backend application servers.

```json
{
  "admin": {
    "sources": ["213.48.12.11/32"]
  },

  "interfaces": {
    "public": "eth0",
    "private": "eth1"
  },

  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "allow-https-public",
        "interface": "public",
        "sources": ["0.0.0.0/0"],
        "protocol": "tcp",
        "ports": [443, 80],
        "action": "accept"
      }
    ]
  },

  "routing": {
    "enabled": false
  },

  "proxy": {
    "enabled": true,
    "mode": "ingress",
    "type": "reverse",
    "bind": {
      "interface": "public",
      "port": 443
    },
    "ssl": {
      "enabled": true,
      "cert_dir": "/etc/ssl/certs"
    },
    "backends": {
      "interface": "private",
      "servers": [
        {"ip": "10.0.1.10", "port": 8080},
        {"ip": "10.0.1.11", "port": 8080}
      ],
      "health_check": {
        "enabled": true,
        "interval": "5s",
        "timeout": "3s",
        "path": "/health"
      },
      "load_balance": "leastconn"
    },
    "logging": {
      "enabled": true,
      "path": "/var/log/haproxy/ingress.log"
    }
  }
}
```

### Example 3: Firewall Only (Database Server with Docker)

**Scenario**: PostgreSQL server with Docker, no proxying or routing.

```json
{
  "admin": {
    "sources": ["213.48.12.11/32"]
  },

  "interfaces": {
    "public": "eth0",
    "private": "eth1",
    "docker": "docker0"
  },

  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "postgres-from-app-servers",
        "interface": "private",
        "sources": ["10.0.1.0/24"],
        "protocol": "tcp",
        "ports": [5432],
        "action": "accept"
      },
      {
        "name": "allow-docker-containers",
        "interface": "docker",
        "sources": ["172.17.0.0/16"],
        "protocol": "all",
        "action": "accept"
      }
    ]
  },

  "routing": {
    "enabled": false
  },

  "proxy": {
    "enabled": false
  }
}
```

---

## Validation Rules

### Config-Level Validation

1. At least one section (`firewall`, `routing`, or `proxy`) must be enabled
2. If any section is enabled, `interfaces` must define at least one interface
3. `admin.sources` must contain at least one valid IP/CIDR
4. All interface references in rules must exist in `interfaces` section

### Firewall Validation

1. `default_policy` must be one of: `drop`, `block`, `accept`
2. Each rule must have unique `name`
3. `interface` must reference a defined interface
4. `sources` must be non-empty array of valid IPs/CIDRs
5. `protocol` must be one of: `tcp`, `udp`, `icmp`, `all`
6. `ports` only valid for `tcp` or `udp` protocols
7. `action` must be one of: `accept`, `drop`, `reject`

### Routing Validation

1. If `routing.enabled` is true, `routing.ip_forward` must be true
2. If `masquerade.enabled` is true, `masquerade.interface` must reference a defined interface
3. MASQUERADE interface must be a physical/external interface (not loopback)

### Proxy Validation

1. `mode` must be one of: `egress`, `ingress`
2. For egress mode:
   - `type` must be `transparent`
   - `intercept` is required
   - `intercept.from_interface` must reference a defined interface
   - `intercept.ports` must be non-empty array
3. For ingress mode:
   - `type` must be `reverse`
   - `backends` is required
   - `backends.servers` must be non-empty array
   - Each server must have valid `ip` and `port`

---

## Implementation Status

- [ ] Config schema struct definitions
- [ ] JSON unmarshaling with validation
- [ ] Admin section → automatic SSH rules generation
- [ ] Interface validation (check if exists on system)
- [ ] Firewall rule generation (iptables + nftables)
- [ ] Routing setup (sysctl + MASQUERADE)
- [ ] Proxy HAProxy config generation (egress transparent)
- [ ] Proxy HAProxy config generation (ingress reverse)
- [ ] PREROUTING redirect rules for transparent proxy
- [ ] Integration tests
- [ ] Documentation update in CLAUDE.md
- [ ] Example configs in `configs/` directory

---

## See Also

- [CLAUDE.md](../CLAUDE.md) - Project architecture and patterns
- [TESTING.md](TESTING.md) - Testing strategy
- [FIREWALL-CONFIG.md](FIREWALL-CONFIG.md) - Current firewall implementation (v1.x)
