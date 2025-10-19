# Logger Configuration Examples

This directory contains example configurations demonstrating the logger's capabilities for comprehensive traffic monitoring.

## Configuration Files

### logger-default.json.example
**Default behavior** - monitors only public IPs with TCP and UDP protocols.

```json
{
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress.log"
  }
}
```

**Monitors:**
- Public IP addresses only
- TCP and UDP traffic
- OUTPUT chain

**Use case:** Standard egress monitoring for internet-bound traffic.

---

### logger-private-lan.json.example
**Private LAN monitoring** - includes private RFC1918 ranges.

```json
{
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-private.log",
    "include_private": true,
    "protocols": ["tcp", "udp"]
  }
}
```

**Monitors:**
- Public IPs + private IPs (10.x, 172.16.x, 192.168.x, 169.254.x)
- TCP and UDP traffic
- OUTPUT chain

**Use case:** Track both internet and internal network connections.

---

### logger-comprehensive.json.example
**Comprehensive monitoring** - captures all traffic including loopback and multicast.

```json
{
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-all.log",
    "chains": ["OUTPUT"],
    "protocols": ["tcp", "udp", "icmp"],
    "include_private": true,
    "include_loopback": true,
    "include_multicast": true
  }
}
```

**Monitors:**
- All IP addresses (public, private, loopback, multicast)
- TCP, UDP, and ICMP traffic
- OUTPUT chain

**Use case:** Complete traffic visibility for security auditing or troubleshooting.

---

### logger-whitelist.json.example
**Whitelist mode** - monitors only specific IPs/ranges.

```json
{
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-db-servers.log",
    "include_ranges": [
      "10.0.1.100",
      "10.0.1.101",
      "10.0.2.0/24"
    ],
    "protocols": ["tcp"]
  }
}
```

**Monitors:**
- ONLY the specified IP addresses/ranges
- TCP traffic only
- OUTPUT chain

**Use case:** Monitor connections to specific database servers or critical infrastructure.

---

### logger-exclude-ranges.json.example
**Exclude specific IPs** - monitors public traffic except DNS servers.

```json
{
  "logger": {
    "enabled": true,
    "output": "/var/log/proxyctl/egress-filtered.log",
    "exclude_ranges": [
      "8.8.8.8",
      "1.1.1.1",
      "208.67.222.0/24"
    ],
    "protocols": ["tcp", "udp"]
  }
}
```

**Monitors:**
- Public IPs except excluded ranges
- TCP and UDP traffic
- OUTPUT chain

**Use case:** Reduce log noise by excluding high-volume DNS or CDN traffic.

---

## Configuration Reference

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | false | Enable/disable logger |
| `output` | string | `/var/log/proxyctl/egress.log` | Log file path |
| `chains` | array[string] | `["OUTPUT"]` | Netfilter chains to monitor (`OUTPUT`, `INPUT`, `FORWARD`) |
| `protocols` | array[string] | `["tcp", "udp"]` | Protocols to log (`tcp`, `udp`, `icmp`, `all`) |
| `include_private` | boolean | false | Include private IPs (10.x, 172.16.x, 192.168.x, 169.254.x) |
| `include_loopback` | boolean | false | Include loopback (127.x) |
| `include_multicast` | boolean | false | Include multicast (224.x, 240.x) |
| `include_ranges` | array[string] | `[]` | Whitelist specific IPs/CIDRs (empty = normal mode) |
| `exclude_ranges` | array[string] | `[]` | Exclude specific IPs/CIDRs from monitoring |

### Filtering Logic

The logger uses a **two-tier filtering system**:

1. **Base Set Construction:**
   - Start with public IPs
   - Add private IPs if `include_private: true`
   - Add loopback if `include_loopback: true`
   - Add multicast if `include_multicast: true`

2. **Range Filtering:**
   - **Whitelist mode** (if `include_ranges` is non-empty):
     - Monitor ONLY IPs in `include_ranges`
     - Apply `exclude_ranges` as exceptions
   - **Normal mode** (if `include_ranges` is empty):
     - Monitor base set
     - Subtract `exclude_ranges`

### Examples

**Monitor only private LAN traffic:**
```json
{
  "logger": {
    "enabled": true,
    "include_private": true,
    "exclude_ranges": ["0.0.0.0/0"]  // Exclude all public IPs
  }
}
```

**Monitor everything except loopback:**
```json
{
  "logger": {
    "enabled": true,
    "include_private": true,
    "include_multicast": true
    // include_loopback: false (default)
  }
}
```

**Monitor specific database ports:**
```json
{
  "logger": {
    "enabled": true,
    "include_ranges": ["10.0.1.0/24"],
    "protocols": ["tcp"]
  }
}
```

## Testing Configurations

To test a configuration without applying it:

```bash
# Copy example to working config
cp logger-private-lan.json.example egress.json

# Validate config syntax
egressctl status --config egress.json

# Dry-run (if implementing --dry-run flag)
egressctl logger install --config egress.json --dry-run
```

## Installation

1. **Copy the desired example:**
   ```bash
   cp logger-private-lan.json.example egress.json
   ```

2. **Edit if needed** (customize IPs, ports, etc.)

3. **Install to one of these locations:**
   - Current directory: `./egress.json`
   - User config: `~/.config/proxyctl/egress.json`
   - System config: `/etc/proxyctl/egress.json`

4. **Or use the `--config` flag:**
   ```bash
   sudo egressctl logger install --config /path/to/egress.json
   ```
