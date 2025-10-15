# Production Deployment Plan

**Status**: Production deployment guide for HAProxy egress proxy infrastructure
**Last Updated**: 2025-10-14
**Target Architecture**: Transparent egress proxy with phased worker server rollout

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Phase 1: Egress Proxy Setup](#phase-1-egress-proxy-setup)
5. [Phase 2: Worker Server Partial Implementation](#phase-2-worker-server-partial-implementation)
6. [Phase 3: Full Implementation](#phase-3-full-implementation)
7. [Testing & Verification](#testing--verification)
8. [Monitoring](#monitoring)
9. [Rollback Procedures](#rollback-procedures)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)

---

## Overview

This document outlines a **phased production deployment** strategy for HAProxy-based egress proxy infrastructure. The deployment is split into distinct phases to minimize risk and allow thorough testing at each stage.

### Deployment Goals

1. **Phase 1**: Deploy and configure egress proxy server with ACL-based access control
2. **Phase 2**: Configure worker server with **partial redirect** (specific IPs only) for testing
3. **Phase 3**: Transition to full redirect after successful validation

### Key Principle: Minimal Risk

Phase 2 uses **selective traffic redirection** - only specified destination IPs route through the proxy. All other traffic continues to function normally. This allows production testing without disrupting existing services.

---

## Architecture

```
┌─────────────────┐
│  Worker Server  │
│   (Internal)    │
│                 │
│  Phase 2:       │
│  - 8.8.8.8 ────┼──┐
│  - 1.1.1.1 ────┼──┤ Redirect specific IPs only
│                 │  │
│  Other traffic: │  │
│  - example.com ─┼──┼─→ Direct (no proxy)
│  - github.com ──┼──┘
└─────────────────┘  │
                     │
                     ↓
            ┌─────────────────┐       ┌──────────────┐
            │  Egress Proxy   │──────→│   Internet   │
            │   (HAProxy)     │       │              │
            │                 │       │ Fixed Public │
            │  - ACL Control  │       │      IP      │
            │  - Logging      │       └──────────────┘
            │  - Monitoring   │
            └─────────────────┘
```

### Traffic Flow

1. **Worker Server**: Configures firewall NAT rules to redirect specific destinations
2. **Egress Proxy**: Validates source IP against ACL, forwards allowed traffic
3. **Internet**: Sees requests from egress proxy's public IP (not worker IP)

---

## Prerequisites

### Server Requirements

**Both Servers:**
- Root or sudo access
- Linux with systemd (Ubuntu 20.04+, Debian 11+, CentOS Stream 8+)
- Firewall tool available (iptables or nftables - auto-detected)
- Internet connectivity

**Egress Proxy Server:**
- HAProxy installed or installable
- Stable/static IP address (private and/or public)
- Minimum 1 CPU, 1GB RAM (2GB recommended)
- Port 8080 accessible from worker servers

**Worker Server:**
- Access to egress proxy (private or public IP)
- Firewall rules allowing outbound to proxy port 8080

### Network Requirements

- **Egress proxy** must be reachable from worker server (test with `ping`)
- **Egress proxy** needs unrestricted outbound internet access
- **Worker server** to egress proxy connectivity (port 8080)

### Information Checklist

Before starting, gather:

- [ ] Egress proxy private IP: `_____________`
- [ ] Egress proxy public IP: `_____________`
- [ ] Worker server IP: `_____________`
- [ ] Test destination IPs: `_____________` (e.g., `8.8.8.8`, `1.1.1.1`)
- [ ] HAProxy port: `_____________` (default: 8080)

---

## Phase 1: Egress Proxy Setup

### Objective

Deploy and configure the egress proxy server with:
- HAProxy transparent proxy configuration
- ACL-based access control
- Connection logging for monitoring
- proxyctl CLI for management

### Step 1.1: Install HAProxy

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y haproxy

# Verify
haproxy -v
```

**CentOS/RHEL:**
```bash
sudo dnf install -y haproxy

# Verify
haproxy -v
```

### Step 1.2: Install proxyctl

```bash
# Install latest version
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Verify installation and firewall detection
egressctl version
```

**Expected output:**
```
proxyctl version: vX.X.X
Git commit: abc123
Built: 2025-10-14
Firewall detected: nftables (or iptables)
```

### Step 1.3: Configure HAProxy

Create or update `/etc/haproxy/haproxy.cfg`:

```bash
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup
```

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# Statistics page (optional but recommended)
listen stats
    bind *:9000
    mode http
    stats enable
    stats uri /
    stats refresh 30s
    stats auth admin:changeme

# Frontend for transparent egress proxy
frontend egress_proxy
    bind 10.16.0.5:8080  # REPLACE with your egress proxy private IP
    mode tcp

    # ACL-based access control - only allow IPs in acl.lst
    tcp-request connection reject if !{ src -f /etc/haproxy/acl.lst }

    # Optional: Log connections
    log-format "%ci:%cp -> %fi:%fp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq"

    default_backend internet

# Backend - forward to actual destination
backend internet
    mode tcp
    # Transparent proxy: preserve client's original destination
    server internet 0.0.0.0:0 source 0.0.0.0 usesrc clientip
```

**Critical**: Replace `10.16.0.5` with your actual egress proxy private IP address.

### Step 1.4: Create proxyctl Configuration

```bash
# Create config directory
sudo mkdir -p /etc/proxyctl

# Create egress configuration
sudo tee /etc/proxyctl/egress.json > /dev/null <<'EOF'
{
  "_comment": "Egress Proxy Configuration - PRODUCTION",
  "mode": "egress",
  "egress": {
    "private_ip": "10.16.0.5",
    "public_ip": "203.0.113.100",
    "port": 8080,
    "acl_file": "/etc/haproxy/acl.lst",
    "auto_reload": true
  },
  "haproxy": {
    "config_file": "/etc/haproxy/haproxy.cfg",
    "binary": "/usr/sbin/haproxy",
    "socket_file": "/run/haproxy/admin.sock",
    "stats_port": 9000
  },
  "logging": {
    "level": "info",
    "format": "json",
    "output": "/var/log/egressctl.log"
  }
}
EOF
```

**Edit the file** to replace IPs with your actual values:
```bash
sudo nano /etc/proxyctl/egress.json
# Or use your preferred editor
```

### Step 1.5: Initialize ACL File

```bash
# Create HAProxy directory if needed
sudo mkdir -p /etc/haproxy

# Create empty ACL file
sudo touch /etc/haproxy/acl.lst
sudo chmod 644 /etc/haproxy/acl.lst
sudo chown root:root /etc/haproxy/acl.lst

# Verify
ls -la /etc/haproxy/acl.lst
```

### Step 1.6: Add Worker Server to ACL

```bash
# Add worker server IP (REPLACE with actual worker IP)
sudo egressctl acl add 10.0.1.100

# Add additional worker servers if needed
# sudo egressctl acl add 10.0.1.101
# sudo egressctl acl add 10.0.1.0/24  # Or entire subnet

# Verify ACL entries
sudo egressctl acl list

# View ACL file directly
cat /etc/haproxy/acl.lst
```

**Expected output:**
```
10.0.1.100
```

### Step 1.7: Validate and Start HAProxy

```bash
# Test configuration syntax
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Expected: "Configuration file is valid"

# Enable HAProxy to start on boot
sudo systemctl enable haproxy

# Start HAProxy
sudo systemctl start haproxy

# Check status
sudo systemctl status haproxy

# Should show: "active (running)"
```

### Step 1.8: Enable IP Forwarding (CRITICAL!)

Without IP forwarding, the proxy cannot forward traffic.

```bash
# Enable immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Verify
sysctl net.ipv4.ip_forward
# Should output: net.ipv4.ip_forward = 1

# Make persistent across reboots
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Or use sysctl.d (preferred)
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf
sudo sysctl -p /etc/sysctl.d/99-ip-forward.conf
```

### Step 1.9: Install Connection Logger (Recommended)

The connection logger helps monitor and verify traffic patterns.

```bash
# Install logger (auto-detects iptables or nftables)
sudo egressctl logger install

# Expected output:
# - Detected firewall type
# - Created firewall rules
# - Configured rsyslog
# - Configured logrotate
```

**Verify installation:**

For **iptables**:
```bash
sudo iptables -L EGRESS_LOG -n -v
# Should show logging chain with rules
```

For **nftables**:
```bash
sudo nft list table ip egress_monitor
# Should show egress_monitor table with rules
```

**Monitor logs:**
```bash
# Watch logs in real-time
sudo tail -f /var/log/proxyctl/egress.log

# Should see kernel log entries like:
# EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=8.8.8.8 ...
```

### Step 1.10: Verify Egress Proxy

```bash
# Check HAProxy is listening
sudo ss -tlnp | grep :8080
# Should show: LISTEN on port 8080

# Check HAProxy stats (if configured)
curl http://localhost:9000
# Should return stats page HTML

# Test ACL rejection (from unauthorized IP)
curl -v --connect-timeout 5 http://localhost:8080
# Should fail/timeout (localhost not in ACL)
```

### Step 1.11: Configure Host Firewall INPUT Filtering (CRITICAL SECURITY)

**Purpose:** Block all incoming traffic except SSH from trusted IPs and proxy port from worker servers.

**Why this is important:**
- Prevents unauthorized access to the egress proxy
- Restricts SSH access to admin IPs only
- Limits proxy port access to known worker servers
- Hardens server against attacks

**Option 1: Using proxyctl firewall config (v0.8.0+)** (Recommended - simplest and most maintainable)

<details>
<parameter name="summary"><b>Config-driven firewall management (recommended)</b></summary>

Create a firewall configuration file:

```bash
# Create firewall config for egress proxy
sudo tee /etc/proxyctl/egress-firewall.json > /dev/null <<'EOF'
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
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
        "sources": ["10.0.1.0/24"],
        "ports": [8080]
      }
    ]
  }
}
EOF
```

**Edit the file** to replace with your actual IPs:
```bash
sudo nano /etc/proxyctl/egress-firewall.json
```

**Apply firewall rules:**
```bash
# Apply INPUT filtering (auto-detects iptables or nftables)
sudo egressctl firewall apply --config /etc/proxyctl/egress-firewall.json

# Expected output:
# - Detected firewall type
# - Created backup of existing rules
# - Applied INPUT filtering rules
# - Rules persisted for reboot
```

**Verify rules:**
```bash
# Check firewall status
sudo egressctl firewall status

# View rules (iptables)
sudo iptables -L PROXYCTL_INPUT -n -v

# View rules (nftables)
sudo nft list table inet proxyctl_filter
```

**Test from allowed SSH IP (CRITICAL - do this before logging out):**
```bash
# From admin IP (should work)
ssh user@egress-proxy-ip

# From disallowed IP (should timeout/refuse)
# Try from different machine
```

**Configuration Options:**

- `input_policy`:
  - `"drop"` - Silently drop unmatched traffic (strict, recommended)
  - `"block"` - Reject with ICMP response (strict + informative)
  - `"ignore"` - Continue to next priority rules (coexistence with other firewalls)

- `allow_ssh_from`: Array of IPs/CIDRs allowed SSH access
- `allow_proxy_from`: Array of rules specifying sources and ports

**Safety Features:**
- Automatic backup before applying rules
- SSH IP detection (warns if you might lock yourself out)
- Confirmation prompt before applying
- Dry-run mode: `--dry-run` flag to preview changes

**Rollback if needed:**
```bash
# Remove all proxyctl firewall rules
sudo egressctl firewall remove

# Or restore from automatic backup
sudo egressctl firewall restore --backup /var/lib/proxyctl/firewall-backups/backup-TIMESTAMP.tar.gz
```

</details>

**Option 2: Native iptables/nftables** (Alternative - more manual control)

<details>
<summary><b>For iptables systems</b></summary>

```bash
# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific IPs only (REPLACE with your admin IPs)
sudo iptables -A INPUT -p tcp --dport 22 -s 203.0.113.50 -j ACCEPT  # Admin IP 1
sudo iptables -A INPUT -p tcp --dport 22 -s 203.0.113.51 -j ACCEPT  # Admin IP 2

# Allow proxy port from worker servers only (REPLACE with your worker IPs)
sudo iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.100 -j ACCEPT  # Worker 1
sudo iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.101 -j ACCEPT  # Worker 2
# Or allow entire worker subnet:
# sudo iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.0/24 -j ACCEPT

# Allow HAProxy stats from trusted IPs (optional)
sudo iptables -A INPUT -p tcp --dport 9000 -s 203.0.113.50 -j ACCEPT

# Log dropped packets (optional - helps with debugging)
sudo iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "INPUT-DROP: " --log-level 4

# Save rules
sudo netfilter-persistent save
# Or: sudo iptables-save > /etc/iptables/rules.v4
```

**Verify:**
```bash
# Check rules
sudo iptables -L INPUT -n -v --line-numbers

# Test from allowed SSH IP (should work)
ssh user@egress-proxy-ip

# Test from disallowed IP (should timeout/refuse)
# Try from different machine
```

</details>

<details>
<summary><b>For nftables systems</b></summary>

```bash
# Create INPUT filtering configuration
sudo tee /etc/nftables.d/input-filter.nft > /dev/null <<'EOF'
# Egress Proxy - INPUT Filtering (Server Hardening)
# Block all incoming traffic except from trusted sources

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established connections
        ct state established,related accept

        # Allow ICMP (ping) for diagnostics
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH from specific admin IPs only (REPLACE with your IPs)
        tcp dport 22 ip saddr { 203.0.113.50, 203.0.113.51 } accept

        # Allow proxy port from worker servers only (REPLACE with your IPs)
        tcp dport 8080 ip saddr { 10.0.1.100, 10.0.1.101 } accept
        # Or allow entire subnet:
        # tcp dport 8080 ip saddr 10.0.1.0/24 accept

        # Allow HAProxy stats from trusted IPs (optional)
        tcp dport 9000 ip saddr { 203.0.113.50 } accept

        # Log dropped packets (optional - helps with debugging)
        limit rate 5/minute log prefix "INPUT-DROP: "

        # Drop everything else (implicit due to policy drop)
    }
}
EOF

# Add include to main config if not present
if ! grep -q 'include "/etc/nftables.d/input-filter.nft"' /etc/nftables.conf 2>/dev/null; then
    echo 'include "/etc/nftables.d/input-filter.nft"' | sudo tee -a /etc/nftables.conf
fi

# Reload nftables
sudo systemctl reload nftables

# Verify rules loaded
sudo nft list table inet filter
```

**Verify:**
```bash
# Check rules
sudo nft list table inet filter

# Test from allowed SSH IP (should work)
ssh user@egress-proxy-ip

# Test from disallowed IP (should timeout/refuse)
# Try from different machine

# Check logs (if logging enabled)
sudo tail -f /var/log/kern.log | grep INPUT-DROP
```

</details>

**Important Notes:**
- ✅ INPUT filtering is **independent** from proxyctl's OUTPUT NAT rules - no conflicts
- ✅ proxyctl manages OUTPUT/NAT tables, INPUT filtering protects the server itself
- ⚠️ **Test from allowed IP before logging out** - wrong rules can lock you out
- ⚠️ Update IP lists when adding new workers or admin IPs

**Troubleshooting:**
```bash
# Temporarily allow all INPUT (if locked out - requires console access)
sudo iptables -P INPUT ACCEPT  # iptables
sudo nft add rule inet filter input accept  # nftables

# View dropped connections
sudo tail -f /var/log/kern.log | grep INPUT-DROP
```

### Step 1.12: Configure Cloud Firewall (If Applicable)

If running on cloud provider (AWS, DigitalOcean, GCP), add an additional layer of security:

- Allow inbound port 22 (SSH) from admin IPs only
- Allow inbound port 8080 from worker server IP(s) only
- Allow outbound to internet (all ports)
- Optionally: Allow port 9000 from trusted IPs for stats

**DigitalOcean Example:**
```bash
# Create firewall rule
doctl compute firewall create \
  --name egress-proxy-fw \
  --inbound-rules "protocol:tcp,ports:22,sources:addresses:203.0.113.50,203.0.113.51" \
  --inbound-rules "protocol:tcp,ports:8080,sources:addresses:10.0.1.100,10.0.1.101" \
  --outbound-rules "protocol:tcp,ports:all,destinations:addresses:0.0.0.0/0"
```

**Note:** Cloud firewalls + host firewalls provide defense in depth (recommended).

### Phase 1 Verification Checklist

- [ ] HAProxy running: `systemctl status haproxy`
- [ ] HAProxy listening on port 8080: `ss -tlnp | grep 8080`
- [ ] ACL file exists with worker IP: `cat /etc/haproxy/acl.lst`
- [ ] IP forwarding enabled: `sysctl net.ipv4.ip_forward` = 1
- [ ] Connection logger installed: `egressctl logger` commands work
- [ ] Logs directory created: `ls /var/log/proxyctl/`
- [ ] INPUT filtering configured: `iptables -L INPUT -n -v` or `nft list table inet filter`
- [ ] SSH accessible from allowed IPs only (test before logging out!)
- [ ] Cloud firewall configured (if applicable)

---

## Phase 2: Worker Server Partial Implementation

### Objective

Configure worker server to redirect **only specific destination IPs** through the egress proxy for testing. All other traffic continues to function normally (direct routing).

### Why Partial Implementation?

- **Low risk**: Only test traffic is affected
- **Easy rollback**: Remove rules without disrupting production
- **Validation**: Verify proxy functionality before full deployment
- **Troubleshooting**: Isolate issues with known destinations

### Step 2.1: Install proxyctl on Worker

```bash
# Install proxyctl
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Verify
egressctl version
```

### Step 2.2: Configure Partial Redirect

**Option A: Using proxyctl firewall config (v0.8.0+)** (Recommended - simplest)

Create a partial redirect configuration:

```bash
# Create partial redirect config
sudo tee /etc/proxyctl/worker-partial.json > /dev/null <<'EOF'
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
  },
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": [
      "8.8.8.8",
      "1.1.1.1"
    ]
  }
}
EOF
```

**Edit the file** to replace with your actual values:
```bash
sudo nano /etc/proxyctl/worker-partial.json
# - Replace proxy IP with your egress proxy IP
# - Replace targets with IPs you want to test
```

**Apply partial redirect:**
```bash
# Apply OUTPUT redirect rules (auto-detects iptables or nftables)
sudo egressctl firewall apply --config /etc/proxyctl/worker-partial.json

# Expected output:
# - Detected firewall type
# - Created backup of existing rules
# - Applied partial redirect rules
# - Rules persisted for reboot
```

**Verify configuration:**
```bash
# Check firewall status
sudo egressctl firewall status

# View rules (iptables)
sudo iptables -t nat -L PROXYCTL_OUTPUT -n -v

# View rules (nftables)
sudo nft list table ip proxyctl_redirect
```

**Test redirected traffic:**
```bash
# Should go through proxy
curl -v http://8.8.8.8 2>&1 | head -20

# Should be direct (not redirected)
curl -v http://example.com 2>&1 | head -20
```

**Rollback if needed:**
```bash
# Remove all redirect rules
sudo egressctl firewall remove
```

**Option B: Using shell script** (Alternative - more manual control)

### Step 2.3: Create Partial Redirect Script

This script provides granular control over which destinations route through the proxy.

```bash
sudo tee /usr/local/bin/partial-egress-redirect.sh > /dev/null <<'SCRIPT_EOF'
#!/bin/bash
# Partial Egress Proxy Redirect
# Redirects ONLY specified destination IPs through egress proxy
# All other traffic continues to work normally

set -euo pipefail

# Configuration
EGRESS_PROXY_IP="${1:-}"
PROXY_PORT="${2:-8080}"
REDIRECT_MODE="${3:-add}"
shift 3 || true
TARGET_IPS=("$@")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_usage() {
    cat <<EOF
Usage: $(basename "$0") EGRESS_PROXY_IP PROXY_PORT {add|remove} TARGET_IP1 [TARGET_IP2 ...]

Arguments:
  EGRESS_PROXY_IP  IP address of egress proxy
  PROXY_PORT       HAProxy port (usually 8080)
  REDIRECT_MODE    'add' to create rules, 'remove' to delete rules
  TARGET_IPs       Space-separated list of destination IPs/CIDRs to redirect

Examples:
  # Redirect traffic to Google DNS and Cloudflare DNS
  $(basename "$0") 10.16.0.5 8080 add 8.8.8.8 1.1.1.1

  # Redirect to subnet
  $(basename "$0") 10.16.0.5 8080 add 203.0.113.0/24

  # Remove redirects
  $(basename "$0") 10.16.0.5 8080 remove 8.8.8.8 1.1.1.1
EOF
    exit 1
}

# Validate input
if [ -z "$EGRESS_PROXY_IP" ] || [ -z "$PROXY_PORT" ] || [ ${#TARGET_IPS[@]} -eq 0 ]; then
    show_usage
fi

# Check root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: Must run as root${NC}"
   exit 1
fi

# Detect firewall
if command -v nft &> /dev/null && [ -f /etc/nftables.conf ]; then
    FIREWALL="nftables"
elif command -v iptables &> /dev/null; then
    FIREWALL="iptables"
else
    echo -e "${RED}Error: No firewall detected${NC}"
    exit 1
fi

echo "Detected firewall: $FIREWALL"
echo "Egress proxy: $EGRESS_PROXY_IP:$PROXY_PORT"
echo "Mode: $REDIRECT_MODE"
echo "Target IPs: ${TARGET_IPS[*]}"
echo ""

# iptables implementation
setup_iptables_partial() {
    iptables -t nat -N EGRESS_PARTIAL 2>/dev/null || iptables -t nat -F EGRESS_PARTIAL

    for target_ip in "${TARGET_IPS[@]}"; do
        echo "Adding redirect rule for $target_ip"
        iptables -t nat -A EGRESS_PARTIAL -d "$target_ip" -p tcp \
            -j DNAT --to-destination "${EGRESS_PROXY_IP}:${PROXY_PORT}"
    done

    iptables -t nat -D OUTPUT -j EGRESS_PARTIAL 2>/dev/null || true
    iptables -t nat -I OUTPUT 1 -j EGRESS_PARTIAL

    echo -e "${GREEN}iptables rules configured${NC}"
}

remove_iptables_partial() {
    iptables -t nat -D OUTPUT -j EGRESS_PARTIAL 2>/dev/null || true
    iptables -t nat -F EGRESS_PARTIAL 2>/dev/null || true
    iptables -t nat -X EGRESS_PARTIAL 2>/dev/null || true
    echo -e "${GREEN}iptables rules removed${NC}"
}

# nftables implementation
setup_nftables_partial() {
    mkdir -p /etc/nftables.d

    cat > /etc/nftables.d/egress-partial.nft <<EOF
# Partial Egress Proxy Redirect
table ip egress_partial {
    chain output {
        type nat hook output priority -100; policy accept;
$(for target_ip in "${TARGET_IPS[@]}"; do
    echo "        ip daddr $target_ip tcp dport 1-65535 dnat to ${EGRESS_PROXY_IP}:${PROXY_PORT}"
done)
    }
}
EOF

    if ! grep -q 'include "/etc/nftables.d/egress-partial.nft"' /etc/nftables.conf 2>/dev/null; then
        echo 'include "/etc/nftables.d/egress-partial.nft"' >> /etc/nftables.conf
    fi

    systemctl reload nftables || nft -f /etc/nftables.conf
    echo -e "${GREEN}nftables rules configured${NC}"
}

remove_nftables_partial() {
    nft delete table ip egress_partial 2>/dev/null || true
    rm -f /etc/nftables.d/egress-partial.nft
    [ -f /etc/nftables.conf ] && sed -i '/egress-partial.nft/d' /etc/nftables.conf
    systemctl reload nftables 2>/dev/null || true
    echo -e "${GREEN}nftables rules removed${NC}"
}

# Execute
if [ "$REDIRECT_MODE" == "add" ]; then
    if [ "$FIREWALL" == "iptables" ]; then
        setup_iptables_partial
    else
        setup_nftables_partial
    fi

    echo ""
    echo -e "${GREEN}Partial redirect configured!${NC}"
    echo ""
    echo "Verification:"
    if [ "$FIREWALL" == "iptables" ]; then
        echo "  sudo iptables -t nat -L EGRESS_PARTIAL -n -v"
    else
        echo "  sudo nft list table ip egress_partial"
    fi
    echo ""
    echo "Test:"
    for target_ip in "${TARGET_IPS[@]}"; do
        echo "  curl -v http://$target_ip  # Should route through proxy"
    done
    echo "  curl -v http://example.com  # Should NOT route through proxy"

elif [ "$REDIRECT_MODE" == "remove" ]; then
    if [ "$FIREWALL" == "iptables" ]; then
        remove_iptables_partial
    else
        remove_nftables_partial
    fi
    echo ""
    echo -e "${GREEN}Partial redirect removed!${NC}"
else
    echo -e "${RED}Invalid mode. Use 'add' or 'remove'${NC}"
    exit 1
fi
SCRIPT_EOF

# Make executable
sudo chmod +x /usr/local/bin/partial-egress-redirect.sh
```

### Step 2.4: Choose Test Destinations

Select destination IPs that are:
- **Safe to test**: Won't disrupt critical services
- **Easy to verify**: Simple curl/ping commands
- **Representative**: Similar protocols to production traffic

**Recommended test destinations:**
- `8.8.8.8` - Google Public DNS (good for TCP testing)
- `1.1.1.1` - Cloudflare DNS (good for TCP testing)
- `93.184.216.34` - example.com
- Or a specific API endpoint your application uses

### Step 2.5: Apply Partial Redirect (Option B - Shell Script)

```bash
# Example: Redirect only Google DNS and Cloudflare DNS
sudo /usr/local/bin/partial-egress-redirect.sh \
    10.16.0.5 \
    8080 \
    add \
    8.8.8.8 \
    1.1.1.1

# REPLACE 10.16.0.5 with your actual egress proxy IP
```

**Example: Redirect specific service subnet:**
```bash
sudo /usr/local/bin/partial-egress-redirect.sh \
    10.16.0.5 \
    8080 \
    add \
    203.0.113.0/24
```

### Step 2.6: Verify Configuration (Option B - Shell Script)

**Check rules were created:**

For **iptables**:
```bash
sudo iptables -t nat -L EGRESS_PARTIAL -n -v

# Should show:
# Chain EGRESS_PARTIAL (1 references)
# target     prot opt source     destination
# DNAT       tcp  --  0.0.0.0/0  8.8.8.8     to:10.16.0.5:8080
# DNAT       tcp  --  0.0.0.0/0  1.1.1.1     to:10.16.0.5:8080
```

For **nftables**:
```bash
sudo nft list table ip egress_partial

# Should show table with dnat rules for target IPs
```

### Step 2.7: Test Redirected Traffic

**Test redirected IP (should go through proxy):**
```bash
# Use verbose curl to see connection details
curl -v http://8.8.8.8 2>&1 | head -20

# Look for connection to egress proxy IP in output
```

**Test non-redirected traffic (should be direct):**
```bash
curl -v http://example.com 2>&1 | head -20

# Should show direct connection, NOT to proxy
```

**Verify on egress proxy:**
```bash
# On egress proxy server, watch logs
sudo tail -f /var/log/proxyctl/egress.log

# Should see connections from worker server to redirected IPs
```

### Step 2.8: Monitor and Validate

**On Worker Server:**
```bash
# Watch active connections to proxy
watch -n 2 'sudo ss -tnp | grep 10.16.0.5'

# Check NAT statistics (if using shell script)
watch -n 2 'sudo iptables -t nat -L EGRESS_PARTIAL -n -v'

# Check NAT statistics (if using v0.8.0 config)
watch -n 2 'sudo iptables -t nat -L PROXYCTL_OUTPUT -n -v'
```

**On Egress Proxy Server:**
```bash
# Watch HAProxy logs
sudo tail -f /var/log/haproxy.log

# Watch connection logs
sudo tail -f /var/log/proxyctl/egress.log

# After collecting data, analyze
sudo egressctl logger analyze

# Should show:
# - Total connections from worker
# - Destination IPs (should include your test IPs)
# - Ports used
# - Protocol distribution
```

### Step 2.9: Extended Testing

**Test various protocols and ports:**
```bash
# HTTP (if redirecting a web service)
curl -v http://8.8.8.8/

# HTTPS (requires full TLS setup)
curl -v https://example.com/  # Direct (not redirected)

# Check DNS resolution still works
nslookup google.com

# Ping should work (ICMP not affected by TCP redirects)
ping -c 4 example.com
```

**Application-level testing:**
```bash
# If you have specific applications, test them
# Example: API calls, database connections, etc.
```

### Phase 2 Verification Checklist

- [ ] Partial redirect configured (v0.8.0 config OR shell script)
- [ ] NAT rules configured:
  - v0.8.0: `iptables -t nat -L PROXYCTL_OUTPUT` or `nft list table ip proxyctl_redirect`
  - Shell script: `iptables -t nat -L EGRESS_PARTIAL` or `nft list table ip egress_partial`
- [ ] Test IP redirects through proxy: `curl -v http://8.8.8.8`
- [ ] Non-test traffic remains direct: `curl -v http://example.com`
- [ ] Egress proxy logs show worker connections: `tail /var/log/proxyctl/egress.log`
- [ ] No disruption to existing services
- [ ] HAProxy stats show active connections (if stats enabled)

---

## Phase 3: Full Implementation

### Objective

After successful Phase 2 testing, transition to full implementation where all HTTP/HTTPS/SSH traffic routes through the egress proxy.

### When to Proceed to Phase 3

Only proceed when:
- ✅ Phase 2 testing shows successful proxy routing
- ✅ No connection issues or errors in logs
- ✅ Application performance is acceptable
- ✅ Stakeholders approve full rollout

### Step 3.1: Remove Partial Redirect

**If using v0.8.0 config:**
```bash
# Remove all redirect rules
sudo egressctl firewall remove

# Verify removal
sudo egressctl firewall status
# Should show: No proxyctl firewall rules configured
```

**If using shell script:**
```bash
# Remove partial redirect rules
sudo /usr/local/bin/partial-egress-redirect.sh \
    10.16.0.5 \
    8080 \
    remove \
    8.8.8.8 \
    1.1.1.1

# Verify removal
sudo iptables -t nat -L EGRESS_PARTIAL -n -v 2>/dev/null || echo "Rules removed"
sudo nft list table ip egress_partial 2>/dev/null || echo "Rules removed"
```

### Step 3.2: Deploy Full Redirect

**Option A: Using proxyctl firewall config (v0.8.0+)** (Recommended - simplest)

Create a full redirect configuration:

```bash
# Create full redirect config
sudo tee /etc/proxyctl/worker-full.json > /dev/null <<'EOF'
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
  },
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
EOF
```

**Edit the file** to replace with your actual proxy IP:
```bash
sudo nano /etc/proxyctl/worker-full.json
```

**Apply full redirect:**
```bash
# Apply full OUTPUT redirect (auto-detects iptables or nftables)
sudo egressctl firewall apply --config /etc/proxyctl/worker-full.json

# Expected output:
# - Detected firewall type
# - Created backup of existing rules
# - Applied full redirect rules (ports 80, 443)
# - Excluded private IP ranges
# - Rules persisted for reboot
```

**Option B: Using legacy egressctl command** (Alternative)

```bash
# This will configure full redirect for HTTP/HTTPS/SSH
sudo egressctl server configure 10.16.0.5
```

**Option C: Manual configuration** (For custom requirements)

If you need custom ports or ranges, use the script manually:

```bash
# View the script to understand what it does
cat scripts.legacy.reference.only/configure-internal-server.sh

# Run with custom configuration if needed
```

### Step 3.3: Verify Full Implementation

**Check NAT rules:**

For **v0.8.0 config:**
```bash
# Check firewall status
sudo egressctl firewall status

# View rules (iptables)
sudo iptables -t nat -L PROXYCTL_OUTPUT -n -v

# View rules (nftables)
sudo nft list table ip proxyctl_redirect
```

For **legacy command:**
```bash
# Check NAT rules (iptables)
sudo iptables -t nat -L EGRESS_PROXY -n -v

# Check NAT rules (nftables)
sudo nft list table ip egress_proxy
```

**Test traffic routing:**
```bash
# HTTP should route through proxy
curl -v http://example.com

# HTTPS should route through proxy
curl -v https://google.com

# Internal IPs should remain direct (not proxied)
ping 10.0.0.1

# Check egress logs
sudo tail -50 /var/log/proxyctl/egress.log
```

### Step 3.4: Monitor Production Traffic

```bash
# On egress proxy - analyze traffic patterns
sudo egressctl logger analyze

# Watch for issues
sudo tail -f /var/log/haproxy.log | grep -i error
```

### Phase 3 Verification Checklist

- [ ] Partial redirect removed
- [ ] Full redirect configured (v0.8.0 OR legacy command)
- [ ] NAT rules verified:
  - v0.8.0: `egressctl firewall status` shows full redirect active
  - Legacy: `iptables -t nat -L EGRESS_PROXY` or `nft list table ip egress_proxy`
- [ ] All outbound HTTP/HTTPS routes through proxy: `curl -v http://example.com`
- [ ] Internal traffic (private IPs) remains direct: `ping 10.0.0.1`
- [ ] No connection errors in application logs
- [ ] HAProxy handling traffic without errors
- [ ] Connection logs show expected traffic patterns: `egressctl logger analyze`

---

## Testing & Verification

### Test Matrix

| Phase | Test | Command | Expected Result |
|-------|------|---------|----------------|
| **Phase 1** | HAProxy running | `systemctl status haproxy` | active (running) |
| **Phase 1** | Port listening | `ss -tlnp \| grep 8080` | LISTEN on 8080 |
| **Phase 1** | ACL configured | `cat /etc/haproxy/acl.lst` | Worker IP present |
| **Phase 1** | Logger active | `tail /var/log/proxyctl/egress.log` | Log entries visible |
| **Phase 1** | INPUT filtering | `iptables -L INPUT` or `nft list table inet filter` | DROP policy, allow rules present |
| **Phase 1** | SSH restricted | SSH from disallowed IP | Connection refused/timeout |
| **Phase 2** | Rules created | `iptables -t nat -L EGRESS_PARTIAL` | Rules for test IPs |
| **Phase 2** | Test IP redirects | `curl -v http://8.8.8.8` | Connection to proxy IP |
| **Phase 2** | Other IPs direct | `curl -v http://example.com` | Direct connection |
| **Phase 2** | Proxy receives | `tail /var/log/proxyctl/egress.log` | Worker connections |
| **Phase 3** | Full redirect | `curl -v http://example.com` | Connection to proxy |
| **Phase 3** | Internal direct | `ping 10.0.0.1` | Direct (no proxy) |
| **Phase 3** | No app errors | Check application logs | No connection errors |

### Performance Testing

```bash
# Latency test (before vs after proxy)
time curl -s http://example.com > /dev/null

# Throughput test
curl -o /dev/null -w "%{speed_download}\n" http://speedtest.tele2.net/10MB.zip

# Connection limits
ab -n 1000 -c 100 http://example.com/
```

### Automated Health Check Script

Create `/usr/local/bin/check-egress-health.sh`:

```bash
#!/bin/bash
# Health check script for egress proxy infrastructure

EGRESS_IP="10.16.0.5"
PROXY_PORT="8080"

echo "=== Egress Proxy Health Check ==="

# Test 1: HAProxy running
if systemctl is-active --quiet haproxy; then
    echo "✓ HAProxy running"
else
    echo "✗ HAProxy NOT running"
    exit 1
fi

# Test 2: Port listening
if ss -tlnp | grep -q ":$PROXY_PORT"; then
    echo "✓ HAProxy listening on port $PROXY_PORT"
else
    echo "✗ HAProxy NOT listening"
    exit 1
fi

# Test 3: ACL file exists
if [ -f /etc/haproxy/acl.lst ]; then
    ACL_COUNT=$(wc -l < /etc/haproxy/acl.lst)
    echo "✓ ACL file exists ($ACL_COUNT entries)"
else
    echo "✗ ACL file missing"
    exit 1
fi

# Test 4: IP forwarding enabled
if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
    echo "✓ IP forwarding enabled"
else
    echo "✗ IP forwarding DISABLED"
    exit 1
fi

# Test 5: Recent log activity
if [ -f /var/log/proxyctl/egress.log ]; then
    LOG_AGE=$(find /var/log/proxyctl/egress.log -mmin -10)
    if [ -n "$LOG_AGE" ]; then
        echo "✓ Recent log activity (last 10 minutes)"
    else
        echo "⚠ No recent log activity (could be normal if no traffic)"
    fi
else
    echo "⚠ Log file not found"
fi

echo ""
echo "=== Health Check Complete ==="
```

---

## Monitoring

### Key Metrics to Monitor

1. **HAProxy Status**
   - Service uptime
   - Connection count
   - Error rates
   - Backend status

2. **Connection Logs**
   - Source IPs
   - Destination IPs
   - Ports used
   - Traffic volume

3. **System Resources**
   - CPU usage
   - Memory usage
   - Network throughput
   - Disk I/O (logs)

### Monitoring Commands

```bash
# HAProxy statistics
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock

# Connection count
sudo ss -tn | grep :8080 | wc -l

# Analyze logs (proxyctl)
sudo egressctl logger analyze
sudo egressctl logger analyze --date 20251014

# System resources
top -bn1 | grep haproxy
free -h
df -h /var/log
```

### Log Rotation

Connection logs are automatically rotated via logrotate:

```bash
# Check logrotate config
cat /etc/logrotate.d/egress-monitor

# Manual rotation (if needed)
sudo logrotate -f /etc/logrotate.d/egress-monitor

# View rotated logs
ls -lh /var/log/proxyctl/
```

### Alerting (Optional)

Consider setting up alerts for:
- HAProxy service down
- High error rates
- ACL rejections (unauthorized access attempts)
- Disk space (logs filling up)
- High connection count (potential DDoS)

**Example: Email alert on HAProxy failure**
```bash
# In /etc/systemd/system/haproxy.service.d/alert.conf
[Service]
OnFailure=alert-email@%n.service
```

---

## Rollback Procedures

### Rollback Phase 3 (Full Implementation)

**Quick rollback to Phase 2 (partial):**

For **v0.8.0 config:**
```bash
# Remove full redirect
sudo egressctl firewall remove

# Re-apply partial redirect
sudo egressctl firewall apply --config /etc/proxyctl/worker-partial.json
```

For **legacy command or shell script:**
```bash
# Remove full redirect
sudo egressctl server remove

# Re-apply partial redirect (shell script)
sudo /usr/local/bin/partial-egress-redirect.sh \
    10.16.0.5 8080 add 8.8.8.8 1.1.1.1
```

**Complete rollback (remove all redirects):**

For **v0.8.0 config:**
```bash
# Remove all firewall rules
sudo egressctl firewall remove

# Verify removal
sudo egressctl firewall status
# Should show: No proxyctl firewall rules configured
```

For **legacy command:**
```bash
# Remove server configuration
sudo egressctl server remove

# Verify removal (iptables)
sudo iptables -t nat -L EGRESS_PROXY 2>/dev/null
# Should show: "No chain/target/match by that name"

# Verify removal (nftables)
sudo nft list table ip egress_proxy 2>/dev/null
# Should show error: table does not exist
```

### Rollback Phase 2 (Partial Implementation)

For **v0.8.0 config:**
```bash
# Remove partial redirect
sudo egressctl firewall remove

# Verify removal
sudo egressctl firewall status
# Should show: No proxyctl firewall rules configured

# Test direct connectivity restored
curl -v http://8.8.8.8
# Should connect directly, not through proxy
```

For **shell script:**
```bash
# Remove partial redirect
sudo /usr/local/bin/partial-egress-redirect.sh \
    10.16.0.5 8080 remove 8.8.8.8 1.1.1.1

# Verify removal
sudo iptables -t nat -L EGRESS_PARTIAL 2>/dev/null || echo "Removed"
sudo nft list table ip egress_partial 2>/dev/null || echo "Removed"

# Test direct connectivity restored
curl -v http://8.8.8.8
# Should connect directly, not through proxy
```

### Rollback Phase 1 (Egress Proxy)

**Stop services (preserve config):**
```bash
# Stop HAProxy
sudo systemctl stop haproxy
sudo systemctl disable haproxy

# Remove logger
sudo egressctl logger remove
```

**Complete cleanup:**
```bash
# Stop HAProxy
sudo systemctl stop haproxy
sudo systemctl disable haproxy

# Remove logger
sudo egressctl logger remove

# Remove configurations
sudo rm -rf /etc/proxyctl
sudo rm -f /etc/haproxy/acl.lst

# Restore original HAProxy config (if you have backup)
sudo cp /etc/haproxy/haproxy.cfg.backup /etc/haproxy/haproxy.cfg

# Uninstall proxyctl (optional)
sudo rm /usr/local/bin/proxyctl
sudo rm /usr/local/bin/egressctl
sudo rm /usr/local/bin/ingressctl
```

### Emergency Rollback (Worker Server)

If all traffic is broken:

```bash
# EMERGENCY: Flush ALL NAT rules
sudo iptables -t nat -F

# Or for nftables
sudo nft flush ruleset

# This removes ALL NAT redirects, restoring normal connectivity
# WARNING: This affects all NAT rules, not just egress proxy rules
```

---

## Troubleshooting

### Issue: Worker Cannot Connect to Proxy

**Symptoms:**
- Connection timeout when accessing redirected IPs
- `curl` hangs or times out

**Diagnosis:**
```bash
# Test network connectivity
ping 10.16.0.5  # Egress proxy IP

# Test port connectivity
nc -zv 10.16.0.5 8080
telnet 10.16.0.5 8080

# Check worker IP in ACL (on egress)
sudo egressctl acl list | grep <WORKER_IP>
```

**Solutions:**
1. **Check ACL**: Ensure worker IP is in `/etc/haproxy/acl.lst`
2. **Check firewall**: Cloud/host firewall must allow port 8080
3. **Check HAProxy**: Verify HAProxy is running: `systemctl status haproxy`
4. **Check routing**: Ensure network path exists between servers

### Issue: Some Destinations Work, Others Don't

**Symptoms:**
- Some IPs route through proxy, others fail
- Intermittent connectivity

**Diagnosis:**
```bash
# Check NAT rules
sudo iptables -t nat -L -n -v --line-numbers
sudo nft list ruleset

# Check for conflicting rules
sudo iptables -t nat -L OUTPUT -n -v
```

**Solutions:**
1. **Rule order**: NAT rules are processed in order. Check for conflicts.
2. **Private IP exclusions**: Ensure private IP ranges are excluded
3. **Proxy exclusion**: Ensure proxy IP itself is excluded (avoid routing loop)

### Issue: Connection Refused by Proxy

**Symptoms:**
- Connection actively refused (not timeout)
- HAProxy logs show connection rejected

**Diagnosis:**
```bash
# Check HAProxy logs
sudo tail -100 /var/log/haproxy.log | grep -i reject

# Check ACL entries
cat /etc/haproxy/acl.lst
```

**Solutions:**
1. **ACL mismatch**: Worker IP not in ACL or format incorrect
2. **ACL reload**: After adding IPs, reload HAProxy: `sudo egressctl acl reload`
3. **Source IP**: Verify source IP seen by HAProxy matches expected IP

### Issue: IP Forwarding Not Working

**Symptoms:**
- Connections reach proxy but don't reach internet
- HAProxy forwards but no response

**Diagnosis:**
```bash
# Check IP forwarding
sysctl net.ipv4.ip_forward
# Should be: net.ipv4.ip_forward = 1

# Check HAProxy backend status
echo "show stat" | sudo socat stdio /run/haproxy/admin.sock | grep internet
```

**Solutions:**
1. **Enable IP forwarding**: `sudo sysctl -w net.ipv4.ip_forward=1`
2. **Make persistent**: Add to `/etc/sysctl.conf` or `/etc/sysctl.d/99-ip-forward.conf`
3. **Restart**: May need to restart HAProxy after enabling

### Issue: Logger Not Capturing Traffic

**Symptoms:**
- `/var/log/proxyctl/egress.log` is empty or not updating
- `egressctl logger analyze` shows no data

**Diagnosis:**
```bash
# Check firewall rules exist
sudo iptables -L EGRESS_LOG -n -v  # iptables
sudo nft list table ip egress_monitor  # nftables

# Check rsyslog config
cat /etc/rsyslog.d/10-egress-monitor.conf

# Check rsyslog status
sudo systemctl status rsyslog

# Check kernel logging
sudo dmesg | grep EGRESS_MONITOR
```

**Solutions:**
1. **Reinstall logger**: `sudo egressctl logger remove && sudo egressctl logger install`
2. **Restart rsyslog**: `sudo systemctl restart rsyslog`
3. **Check permissions**: Log directory must be writable by syslog user
4. **Check disk space**: `df -h /var/log`

### Issue: Performance Degradation

**Symptoms:**
- Slow response times
- Increased latency
- Connection timeouts under load

**Diagnosis:**
```bash
# Check HAProxy stats
curl http://localhost:9000  # HAProxy stats page

# Check system resources
top
free -h
iostat -x 1 5

# Check connection count
sudo ss -tn | grep :8080 | wc -l

# Check HAProxy connection limits
grep maxconn /etc/haproxy/haproxy.cfg
```

**Solutions:**
1. **Increase HAProxy limits**: Adjust `maxconn` in haproxy.cfg
2. **Optimize timeouts**: Tune `timeout connect/client/server`
3. **Scale resources**: Increase CPU/memory for egress proxy
4. **Connection pooling**: Configure applications to reuse connections

### Issue: NAT Rules Not Persisting After Reboot

**Symptoms:**
- After reboot, traffic no longer routes through proxy
- Rules missing from iptables/nftables

**Solutions:**

**For iptables:**
```bash
# Install persistence tool
sudo apt-get install iptables-persistent

# Save current rules
sudo netfilter-persistent save

# Enable service
sudo systemctl enable netfilter-persistent
```

**For nftables:**
```bash
# Enable nftables service
sudo systemctl enable nftables

# Ensure config is included
cat /etc/nftables.conf
# Should include: /etc/nftables.d/ files
```

**For proxyctl logger (iptables):**
The logger automatically creates a systemd service for persistence. Verify:
```bash
sudo systemctl status egressctl-logger
sudo systemctl enable egressctl-logger
```

### Issue: Logs Filling Disk

**Symptoms:**
- Disk space alert
- `/var/log/proxyctl/` consuming lots of space

**Diagnosis:**
```bash
# Check disk usage
du -sh /var/log/proxyctl/
ls -lh /var/log/proxyctl/

# Check logrotate config
cat /etc/logrotate.d/egress-monitor
```

**Solutions:**
1. **Manual rotation**: `sudo logrotate -f /etc/logrotate.d/egress-monitor`
2. **Adjust retention**: Edit `/etc/logrotate.d/egress-monitor`, change `rotate 14` to fewer days
3. **Compress old logs**: Existing logs can be gzipped manually
4. **Delete old logs**: `sudo rm /var/log/proxyctl/egress.log-*.gz`

---

## Security Considerations

### Access Control

1. **ACL Management**
   - Only authorized worker IPs in ACL
   - Use CIDR ranges carefully (avoid overly broad ranges)
   - Regular ACL audits: `sudo egressctl acl list`
   - Remove decommissioned servers promptly

2. **Firewall Rules**
   - Cloud/host firewall: Restrict port 8080 to known worker IPs
   - Consider VPN or private networking instead of public IP access
   - Monitor unauthorized access attempts

3. **HAProxy Admin Socket**
   - Admin socket `/run/haproxy/admin.sock` requires root access
   - Do not expose over network
   - Use for local monitoring only

### Monitoring & Auditing

1. **Connection Logs**
   - All connections logged with source/destination
   - Regular log reviews for anomalies
   - Archive logs for compliance (if required)

2. **Failed Connections**
   - Monitor HAProxy logs for rejected connections
   - Alert on unusual rejection patterns (potential attack)

3. **ACL Changes**
   - Log all ACL modifications
   - Consider git tracking for `/etc/haproxy/acl.lst`
   - Implement change approval process

### Data Privacy

1. **Log Retention**
   - Connection logs contain IP addresses and ports
   - Comply with data retention policies
   - Secure log files: `chmod 640 /var/log/proxyctl/egress.log`

2. **Log Access**
   - Restrict log access to authorized personnel
   - Consider log aggregation/SIEM integration

### Incident Response

1. **Compromise Detection**
   - Unusual traffic patterns
   - Connections from unexpected sources
   - High volume to specific destinations

2. **Response Procedures**
   - Block compromised worker: `sudo egressctl acl remove <IP>`
   - Investigate connection logs: `sudo egressctl logger analyze`
   - Review HAProxy logs for attack indicators

3. **DDoS Mitigation**
   - HAProxy can be targeted by compromised workers
   - Monitor connection rates
   - Implement rate limiting (HAProxy stick-tables)

### Updates & Patching

1. **Regular Updates**
   - Keep HAProxy updated: `sudo apt-get update && sudo apt-get upgrade haproxy`
   - Keep proxyctl updated: Check GitHub releases
   - Keep OS updated

2. **Testing Updates**
   - Test HAProxy updates in staging first
   - Verify config compatibility: `haproxy -c -f /etc/haproxy/haproxy.cfg`
   - Have rollback plan

---

## Appendix: Configuration Reference

### Example HAProxy Configuration

See Step 1.3 for complete configuration.

Key sections:
- **Frontend**: Receives connections from workers, validates ACL
- **Backend**: Forwards to internet with source IP preservation
- **Stats**: Optional monitoring interface

### Example proxyctl Configuration

See Step 1.4 for complete configuration.

Key fields:
- `egress.acl_file`: Path to HAProxy ACL file
- `egress.auto_reload`: Automatically reload HAProxy on ACL changes
- `haproxy.config_file`: Path to HAProxy config

### Firewall Rule Reference

**iptables (monitoring):**
```bash
# Chain: EGRESS_LOG
# Purpose: Log outbound connections to public IPs
# Created by: egressctl logger install
```

**iptables (redirect):**
```bash
# Chain: EGRESS_PROXY (full) or EGRESS_PARTIAL (partial)
# Purpose: Redirect traffic to egress proxy
# Created by: egressctl server configure or partial-egress-redirect.sh
```

**nftables (monitoring):**
```bash
# Table: ip egress_monitor
# Purpose: Log outbound connections to public IPs
# Created by: egressctl logger install
```

**nftables (redirect):**
```bash
# Table: ip egress_proxy (full) or ip egress_partial (partial)
# Purpose: Redirect traffic to egress proxy
# Created by: egressctl server configure or partial-egress-redirect.sh
```

---

## Appendix: Quick Reference Commands

### Egress Proxy Management
```bash
# ACL operations
sudo egressctl acl add <IP>
sudo egressctl acl remove <IP>
sudo egressctl acl list
sudo egressctl acl reload

# Logger operations
sudo egressctl logger install
sudo egressctl logger remove
sudo egressctl logger analyze
sudo egressctl logger analyze --date 20251014

# Firewall operations (v0.8.0+)
sudo egressctl firewall apply --config /etc/proxyctl/egress-firewall.json
sudo egressctl firewall remove
sudo egressctl firewall status
sudo egressctl firewall restore --backup /var/lib/proxyctl/firewall-backups/backup-TIMESTAMP.tar.gz

# HAProxy operations
sudo systemctl start haproxy
sudo systemctl stop haproxy
sudo systemctl reload haproxy
sudo systemctl status haproxy
```

### Worker Server Management

**v0.8.0+ (config-driven - recommended):**
```bash
# Partial redirect
sudo egressctl firewall apply --config /etc/proxyctl/worker-partial.json
sudo egressctl firewall remove
sudo egressctl firewall status

# Full redirect
sudo egressctl firewall apply --config /etc/proxyctl/worker-full.json
sudo egressctl firewall remove
sudo egressctl firewall status
```

**Legacy commands:**
```bash
# Partial redirect (shell script)
sudo /usr/local/bin/partial-egress-redirect.sh <PROXY_IP> 8080 add <TEST_IPS>
sudo /usr/local/bin/partial-egress-redirect.sh <PROXY_IP> 8080 remove <TEST_IPS>

# Full redirect (legacy command)
sudo egressctl server configure <PROXY_IP>
sudo egressctl server remove
```

### Verification Commands
```bash
# Check HAProxy
sudo systemctl status haproxy
sudo ss -tlnp | grep 8080

# Check ACL
cat /etc/haproxy/acl.lst

# Check firewall status (v0.8.0+)
sudo egressctl firewall status

# Check NAT rules (iptables)
sudo iptables -t nat -L -n -v
sudo iptables -L PROXYCTL_INPUT -n -v  # INPUT filtering (v0.8.0)

# Check NAT rules (nftables)
sudo nft list ruleset
sudo nft list table inet proxyctl_filter  # INPUT filtering (v0.8.0)
sudo nft list table ip proxyctl_redirect  # OUTPUT redirect (v0.8.0)

# Check IP forwarding
sysctl net.ipv4.ip_forward

# Check logs
sudo tail -f /var/log/proxyctl/egress.log
sudo tail -f /var/log/haproxy.log
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-10-14 | Initial production deployment plan |
| 1.1 | 2025-10-15 | Added v0.8.0 firewall configuration examples (config-driven firewall management) |

---

## Support & Feedback

- **Issues**: [GitHub Issues](https://github.com/carmendata/proxyctl/issues)
- **Documentation**: [GitHub Wiki](https://github.com/carmendata/proxyctl/wiki)
- **Releases**: [GitHub Releases](https://github.com/carmendata/proxyctl/releases)

---

**END OF DOCUMENT**
