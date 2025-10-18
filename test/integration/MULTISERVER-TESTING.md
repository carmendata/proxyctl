# Multi-Server Integration Testing

## Overview

Multi-server integration tests validate **real-world production topology** where traffic flows from internal servers through an egress proxy to the internet.

## Topology

```
┌─────────────────────────┐         ┌─────────────────────────┐
│  Internal Server        │         │  Egress Proxy Server    │
│  (Worker/Client)        │         │  (HAProxy)              │
│                         │         │                         │
│  - OUTPUT redirect      │────────>│  - INPUT filtering      │
│    to proxy             │  :8080  │  - HAProxy transparent  │
│  - Routes HTTP/HTTPS    │         │    proxy               │
│    through proxy        │         │  - MASQUERADE outbound  │
│                         │         │                         │
│  Region: lon1           │         │  Region: lon1           │
│  Private IP: 10.x.x.x   │         │  Private IP: 10.y.y.y   │
└─────────────────────────┘         └─────────────────────────┘
```

## Test Scenarios

### Scenario 1: Same Region Connectivity
**Goal**: Verify basic egress proxy functionality with 2 servers in same region

**Setup**:
- Both servers in `lon1` region
- Egress proxy configured with INPUT filtering (allow from internal server only)
- Internal server configured with OUTPUT redirect (partial mode)

**Tests**:
- Internal server can reach proxy on port 8080
- HTTP/HTTPS traffic flows through proxy
- HAProxy logs show connections from internal server
- External IPs cannot reach proxy (blocked by INPUT filter)
- DNS queries work through proxy

### Scenario 2: Reboot Persistence
**Goal**: Verify firewall rules and configuration survive droplet reboots

**Setup**:
- Apply v2 configuration to both servers
- Reboot both droplets using `doctl compute droplet-action reboot`

**Tests**:
- After reboot, iptables/nftables rules still present
- After reboot, HAProxy service auto-started
- After reboot, traffic still flows through proxy
- After reboot, sysctl settings preserved (IP forwarding)

### Scenario 3: Cross-Region with Firewall
**Goal**: Verify cross-region connectivity and firewall rules with public IPs

**Setup**:
- Egress proxy in `lon1` region
- Internal server in `nyc1` region (different VPC)
- Use public IPs for communication (not private networking)

**Tests**:
- Cross-region connectivity works
- Firewall rules work with public IPs
- Latency measured but acceptable
- Traffic still proxied correctly

### Scenario 4: Full vs Partial Redirect
**Goal**: Verify both redirect modes work correctly

**Setup**:
- Start with partial redirect (specific IPs: 8.8.8.8, 1.1.1.1)
- Switch to full redirect (all HTTP/HTTPS)

**Tests**:
- Partial mode: Only specified IPs redirected
- Partial mode: Other IPs bypass proxy
- Full mode: All HTTP/HTTPS traffic redirected
- Mode switching works without service interruption

## Configuration Files

### Egress Proxy Configuration (`egress-proxy-v2.yaml`)

```yaml
interfaces:
  public: eth0
  private: eth1

admin:
  sources:
    - 0.0.0.0/0  # Allow SSH from anywhere (for testing)
  ports: [22]

routing:
  enabled: true
  ip_forward: true
  masquerade:
    enabled: true
    interface: public

proxy:
  enabled: true
  mode: egress
  type: transparent
  bind:
    interface: private
    port: 8080
  intercept:
    from_interface: private
    ports: [80, 443]
  logging:
    enabled: true
    format: json

firewall:
  enabled: true
  default_policy: drop
  rules:
    - name: allow-ssh-admin
      action: accept
      sources: ["INTERNAL_SERVER_IP"]  # Replaced by test script
      ports: [22]
    - name: allow-proxy-from-internal
      action: accept
      sources: ["INTERNAL_SERVER_IP"]
      ports: [8080]
```

### Internal Server Configuration - Partial Mode (`internal-server-v2-partial.yaml`)

```yaml
interfaces:
  public: eth0

proxy:
  ip: EGRESS_PROXY_IP  # Replaced by test script
  port: 8080

redirect:
  enabled: true
  type: partial
  targets:
    - 8.8.8.8           # Google DNS
    - 1.1.1.1           # Cloudflare DNS
    - 142.250.0.0/16    # Google IP range
```

### Internal Server Configuration - Full Mode (`internal-server-v2-full.yaml`)

```yaml
interfaces:
  public: eth0

proxy:
  ip: EGRESS_PROXY_IP  # Replaced by test script
  port: 8080

redirect:
  enabled: true
  type: full  # Redirect ALL HTTP/HTTPS traffic
```

## Test Flow

### 1. Setup Phase
```bash
# Create egress-proxy droplet (lon1)
create_droplet "egress-proxy" "lon1"

# Create internal-server droplet (lon1)
create_droplet "internal-server" "lon1"

# Wait for both to be ready
wait_for_ssh egress-proxy
wait_for_ssh internal-server

# Copy proxyctl binary to both
upload_binary egress-proxy
upload_binary internal-server

# Generate config files with actual IPs substituted
generate_config egress-proxy $INTERNAL_SERVER_IP
generate_config internal-server $EGRESS_PROXY_IP
```

### 2. Configuration Phase
```bash
# Configure egress-proxy
ssh egress-proxy "proxyctl firewall apply --config egress-proxy-v2.yaml"

# Verify egress-proxy configuration
ssh egress-proxy "systemctl status haproxy"
ssh egress-proxy "iptables -L -n -v" # or "nft list ruleset"
ssh egress-proxy "sysctl net.ipv4.ip_forward"

# Configure internal-server (partial mode first)
ssh internal-server "proxyctl firewall apply --config internal-server-v2-partial.yaml"

# Verify internal-server configuration
ssh internal-server "iptables -t nat -L -n -v" # or "nft list ruleset"
```

### 3. Connectivity Tests
```bash
# Test: DNS query through proxy
ssh internal-server "dig @8.8.8.8 google.com"

# Test: HTTP request through proxy
ssh internal-server "curl --connect-timeout 5 http://8.8.8.8"

# Test: Check HAProxy logs on egress-proxy
ssh egress-proxy "journalctl -u haproxy -n 50 | grep $INTERNAL_SERVER_IP"

# Test: Verify external connections blocked
# (from test runner, not internal-server)
curl --connect-timeout 5 http://$EGRESS_PROXY_IP:8080  # Should fail/timeout
```

### 4. Reboot Persistence Tests
```bash
# Reboot egress-proxy
doctl compute droplet-action reboot $EGRESS_PROXY_ID --wait

# Reboot internal-server
doctl compute droplet-action reboot $INTERNAL_SERVER_ID --wait

# Wait for SSH to come back
wait_for_ssh egress-proxy
wait_for_ssh internal-server

# Verify rules still present
ssh egress-proxy "iptables -L -n -v | grep PROXYCTL"
ssh internal-server "iptables -t nat -L -n -v | grep PROXYCTL"

# Verify HAProxy auto-started
ssh egress-proxy "systemctl is-active haproxy"

# Re-run connectivity tests
ssh internal-server "curl --connect-timeout 5 http://8.8.8.8"
```

### 5. Full Redirect Tests
```bash
# Switch to full redirect mode
ssh internal-server "proxyctl firewall apply --config internal-server-v2-full.yaml"

# Test: General HTTP traffic
ssh internal-server "curl -I http://www.google.com"

# Test: HTTPS traffic
ssh internal-server "curl -I https://www.cloudflare.com"

# Verify all traffic goes through proxy
ssh egress-proxy "journalctl -u haproxy -n 100 | grep -c $INTERNAL_SERVER_IP"
```

### 6. Cleanup Phase
```bash
# Remove configurations
ssh egress-proxy "proxyctl firewall remove"
ssh internal-server "proxyctl firewall remove"

# Destroy droplets
doctl compute droplet delete $EGRESS_PROXY_ID $INTERNAL_SERVER_ID --force

# Cleanup SSH keys
doctl compute ssh-key delete $SSH_KEY_ID --force
```

## Limitations

### What We CAN Test
- ✅ Multi-server topology (internal → proxy → internet)
- ✅ Actual traffic flow through HAProxy
- ✅ Firewall INPUT filtering on proxy server
- ✅ Firewall OUTPUT redirect on internal server
- ✅ Reboot persistence of all components
- ✅ HAProxy logging and connection tracking
- ✅ Cross-region connectivity

### What We CANNOT Fully Test
- ❌ Complex VPC topologies (DigitalOcean droplet limitations)
- ❌ High-traffic load testing (cost prohibitive)
- ❌ Long-running stability tests (cost/time prohibitive)
- ❌ Private networking with VPC peering (requires VPC setup)

## Cost Considerations

**Per Multi-Server Test Run**:
- 2 droplets × $0.007/hour = $0.014/hour
- Typical test duration: 30-45 minutes
- Cost per run: ~$0.01-0.02

**Safety Features**:
- Automatic cleanup after tests
- Tagged droplets for easy identification
- Safety timeout (auto-destroy after 2 hours)
- Manual cleanup script available

## Test Execution

```bash
# Run multi-server test suite
cd test/integration
./run-integration-tests.sh --suite v2-multiserver --os ubuntu-22-04

# Run with reboot persistence testing
TEST_REBOOT_PERSISTENCE=true ./run-integration-tests.sh --suite v2-multiserver --os ubuntu-22-04

# Run cross-region test
TEST_CROSS_REGION=true ./run-integration-tests.sh --suite v2-multiserver --os ubuntu-22-04

# Keep droplets alive for debugging
./run-integration-tests.sh --suite v2-multiserver --os ubuntu-22-04 --keep-alive
```

## Implementation Files

- `test-suite-v2-multiserver.sh` - Main test suite script
- `configs/egress-proxy-v2.yaml.template` - Egress proxy config template
- `configs/internal-server-v2-partial.yaml.template` - Internal server partial redirect template
- `configs/internal-server-v2-full.yaml.template` - Internal server full redirect template

## Success Criteria

A successful multi-server test run validates:

1. **Configuration Application**: Both servers configured without errors
2. **Traffic Flow**: HTTP/HTTPS requests reach internet through proxy
3. **Security**: External connections to proxy are blocked
4. **Logging**: HAProxy logs show all proxied connections
5. **Persistence**: Configuration survives reboots
6. **Mode Switching**: Can switch between partial and full redirect modes
7. **Cleanup**: All resources cleaned up automatically

## Future Enhancements

- [ ] VPC peering tests (private networking between regions)
- [ ] Load testing with multiple internal servers
- [ ] Failover testing (proxy goes down, internal server behavior)
- [ ] SSL/TLS interception testing
- [ ] ACL-based filtering on egress proxy
- [ ] Connection logger integration
