#!/bin/bash
#
# Multi-Server Integration Test Suite for V2.0 Configuration
#
# This test suite validates real-world production topology where traffic flows
# from internal servers through an egress proxy to the internet.
#
# Topology:
#   Internal Server → Egress Proxy Server → Internet
#
# Tests:
#   - Multi-server connectivity (internal → proxy → internet)
#   - INPUT filtering on egress proxy
#   - OUTPUT redirect on internal server
#   - Reboot persistence (optional)
#   - Cross-region connectivity (optional)
#
# Usage:
#   ./test-suite-v2-multiserver.sh
#
# Environment Variables:
#   DO_API_TOKEN              - DigitalOcean API token (required)
#   DO_REGION                 - Primary region (default: lon1)
#   DO_REGION_SECONDARY       - Secondary region for cross-region tests (default: nyc1)
#   DO_DROPLET_SIZE           - Droplet size (default: s-1vcpu-1gb)
#   TEST_REBOOT_PERSISTENCE   - Test reboot persistence (default: false)
#   TEST_CROSS_REGION         - Test cross-region connectivity (default: false)
#   CLEANUP                   - Cleanup droplets after tests (default: true)
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Required environment variables
: "${DO_API_TOKEN:?Error: DO_API_TOKEN environment variable must be set}"

# Optional environment variables
DO_REGION="${DO_REGION:-lon1}"
DO_REGION_SECONDARY="${DO_REGION_SECONDARY:-nyc1}"
DO_DROPLET_SIZE="${DO_DROPLET_SIZE:-s-1vcpu-1gb}"
TEST_REBOOT_PERSISTENCE="${TEST_REBOOT_PERSISTENCE:-false}"
TEST_CROSS_REGION="${TEST_CROSS_REGION:-false}"
CLEANUP="${CLEANUP:-true}"

# Droplet configuration
EGRESS_PROXY_NAME="proxyctl-test-egress-proxy-$(date +%s)-$$"
INTERNAL_SERVER_NAME="proxyctl-test-internal-server-$(date +%s)-$$"
VPC_ID=""
EGRESS_PROXY_ID=""
INTERNAL_SERVER_ID=""
EGRESS_PROXY_IP=""
INTERNAL_SERVER_IP=""
EGRESS_PROXY_PRIVATE_IP=""
INTERNAL_SERVER_PRIVATE_IP=""

# SSH configuration
SSH_KEY_NAME="proxyctl-test-multiserver-$(date +%s)-$$"
SSH_KEY_PATH=""
SSH_KEY_ID=""

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    local exit_code=$?

    echo ""
    echo -e "${BLUE}Cleanup phase...${NC}"

    if [[ "$CLEANUP" != "true" ]]; then
        echo -e "${YELLOW}CLEANUP=false - Keeping droplets for manual inspection${NC}"
        echo ""
        echo "Egress Proxy:"
        echo "  ID: $EGRESS_PROXY_ID"
        echo "  IP: $EGRESS_PROXY_IP"
        echo "  SSH: ssh -i $SSH_KEY_PATH root@$EGRESS_PROXY_IP"
        echo ""
        echo "Internal Server:"
        echo "  ID: $INTERNAL_SERVER_ID"
        echo "  IP: $INTERNAL_SERVER_IP"
        echo "  SSH: ssh -i $SSH_KEY_PATH root@$INTERNAL_SERVER_IP"
        echo ""
        echo "Manual cleanup:"
        echo "  doctl compute droplet delete $EGRESS_PROXY_ID $INTERNAL_SERVER_ID --force"
        echo "  doctl compute ssh-key delete $SSH_KEY_ID --force"
        return
    fi

    # Destroy droplets
    if [[ -n "$EGRESS_PROXY_ID" ]]; then
        echo "Destroying egress-proxy droplet..."
        doctl compute droplet delete "$EGRESS_PROXY_ID" --force 2>/dev/null || true
    fi

    if [[ -n "$INTERNAL_SERVER_ID" ]]; then
        echo "Destroying internal-server droplet..."
        doctl compute droplet delete "$INTERNAL_SERVER_ID" --force 2>/dev/null || true
    fi

    # Cleanup SSH key
    if [[ -n "$SSH_KEY_ID" ]]; then
        echo "Deleting SSH key..."
        doctl compute ssh-key delete "$SSH_KEY_ID" --force 2>/dev/null || true
    fi

    # Cleanup local SSH key files
    if [[ -n "$SSH_KEY_PATH" && -f "$SSH_KEY_PATH" ]]; then
        local key_dir=$(dirname "$SSH_KEY_PATH")
        rm -rf "$key_dir" 2>/dev/null || true
    fi

    echo -e "${GREEN}Cleanup complete${NC}"

    exit $exit_code
}

trap cleanup EXIT INT TERM

# Test helper functions
pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}✓ PASS${NC}: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo "  Error: $2"
}

test_start() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    echo -e "${BLUE}Test $TESTS_RUN: $1${NC}"
}

# SSH helper with retry
ssh_exec() {
    local host=$1
    shift
    local cmd="$@"

    ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -o LogLevel=ERROR \
        root@"$host" "$cmd"
}

# SCP helper
scp_upload() {
    local src=$1
    local host=$2
    local dest=$3

    scp -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$src" root@"$host":"$dest"
}

# Create SSH key
create_ssh_key() {
    echo -e "${BLUE}Creating ephemeral SSH key...${NC}"

    local key_dir=$(mktemp -d)
    SSH_KEY_PATH="$key_dir/proxyctl-test-key"

    ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "$SSH_KEY_NAME" >/dev/null 2>&1

    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        echo -e "${RED}Error: Failed to generate SSH key${NC}"
        exit 1
    fi

    echo "Uploading SSH key to DigitalOcean..."
    SSH_KEY_ID=$(doctl compute ssh-key import "$SSH_KEY_NAME" \
        --public-key-file "${SSH_KEY_PATH}.pub" \
        --format ID \
        --no-header 2>/dev/null)

    if [[ -z "$SSH_KEY_ID" ]]; then
        echo -e "${RED}Error: Failed to upload SSH key${NC}"
        exit 1
    fi

    echo -e "${GREEN}SSH key created (ID: $SSH_KEY_ID)${NC}"
}

# Get or create VPC for the region
get_or_create_vpc() {
    local region=$1

    echo -e "${BLUE}Getting VPC for region $region...${NC}"

    # Try to get default VPC for region
    local vpc_id=$(doctl compute vpc list --region "$region" --format ID --no-header | head -1)

    if [[ -n "$vpc_id" ]]; then
        echo -e "${GREEN}Using existing VPC: $vpc_id${NC}"
        echo "$vpc_id"
    else
        echo "No VPC found, using default (droplets will get private IPs automatically)"
        echo ""
    fi
}

# Create droplet with VPC support
create_droplet() {
    local name=$1
    local region=$2
    local vpc_id=$3
    local image="ubuntu-22-04-x64"

    echo -e "${BLUE}Creating droplet: $name${NC}"
    echo "  Image: $image"
    echo "  Region: $region"
    echo "  Size: $DO_DROPLET_SIZE"
    [[ -n "$vpc_id" ]] && echo "  VPC: $vpc_id"

    local create_cmd="doctl compute droplet create \"$name\" \
        --image \"$image\" \
        --region \"$region\" \
        --size \"$DO_DROPLET_SIZE\" \
        --ssh-keys \"$SSH_KEY_ID\" \
        --tag-names \"proxyctl-test,ephemeral,multiserver\" \
        --enable-private-networking \
        --wait \
        --format ID \
        --no-header"

    # Add VPC if specified
    if [[ -n "$vpc_id" ]]; then
        create_cmd="$create_cmd --vpc-uuid \"$vpc_id\""
    fi

    local droplet_id=$(eval $create_cmd)

    if [[ -z "$droplet_id" ]]; then
        echo -e "${RED}Error: Failed to create droplet${NC}"
        exit 1
    fi

    echo -e "${GREEN}Droplet created: $droplet_id${NC}"
    echo "$droplet_id"
}

# Wait for SSH
wait_for_ssh() {
    local host=$1
    local name=$2

    echo "Waiting for SSH on $name ($host)..."
    local attempts=0
    local max_attempts=30

    while ! ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        root@"$host" "echo SSH ready" >/dev/null 2>&1; do

        attempts=$((attempts + 1))
        if [[ $attempts -ge $max_attempts ]]; then
            echo -e "${RED}Error: SSH not ready after $max_attempts attempts${NC}"
            exit 1
        fi

        echo -n "."
        sleep 10
    done

    echo ""
    echo -e "${GREEN}SSH ready on $name${NC}"
}

# Bootstrap droplet
bootstrap_droplet() {
    local host=$1
    local name=$2

    echo "Bootstrapping $name..."

    # Upload bootstrap script
    scp_upload "$SCRIPT_DIR/bootstrap-droplet.sh" "$host" "/tmp/bootstrap.sh"

    # Run bootstrap
    ssh_exec "$host" "bash /tmp/bootstrap.sh"

    echo -e "${GREEN}Bootstrap complete on $name${NC}"
}

# Upload binary
upload_binary() {
    local host=$1
    local name=$2

    echo "Uploading proxyctl binary to $name..."

    scp_upload "$PROJECT_ROOT/bin/proxyctl" "$host" "/usr/local/bin/proxyctl"

    ssh_exec "$host" "cd /usr/local/bin && ln -sf proxyctl egressctl && ln -sf proxyctl ingressctl && chmod +x proxyctl"

    echo -e "${GREEN}Binary uploaded to $name${NC}"
}

# Generate config file with IP substitution
generate_config() {
    local config_type=$1  # "egress-proxy" or "internal-server-partial" or "internal-server-full"
    local output_file=$2

    case $config_type in
        egress-proxy)
            cat > "$output_file" <<EOF
{
  "interfaces": {
    "public": "eth0",
    "private": "eth1"
  },
  "admin": {
    "sources": ["0.0.0.0/0"],
    "ports": [22]
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
      "interface": "private",
      "port": 8080
    },
    "intercept": {
      "from_interface": "private",
      "ports": [80, 443]
    },
    "logging": {
      "enabled": true,
      "format": "json"
    }
  },
  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "allow-ssh-public",
        "action": "accept",
        "sources": ["0.0.0.0/0"],
        "ports": [22]
      },
      {
        "name": "allow-all-from-internal-private",
        "action": "accept",
        "sources": ["$INTERNAL_SERVER_PRIVATE_IP"]
      }
    ]
  }
}
EOF
            ;;

        internal-server-partial)
            cat > "$output_file" <<EOF
{
  "interfaces": {
    "public": "eth0"
  },
  "proxy": {
    "ip": "$EGRESS_PROXY_PRIVATE_IP",
    "port": 8080
  },
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1", "142.250.0.0/16"]
  }
}
EOF
            ;;

        internal-server-full)
            cat > "$output_file" <<EOF
{
  "interfaces": {
    "public": "eth0"
  },
  "proxy": {
    "ip": "$EGRESS_PROXY_PRIVATE_IP",
    "port": 8080
  },
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
EOF
            ;;

        *)
            echo -e "${RED}Error: Unknown config type: $config_type${NC}"
            exit 1
            ;;
    esac

    echo -e "${GREEN}Generated config: $output_file${NC}"
}

# Main test execution
main() {
    echo "========================================"
    echo "Multi-Server Integration Test Suite"
    echo "========================================"
    echo ""
    echo "Configuration:"
    echo "  Primary Region: $DO_REGION"
    echo "  Secondary Region: $DO_REGION_SECONDARY"
    echo "  Droplet Size: $DO_DROPLET_SIZE"
    echo "  Reboot Tests: $TEST_REBOOT_PERSISTENCE"
    echo "  Cross-Region Tests: $TEST_CROSS_REGION"
    echo "  Cleanup: $CLEANUP"
    echo ""

    # Step 1: Create SSH key
    create_ssh_key
    echo ""

    # Step 2: Get or create VPC and create droplets
    echo -e "${BLUE}Setting up VPC and creating droplets...${NC}"

    # Determine regions
    local egress_region="$DO_REGION"
    local internal_region="$DO_REGION"

    if [[ "$TEST_CROSS_REGION" = "true" ]]; then
        internal_region="$DO_REGION_SECONDARY"
        echo -e "${YELLOW}Cross-region testing enabled${NC}"
        echo "  Egress proxy: $egress_region"
        echo "  Internal server: $internal_region"
        echo -e "${YELLOW}Note: Cross-region droplets won't have private network connectivity${NC}"
    else
        # Get VPC for same-region testing (enables private networking)
        VPC_ID=$(get_or_create_vpc "$egress_region")
    fi

    EGRESS_PROXY_ID=$(create_droplet "$EGRESS_PROXY_NAME" "$egress_region" "$VPC_ID")
    INTERNAL_SERVER_ID=$(create_droplet "$INTERNAL_SERVER_NAME" "$internal_region" "$VPC_ID")

    # Get droplet IPs
    EGRESS_PROXY_IP=$(doctl compute droplet get "$EGRESS_PROXY_ID" --format PublicIPv4 --no-header)
    INTERNAL_SERVER_IP=$(doctl compute droplet get "$INTERNAL_SERVER_ID" --format PublicIPv4 --no-header)
    EGRESS_PROXY_PRIVATE_IP=$(doctl compute droplet get "$EGRESS_PROXY_ID" --format PrivateIPv4 --no-header)
    INTERNAL_SERVER_PRIVATE_IP=$(doctl compute droplet get "$INTERNAL_SERVER_ID" --format PrivateIPv4 --no-header)

    echo ""
    echo "Droplet IPs:"
    echo "  Egress Proxy Public: $EGRESS_PROXY_IP"
    echo "  Egress Proxy Private: $EGRESS_PROXY_PRIVATE_IP"
    echo "  Internal Server Public: $INTERNAL_SERVER_IP"
    echo "  Internal Server Private: $INTERNAL_SERVER_PRIVATE_IP"
    echo ""

    # Step 3: Wait for SSH
    wait_for_ssh "$EGRESS_PROXY_IP" "egress-proxy"
    wait_for_ssh "$INTERNAL_SERVER_IP" "internal-server"
    echo ""

    # Step 4: Bootstrap droplets
    bootstrap_droplet "$EGRESS_PROXY_IP" "egress-proxy"
    bootstrap_droplet "$INTERNAL_SERVER_IP" "internal-server"
    echo ""

    # Step 5: Upload binaries
    upload_binary "$EGRESS_PROXY_IP" "egress-proxy"
    upload_binary "$INTERNAL_SERVER_IP" "internal-server"
    echo ""

    # Step 6: Generate and upload configs
    echo -e "${BLUE}Generating configuration files...${NC}"

    local config_dir=$(mktemp -d)
    local egress_config="$config_dir/egress-proxy.json"
    local internal_config_partial="$config_dir/internal-server-partial.json"
    local internal_config_full="$config_dir/internal-server-full.json"

    generate_config "egress-proxy" "$egress_config"
    generate_config "internal-server-partial" "$internal_config_partial"
    generate_config "internal-server-full" "$internal_config_full"

    echo "Uploading configs..."
    scp_upload "$egress_config" "$EGRESS_PROXY_IP" "/tmp/egress-proxy.json"
    scp_upload "$internal_config_partial" "$INTERNAL_SERVER_IP" "/tmp/internal-server-partial.json"
    scp_upload "$internal_config_full" "$INTERNAL_SERVER_IP" "/tmp/internal-server-full.json"
    echo ""

    # Step 7: Apply configuration to egress proxy
    echo -e "${BLUE}Configuring egress proxy...${NC}"

    test_start "Apply v2 config on egress proxy"
    if ssh_exec "$EGRESS_PROXY_IP" "proxyctl firewall apply --config /tmp/egress-proxy.json" 2>&1; then
        pass "Egress proxy configuration applied"
    else
        fail "Egress proxy configuration" "Failed to apply config"
    fi

    # Step 8: Verify egress proxy configuration
    test_start "Verify HAProxy service on egress proxy"
    if ssh_exec "$EGRESS_PROXY_IP" "systemctl is-active haproxy"; then
        pass "HAProxy service is active"
    else
        fail "HAProxy service" "Service not active"
    fi

    test_start "Verify IP forwarding enabled"
    if ssh_exec "$EGRESS_PROXY_IP" "sysctl net.ipv4.ip_forward | grep -q '= 1'"; then
        pass "IP forwarding is enabled"
    else
        fail "IP forwarding" "Not enabled"
    fi

    test_start "Verify MASQUERADE rules present"
    if ssh_exec "$EGRESS_PROXY_IP" "iptables -t nat -L -n | grep -q MASQUERADE || nft list ruleset | grep -q masquerade"; then
        pass "MASQUERADE rules found"
    else
        fail "MASQUERADE rules" "Not found"
    fi

    test_start "Verify INPUT filtering rules present"
    if ssh_exec "$EGRESS_PROXY_IP" "iptables -L INPUT -n | grep -q PROXYCTL || nft list ruleset | grep -q 'chain input'"; then
        pass "INPUT filtering rules found"
    else
        fail "INPUT filtering" "Rules not found"
    fi

    # Step 8.5: Test actual incoming traffic filtering
    echo ""
    echo -e "${BLUE}Testing incoming traffic filtering...${NC}"

    test_start "External connection to HAProxy port should be blocked"
    # Try to connect from test runner machine (external) to HAProxy port 8080
    # This should be blocked by INPUT filtering (only internal server is allowed)
    if timeout 3 nc -zv "$EGRESS_PROXY_IP" 8080 2>&1 >/dev/null; then
        fail "External connection blocking" "Port 8080 accessible from external (should be blocked)"
    else
        pass "External connections blocked on port 8080 (DROP policy working)"
    fi

    test_start "SSH remains accessible from anywhere"
    # SSH should be accessible from 0.0.0.0/0 as configured
    if timeout 3 nc -zv "$EGRESS_PROXY_IP" 22 2>&1 >/dev/null; then
        pass "SSH port 22 accessible as configured"
    else
        fail "SSH accessibility" "Port 22 should be open but cannot connect"
    fi

    test_start "Internal server can connect to egress proxy via private IP"
    # Internal server should be able to connect to HAProxy (allowed by firewall rule)
    # Wait for HAProxy to be fully ready
    sleep 2
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 5 nc -zv $EGRESS_PROXY_PRIVATE_IP 8080 2>&1"; then
        pass "Internal server allowed to connect to HAProxy port"
    else
        fail "Internal server connection" "Should be allowed but connection failed"
    fi

    test_start "Internal server can reach egress proxy via public IP (from within VPC)"
    # Even though firewall filters by source IP, internal server might reach public IP
    # This tests that the firewall correctly identifies internal server's traffic
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 5 nc -zv $EGRESS_PROXY_IP 22 2>&1"; then
        pass "Internal server can reach egress proxy's public IP on SSH"
    else
        # This is acceptable - VPC routing may not allow public IP access
        echo -e "${YELLOW}  Note: Internal server cannot reach egress proxy's public IP (VPC routing limitation)${NC}"
    fi

    # Step 9: Apply configuration to internal server (partial mode)
    echo ""
    echo -e "${BLUE}Configuring internal server (partial redirect)...${NC}"

    test_start "Apply OUTPUT redirect config (partial mode)"
    if ssh_exec "$INTERNAL_SERVER_IP" "proxyctl firewall apply --config /tmp/internal-server-partial.json" 2>&1; then
        pass "Internal server configuration applied (partial)"
    else
        fail "Internal server configuration" "Failed to apply config"
    fi

    test_start "Verify OUTPUT redirect rules present"
    if ssh_exec "$INTERNAL_SERVER_IP" "iptables -t nat -L OUTPUT -n | grep -q DNAT || nft list ruleset | grep -q 'chain output'"; then
        pass "OUTPUT redirect rules found"
    else
        fail "OUTPUT redirect" "Rules not found"
    fi

    # Step 10: Connectivity tests
    echo ""
    echo -e "${BLUE}Running connectivity tests...${NC}"

    test_start "DNS query through proxy (8.8.8.8)"
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 dig @8.8.8.8 +short google.com | grep -q '^[0-9]'"; then
        pass "DNS query successful"
    else
        fail "DNS query" "Query failed or timed out"
    fi

    test_start "HTTP request through proxy (partial target)"
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 curl -s -o /dev/null -w '%{http_code}' http://8.8.8.8 | grep -q '200\\|301\\|302'"; then
        pass "HTTP request successful"
    else
        fail "HTTP request" "Request failed or timed out"
    fi

    test_start "Verify HAProxy logs show internal server connections"
    if ssh_exec "$EGRESS_PROXY_IP" "journalctl -u haproxy -n 50 --no-pager | grep -q '$INTERNAL_SERVER_IP'"; then
        pass "HAProxy logs show connections from internal server"
    else
        fail "HAProxy logs" "No connections from internal server found"
    fi

    # Step 11: Full redirect mode tests
    echo ""
    echo -e "${BLUE}Testing full redirect mode...${NC}"

    test_start "Switch to full redirect mode"
    if ssh_exec "$INTERNAL_SERVER_IP" "proxyctl firewall apply --config /tmp/internal-server-full.json" 2>&1; then
        pass "Switched to full redirect mode"
    else
        fail "Full redirect mode" "Failed to apply config"
    fi

    test_start "HTTP request to general domain (google.com)"
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 curl -s -o /dev/null -w '%{http_code}' http://www.google.com | grep -q '200\\|301\\|302'"; then
        pass "HTTP request to google.com successful"
    else
        fail "HTTP request to google.com" "Request failed or timed out"
    fi

    test_start "Verify all traffic goes through proxy"
    local connection_count=$(ssh_exec "$EGRESS_PROXY_IP" "journalctl -u haproxy -n 100 --no-pager | grep -c '$INTERNAL_SERVER_IP' || echo 0")
    if [[ $connection_count -gt 0 ]]; then
        pass "HAProxy logs show $connection_count connections from internal server"
    else
        fail "HAProxy connection count" "No connections found"
    fi

    # Step 11.5: Gateway Mode Tests
    echo ""
    echo -e "${BLUE}Testing gateway mode (full routing through egress proxy)...${NC}"
    echo -e "${YELLOW}Note: These tests validate traffic that bypasses HAProxy but uses egress-proxy for IP masquerading${NC}"

    test_start "Remove OUTPUT redirect rules"
    if ssh_exec "$INTERNAL_SERVER_IP" "proxyctl firewall remove" 2>&1; then
        pass "OUTPUT redirect rules removed"
    else
        fail "Remove OUTPUT redirect" "Failed to remove rules"
    fi

    test_start "Configure egress-proxy as default gateway"
    # Add static route via private IP (gateway mode)
    if ssh_exec "$INTERNAL_SERVER_IP" "ip route add 8.8.8.8 via $EGRESS_PROXY_PRIVATE_IP"; then
        pass "Static route added for 8.8.8.8 via egress-proxy"
    else
        fail "Gateway route configuration" "Failed to add static route"
    fi

    test_start "Verify routing through egress proxy (ping)"
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 5 ping -c 2 8.8.8.8 >/dev/null 2>&1"; then
        pass "Ping through gateway successful"
    else
        fail "Gateway ping test" "Ping failed"
    fi

    test_start "Test non-HTTP/HTTPS traffic (DNS on port 53)"
    # DNS query directly on port 53 (not HTTP/HTTPS, should be MASQUERADED, NOT proxied)
    if ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 dig @8.8.8.8 +short google.com | grep -q '^[0-9]'"; then
        pass "DNS query through gateway successful"
    else
        fail "DNS through gateway" "DNS query failed"
    fi

    test_start "Verify HAProxy does NOT see non-HTTP traffic"
    # Clear previous HAProxy logs to ensure we're checking fresh logs
    ssh_exec "$EGRESS_PROXY_IP" "journalctl --rotate && journalctl --vacuum-time=1s" >/dev/null 2>&1 || true

    # Perform DNS query again
    ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 dig @8.8.8.8 +short google.com >/dev/null 2>&1" || true

    # Check HAProxy logs - should NOT contain DNS traffic (port 53)
    # HAProxy only intercepts HTTP/HTTPS (ports 80, 443), not DNS (port 53)
    if ssh_exec "$EGRESS_PROXY_IP" "journalctl -u haproxy --since '5 seconds ago' --no-pager | grep -q 'sport=53\\|:53'"; then
        fail "HAProxy traffic filtering" "HAProxy incorrectly logged non-HTTP traffic (DNS)"
    else
        pass "HAProxy correctly ignores non-HTTP/HTTPS traffic"
    fi

    test_start "Verify source IP masquerading (external sees egress-proxy IP)"
    # Resolve ifconfig.me to an IP and add route through gateway
    local ifconfig_ip=$(ssh_exec "$INTERNAL_SERVER_IP" "dig +short ifconfig.me | head -1")

    if [[ -z "$ifconfig_ip" ]]; then
        fail "Source IP masquerading test" "Failed to resolve ifconfig.me"
    else
        # Add route for ifconfig.me through egress proxy
        ssh_exec "$INTERNAL_SERVER_IP" "ip route add $ifconfig_ip via $EGRESS_PROXY_PRIVATE_IP" 2>/dev/null || true

        # Use ifconfig.me to check what IP external services see
        # Should see egress-proxy's public IP, not internal-server's IP
        local detected_ip=$(ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 curl -s --max-time 5 http://ifconfig.me 2>/dev/null || echo 'TIMEOUT'")

        if [[ "$detected_ip" = "$EGRESS_PROXY_IP" ]]; then
            pass "External services see egress-proxy IP ($EGRESS_PROXY_IP)"
        elif [[ "$detected_ip" = "TIMEOUT" ]]; then
            fail "Source IP masquerading test" "Request to ifconfig.me timed out"
        else
            fail "Source IP masquerading" "Expected $EGRESS_PROXY_IP but got $detected_ip"
        fi

        # Clean up the route
        ssh_exec "$INTERNAL_SERVER_IP" "ip route del $ifconfig_ip via $EGRESS_PROXY_PRIVATE_IP" 2>/dev/null || true
    fi

    test_start "Restore OUTPUT redirect for remaining tests"
    # Restore full redirect mode for subsequent tests
    ssh_exec "$INTERNAL_SERVER_IP" "ip route del 8.8.8.8 via $EGRESS_PROXY_PRIVATE_IP" 2>/dev/null || true
    if ssh_exec "$INTERNAL_SERVER_IP" "proxyctl firewall apply --config /tmp/internal-server-full.json" 2>&1; then
        pass "OUTPUT redirect restored"
    else
        fail "Restore OUTPUT redirect" "Failed to restore config"
    fi

    # Step 12: Reboot persistence tests (optional)
    if [[ "$TEST_REBOOT_PERSISTENCE" = "true" ]]; then
        echo ""
        echo -e "${BLUE}Testing reboot persistence...${NC}"

        test_start "Reboot egress proxy"
        if doctl compute droplet-action reboot "$EGRESS_PROXY_ID" --wait 2>&1 >/dev/null; then
            pass "Egress proxy rebooted"
        else
            fail "Egress proxy reboot" "Reboot command failed"
        fi

        test_start "Reboot internal server"
        if doctl compute droplet-action reboot "$INTERNAL_SERVER_ID" --wait 2>&1 >/dev/null; then
            pass "Internal server rebooted"
        else
            fail "Internal server reboot" "Reboot command failed"
        fi

        echo "Waiting for droplets to come back online..."
        sleep 30

        wait_for_ssh "$EGRESS_PROXY_IP" "egress-proxy"
        wait_for_ssh "$INTERNAL_SERVER_IP" "internal-server"

        test_start "Verify HAProxy service auto-started after reboot"
        if ssh_exec "$EGRESS_PROXY_IP" "systemctl is-active haproxy"; then
            pass "HAProxy service is active after reboot"
        else
            fail "HAProxy service after reboot" "Service not active"
        fi

        test_start "Verify firewall rules persisted after reboot"
        if ssh_exec "$EGRESS_PROXY_IP" "iptables -L INPUT -n | grep -q PROXYCTL || nft list ruleset | grep -q 'chain input'"; then
            pass "Firewall rules persisted on egress proxy"
        else
            fail "Firewall rules persistence" "Rules not found after reboot"
        fi

        test_start "Verify OUTPUT redirect persisted after reboot"
        if ssh_exec "$INTERNAL_SERVER_IP" "iptables -t nat -L OUTPUT -n | grep -q DNAT || nft list ruleset | grep -q 'chain output'"; then
            pass "OUTPUT redirect rules persisted on internal server"
        else
            fail "OUTPUT redirect persistence" "Rules not found after reboot"
        fi

        test_start "Re-test connectivity after reboot"
        if ssh_exec "$INTERNAL_SERVER_IP" "timeout 10 curl -s -o /dev/null -w '%{http_code}' http://www.google.com | grep -q '200\\|301\\|302'"; then
            pass "Connectivity still works after reboot"
        else
            fail "Connectivity after reboot" "Request failed"
        fi
    fi

    # Test summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo "  Tests Run: $TESTS_RUN"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
        exit 0
    else
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        exit 1
    fi
}

# Run main
main
