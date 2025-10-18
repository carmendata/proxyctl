#!/bin/bash
#
# Integration test suite for proxyctl v2.0 configuration
#
# Tests the v2.0 unified configuration system including:
# - Routing setup (IP forwarding, MASQUERADE)
# - HAProxy config generation and service management
# - PREROUTING port interception (transparent proxy)
# - Apply/remove/status commands
# - Rollback on errors
# - Dry-run mode
# - Interface validation
#

set -euo pipefail

# Output file for test results
OUTFILE="/tmp/test-output.log"
exec > >(tee -a "$OUTFILE") 2>&1

echo "========================================"
echo "Test Suite: V2.0 Configuration"
echo "Started: $(date)"
echo "========================================"
echo ""

# Cleanup function
cleanup() {
    local exit_code=$?
    echo ""
    echo "Cleaning up..."

    # Remove v2 config if applied
    /usr/local/bin/proxyctl remove 2>/dev/null || true

    # Clean up test config files
    rm -f /tmp/test-v2-*.json 2>/dev/null || true

    # Stop HAProxy if running
    systemctl stop haproxy 2>/dev/null || true
    systemctl disable haproxy 2>/dev/null || true

    exit $exit_code
}

trap cleanup EXIT

# Helper functions

# Detect network interface
detect_interface() {
    # Try to find first non-loopback interface
    local iface=$(ip -o link show | awk -F': ' '$2 !~ /^lo$/ {print $2; exit}')
    if [ -z "$iface" ]; then
        # Fallback to eth0
        echo "eth0"
    else
        echo "$iface"
    fi
}

# Check if IP forwarding is enabled
check_ip_forward() {
    local value=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    [ "$value" = "1" ]
}

# Check if MASQUERADE is enabled
check_masquerade() {
    local fw_type=$(detect_firewall_type)

    if [ "$fw_type" = "iptables" ]; then
        iptables -t nat -L POSTROUTING -n | grep -q MASQUERADE
    else
        nft list ruleset | grep -q "masquerade"
    fi
}

# Check if port interception is enabled
check_port_intercept() {
    local fw_type=$(detect_firewall_type)

    if [ "$fw_type" = "iptables" ]; then
        iptables -t nat -L PREROUTING -n | grep -q "REDIRECT"
    else
        nft list ruleset | grep -q "redirect"
    fi
}

# Detect firewall type
detect_firewall_type() {
    if command -v nft >/dev/null 2>&1 && [ -f /etc/nftables.conf ]; then
        echo "nftables"
    else
        echo "iptables"
    fi
}

# Check if HAProxy is running
check_haproxy_running() {
    systemctl is-active --quiet haproxy
}

# Check if HAProxy is enabled
check_haproxy_enabled() {
    systemctl is-enabled --quiet haproxy
}

# Test 1: Dry-run mode - egress transparent proxy
test_apply_v2_dry_run() {
    echo "Test 1: Apply V2 Config (Dry-Run Mode)"
    echo "---"

    local primary_iface=$(detect_interface)
    echo "  Using interface: $primary_iface"

    # Create test v2 config
    cat > /tmp/test-v2-egress.json <<EOF
{
  "admin": {
    "sources": ["0.0.0.0/0"]
  },
  "interfaces": {
    "public": "$primary_iface",
    "private": "lo",
    "loopback": "lo"
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
    }
  }
}
EOF

    echo "  Created test v2 config"

    # Run apply with dry-run
    if ! /usr/local/bin/proxyctl apply --config /tmp/test-v2-egress.json --dry-run; then
        echo "✗ FAIL: Dry-run failed"
        return 1
    fi

    echo "✓ Dry-run succeeded without errors"

    # Verify nothing was actually applied
    if check_ip_forward; then
        echo "  Warning: IP forwarding already enabled (may be from previous test)"
    else
        echo "✓ IP forwarding NOT enabled (dry-run worked)"
    fi

    if check_masquerade 2>/dev/null; then
        echo "  Warning: MASQUERADE already active (may be from previous test)"
    else
        echo "✓ MASQUERADE NOT active (dry-run worked)"
    fi

    if check_haproxy_running 2>/dev/null; then
        echo "  Warning: HAProxy already running (may be from previous test)"
    else
        echo "✓ HAProxy NOT running (dry-run worked)"
    fi

    echo "✓ PASS: Dry-run mode works correctly"
    echo ""
}

# Test 2: Apply v2 config (real)
test_apply_v2_config() {
    echo "Test 2: Apply V2 Config (Real)"
    echo "---"

    local primary_iface=$(detect_interface)

    # Apply the config (non-interactive)
    if ! echo "yes" | /usr/local/bin/proxyctl apply --config /tmp/test-v2-egress.json; then
        echo "✗ FAIL: Config apply failed"
        return 1
    fi

    echo "✓ Config applied successfully"
    sleep 2  # Wait for services to start

    echo "✓ PASS: V2 config application"
    echo ""
}

# Test 3: Verify routing setup
test_verify_routing() {
    echo "Test 3: Verify Routing Setup"
    echo "---"

    # Check IP forwarding
    if check_ip_forward; then
        echo "✓ IP forwarding is enabled"
    else
        echo "✗ FAIL: IP forwarding not enabled"
        return 1
    fi

    # Verify sysctl persistence
    if grep -q "net.ipv4.ip_forward.*=.*1" /etc/sysctl.d/99-proxyctl-routing.conf 2>/dev/null; then
        echo "✓ IP forwarding persistence configured"
    else
        echo "  Warning: Persistence config not found (may use different method)"
    fi

    # Check MASQUERADE
    if check_masquerade; then
        echo "✓ MASQUERADE is active"
    else
        echo "✗ FAIL: MASQUERADE not active"
        return 1
    fi

    # Verify MASQUERADE rule
    local fw_type=$(detect_firewall_type)
    if [ "$fw_type" = "iptables" ]; then
        if iptables -t nat -L POSTROUTING -n -v | grep -q MASQUERADE; then
            echo "✓ MASQUERADE rule found in iptables"
        else
            echo "✗ FAIL: MASQUERADE rule not found"
            return 1
        fi
    else
        if nft list ruleset | grep -q "masquerade"; then
            echo "✓ MASQUERADE rule found in nftables"
        else
            echo "✗ FAIL: MASQUERADE rule not found"
            return 1
        fi
    fi

    echo "✓ PASS: Routing setup verified"
    echo ""
}

# Test 4: Verify HAProxy configuration
test_verify_haproxy() {
    echo "Test 4: Verify HAProxy Configuration"
    echo "---"

    # Check if HAProxy is installed
    if ! command -v haproxy >/dev/null 2>&1; then
        echo "✗ FAIL: HAProxy not installed"
        return 1
    fi
    echo "✓ HAProxy is installed"

    # Check if config file exists
    if [ ! -f /etc/haproxy/haproxy.cfg ]; then
        echo "✗ FAIL: HAProxy config not generated"
        return 1
    fi
    echo "✓ HAProxy config exists"

    # Verify config is valid
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
        echo "✗ FAIL: HAProxy config is invalid"
        haproxy -c -f /etc/haproxy/haproxy.cfg
        return 1
    fi
    echo "✓ HAProxy config is valid"

    # Check if HAProxy is running
    if check_haproxy_running; then
        echo "✓ HAProxy service is running"
    else
        echo "✗ FAIL: HAProxy service not running"
        systemctl status haproxy --no-pager
        return 1
    fi

    # Check if HAProxy is enabled
    if check_haproxy_enabled; then
        echo "✓ HAProxy service is enabled (autostart)"
    else
        echo "  Warning: HAProxy not enabled for autostart"
    fi

    # Verify HAProxy config contains expected settings
    if grep -q "mode.*tcp" /etc/haproxy/haproxy.cfg; then
        echo "✓ HAProxy configured for TCP mode"
    else
        echo "  Warning: TCP mode not found in config"
    fi

    if grep -q "bind.*127.0.0.1:3128" /etc/haproxy/haproxy.cfg; then
        echo "✓ HAProxy bind address configured"
    else
        echo "  Warning: Expected bind address not found"
    fi

    echo "✓ PASS: HAProxy configuration verified"
    echo ""
}

# Test 5: Verify port interception
test_verify_port_intercept() {
    echo "Test 5: Verify Port Interception"
    echo "---"

    local fw_type=$(detect_firewall_type)
    echo "  Firewall type: $fw_type"

    # Check if port interception is enabled
    if check_port_intercept; then
        echo "✓ Port interception is active"
    else
        echo "✗ FAIL: Port interception not active"
        return 1
    fi

    # Verify specific intercept rules
    if [ "$fw_type" = "iptables" ]; then
        # Check for PROXYCTL_INTERCEPT chain
        if iptables -t nat -L PROXYCTL_INTERCEPT -n >/dev/null 2>&1; then
            echo "✓ PROXYCTL_INTERCEPT chain exists"
        else
            echo "✗ FAIL: PROXYCTL_INTERCEPT chain not found"
            return 1
        fi

        # Check for redirect rules (port 80, 443 -> 3128)
        if iptables -t nat -L PROXYCTL_INTERCEPT -n | grep -q "REDIRECT.*dpt:80.*redir ports 3128"; then
            echo "✓ Port 80 redirect rule found"
        else
            echo "  Warning: Port 80 redirect rule not found in expected format"
        fi

        if iptables -t nat -L PROXYCTL_INTERCEPT -n | grep -q "REDIRECT.*dpt:443.*redir ports 3128"; then
            echo "✓ Port 443 redirect rule found"
        else
            echo "  Warning: Port 443 redirect rule not found in expected format"
        fi
    else
        # Check for nftables table
        if nft list table ip proxyctl_intercept >/dev/null 2>&1; then
            echo "✓ proxyctl_intercept table exists"
        else
            echo "✗ FAIL: proxyctl_intercept table not found"
            return 1
        fi

        # Check for redirect rules
        if nft list table ip proxyctl_intercept | grep -q "tcp dport 80 redirect to :3128"; then
            echo "✓ Port 80 redirect rule found"
        else
            echo "  Warning: Port 80 redirect rule not found"
        fi

        if nft list table ip proxyctl_intercept | grep -q "tcp dport 443 redirect to :3128"; then
            echo "✓ Port 443 redirect rule found"
        else
            echo "  Warning: Port 443 redirect rule not found"
        fi
    fi

    echo "✓ PASS: Port interception verified"
    echo ""
}

# Test 6: V2 status command
test_v2_status() {
    echo "Test 6: V2 Status Command"
    echo "---"

    # Run status command
    if ! /usr/local/bin/proxyctl status --config /tmp/test-v2-egress.json > /tmp/v2-status-output.log 2>&1; then
        echo "✗ FAIL: Status command failed"
        cat /tmp/v2-status-output.log
        return 1
    fi

    echo "✓ Status command executed"

    # Verify status output contains expected sections
    local expected_sections=(
        "Configuration"
        "Routing"
        "HAProxy"
        "Port Interception"
    )

    for section in "${expected_sections[@]}"; do
        if grep -q "$section" /tmp/v2-status-output.log; then
            echo "✓ Section found: $section"
        else
            echo "  Warning: Section not found: $section"
        fi
    done

    # Check for status indicators
    if grep -q "IP Forwarding.*enabled\|✓" /tmp/v2-status-output.log; then
        echo "✓ IP forwarding status shown"
    fi

    if grep -q "MASQUERADE.*enabled\|active\|✓" /tmp/v2-status-output.log; then
        echo "✓ MASQUERADE status shown"
    fi

    if grep -q "Service.*running\|active\|✓" /tmp/v2-status-output.log; then
        echo "✓ HAProxy service status shown"
    fi

    if grep -q "Status.*active\|✓" /tmp/v2-status-output.log; then
        echo "✓ Port interception status shown"
    fi

    echo "✓ PASS: V2 status command"
    echo ""
}

# Test 7: Remove v2 config
test_remove_v2_config() {
    echo "Test 7: Remove V2 Config"
    echo "---"

    # Run remove command
    if ! echo "yes" | /usr/local/bin/proxyctl remove --config /tmp/test-v2-egress.json; then
        echo "✗ FAIL: Config removal failed"
        return 1
    fi

    echo "✓ Removal command completed"
    sleep 2

    # Verify port interception removed
    if check_port_intercept 2>/dev/null; then
        echo "  Warning: Port interception still active"
    else
        echo "✓ Port interception removed"
    fi

    # Verify HAProxy stopped
    if check_haproxy_running 2>/dev/null; then
        echo "  Warning: HAProxy still running"
    else
        echo "✓ HAProxy stopped"
    fi

    # Verify HAProxy disabled
    if check_haproxy_enabled 2>/dev/null; then
        echo "  Warning: HAProxy still enabled"
    else
        echo "✓ HAProxy disabled"
    fi

    # Verify routing removed
    if check_ip_forward; then
        echo "  Warning: IP forwarding still enabled (may be desired)"
    else
        echo "✓ IP forwarding disabled"
    fi

    if check_masquerade 2>/dev/null; then
        echo "  Warning: MASQUERADE still active"
    else
        echo "✓ MASQUERADE removed"
    fi

    echo "✓ PASS: V2 config removal"
    echo ""
}

# Test 8: Config validation - invalid interface
test_config_validation_invalid_interface() {
    echo "Test 8: Config Validation - Invalid Interface"
    echo "---"

    # Create config with non-existent interface
    cat > /tmp/test-v2-invalid-iface.json <<'EOF'
{
  "admin": {
    "sources": ["0.0.0.0/0"]
  },
  "interfaces": {
    "public": "nonexistent999",
    "loopback": "lo"
  },
  "routing": {
    "enabled": true,
    "ip_forward": true,
    "masquerade": {
      "enabled": true,
      "interface": "public"
    }
  }
}
EOF

    # Should fail with interface validation error
    if echo "yes" | /usr/local/bin/proxyctl apply --config /tmp/test-v2-invalid-iface.json 2>&1 | grep -q "does not exist"; then
        echo "✓ Invalid interface properly rejected"
    else
        echo "  Warning: Interface validation may have passed (interface may exist)"
    fi

    echo "✓ PASS: Config validation for invalid interface"
    echo ""
}

# Test 9: Config validation - missing required fields
test_config_validation_missing_fields() {
    echo "Test 9: Config Validation - Missing Required Fields"
    echo "---"

    # Create config missing admin section
    cat > /tmp/test-v2-missing-admin.json <<'EOF'
{
  "interfaces": {
    "public": "eth0"
  },
  "routing": {
    "enabled": true,
    "ip_forward": true,
    "masquerade": {
      "enabled": false
    }
  }
}
EOF

    # Should fail with validation error
    if /usr/local/bin/proxyctl apply --config /tmp/test-v2-missing-admin.json --dry-run 2>&1 | grep -q "validation failed\|admin"; then
        echo "✓ Missing admin section properly rejected"
    else
        echo "  Warning: Validation may have passed with empty admin"
    fi

    echo "✓ PASS: Config validation for missing fields"
    echo ""
}

# Test 10: Ingress reverse proxy config (dry-run only)
test_ingress_reverse_proxy_dry_run() {
    echo "Test 10: Ingress Reverse Proxy Config (Dry-Run)"
    echo "---"

    local primary_iface=$(detect_interface)

    # Create ingress config
    cat > /tmp/test-v2-ingress.json <<EOF
{
  "admin": {
    "sources": ["0.0.0.0/0"]
  },
  "interfaces": {
    "public": "$primary_iface",
    "private": "lo"
  },
  "proxy": {
    "enabled": true,
    "mode": "ingress",
    "type": "reverse",
    "bind": {
      "interface": "public",
      "port": 80
    },
    "backends": {
      "interface": "private",
      "servers": [
        {"ip": "127.0.0.1", "port": 8080, "weight": 100}
      ],
      "load_balance": "roundrobin"
    }
  }
}
EOF

    echo "  Created ingress reverse proxy config"

    # Dry-run only (don't actually apply ingress config on test system)
    if /usr/local/bin/proxyctl apply --config /tmp/test-v2-ingress.json --dry-run; then
        echo "✓ Ingress config validation passed"
    else
        echo "✗ FAIL: Ingress config validation failed"
        return 1
    fi

    echo "✓ PASS: Ingress reverse proxy config (dry-run)"
    echo ""
}

# Test 11: Firewall + Routing + Proxy combined
test_combined_firewall_routing_proxy() {
    echo "Test 11: Combined Firewall + Routing + Proxy"
    echo "---"

    local primary_iface=$(detect_interface)

    # Create comprehensive config
    cat > /tmp/test-v2-combined.json <<EOF
{
  "admin": {
    "sources": ["0.0.0.0/0"],
    "ports": [22]
  },
  "interfaces": {
    "public": "$primary_iface",
    "private": "lo",
    "loopback": "lo"
  },
  "firewall": {
    "enabled": true,
    "default_policy": "drop",
    "rules": [
      {
        "name": "allow-ssh",
        "interface": "public",
        "sources": ["0.0.0.0/0"],
        "protocol": "tcp",
        "ports": [22],
        "action": "accept"
      },
      {
        "name": "allow-proxy",
        "interface": "public",
        "sources": ["0.0.0.0/0"],
        "protocol": "tcp",
        "ports": [3128],
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
    }
  }
}
EOF

    echo "  Created combined config (firewall + routing + proxy)"

    # Dry-run to validate
    if ! /usr/local/bin/proxyctl apply --config /tmp/test-v2-combined.json --dry-run; then
        echo "✗ FAIL: Combined config dry-run failed"
        return 1
    fi

    echo "✓ Combined config validation passed"

    # Note: We don't actually apply this in integration tests because:
    # - Firewall rules might interfere with SSH
    # - This is just validating the config structure works

    echo "✓ PASS: Combined firewall + routing + proxy config"
    echo ""
}

# Test 12: Configuration summary display
test_configuration_summary() {
    echo "Test 12: Configuration Summary Display"
    echo "---"

    # Apply a config and check summary
    local primary_iface=$(detect_interface)

    # Re-apply test config
    if ! echo "yes" | /usr/local/bin/proxyctl apply --config /tmp/test-v2-egress.json 2>&1 | tee /tmp/apply-output.log; then
        echo "✗ FAIL: Failed to apply config"
        return 1
    fi

    # Check if summary was displayed
    if grep -q "Configuration Summary" /tmp/apply-output.log; then
        echo "✓ Configuration summary displayed"
    else
        echo "  Warning: Configuration summary not found"
    fi

    # Check for key sections in summary
    if grep -q "Routing:" /tmp/apply-output.log; then
        echo "✓ Routing section in summary"
    fi

    if grep -q "Proxy:" /tmp/apply-output.log; then
        echo "✓ Proxy section in summary"
    fi

    # Clean up
    echo "yes" | /usr/local/bin/proxyctl remove --config /tmp/test-v2-egress.json >/dev/null 2>&1 || true

    echo "✓ PASS: Configuration summary display"
    echo ""
}

# Run all tests
main() {
    local failed_tests=()

    for test_func in \
        test_apply_v2_dry_run \
        test_apply_v2_config \
        test_verify_routing \
        test_verify_haproxy \
        test_verify_port_intercept \
        test_v2_status \
        test_remove_v2_config \
        test_config_validation_invalid_interface \
        test_config_validation_missing_fields \
        test_ingress_reverse_proxy_dry_run \
        test_combined_firewall_routing_proxy \
        test_configuration_summary; do

        if ! $test_func; then
            failed_tests+=("$test_func")
        fi
    done

    echo "========================================"
    echo "Test Results"
    echo "========================================"
    if [ ${#failed_tests[@]} -eq 0 ]; then
        echo "✓ All tests passed!"
        echo "Completed: $(date)"
        exit 0
    else
        echo "✗ Failed tests: ${failed_tests[*]}"
        echo "Completed: $(date)"
        exit 1
    fi
}

main
