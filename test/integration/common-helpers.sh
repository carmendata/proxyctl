#!/bin/bash
#
# Common helper functions for integration tests
#

# Detect the current SSH connection IP
# This prevents lockout when applying firewall rules
get_ssh_ip() {
    local ssh_ip=""

    # Method 1: Check SSH_CONNECTION environment variable
    if [ -n "$SSH_CONNECTION" ]; then
        ssh_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi

    # Method 2: Check SSH_CLIENT environment variable (fallback)
    if [ -z "$ssh_ip" ] && [ -n "$SSH_CLIENT" ]; then
        ssh_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi

    # Method 3: Get client IP from who command (fallback)
    if [ -z "$ssh_ip" ]; then
        ssh_ip=$(who -m | awk '{print $NF}' | tr -d '()')
    fi

    # Method 4: Check last login (last resort)
    if [ -z "$ssh_ip" ] || [ "$ssh_ip" = ":0" ] || [ "$ssh_ip" = "0.0.0.0" ]; then
        # If all methods fail or return local, get public IP of the test runner
        # This assumes the test is being run from a remote machine
        ssh_ip=$(curl -s -m 5 https://api.ipify.org 2>/dev/null || echo "")
    fi

    # Validate IP format
    if [[ ! $ssh_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ERROR: Could not detect valid SSH IP address. Got: '$ssh_ip'" >&2
        echo "ERROR: This would cause SSH lockout! Aborting." >&2
        return 1
    fi

    echo "$ssh_ip"
    return 0
}

# Validate that we're not using dangerous IPs in SSH whitelist
validate_ssh_whitelist() {
    local ip="$1"

    # Never allow 0.0.0.0/0 in tests
    if [ "$ip" = "0.0.0.0/0" ]; then
        echo "ERROR: 0.0.0.0/0 is not allowed in integration tests (too permissive)" >&2
        return 1
    fi

    # Warn about other overly broad ranges
    if [[ "$ip" =~ ^0\.0\.0\.0 ]] || [[ "$ip" =~ /0$ ]] || [[ "$ip" =~ /8$ ]]; then
        echo "WARNING: Very broad IP range detected: $ip" >&2
    fi

    return 0
}

# Export functions for use in test scripts
export -f get_ssh_ip
export -f validate_ssh_whitelist
