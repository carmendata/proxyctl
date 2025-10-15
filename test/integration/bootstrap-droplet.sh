#!/bin/bash
#
# Bootstrap script for proxyctl integration test droplets
# Installs required dependencies
#

set -euo pipefail

echo "=== Bootstrapping test droplet ==="

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Error: Cannot detect OS"
    exit 1
fi

echo "OS: $OS $VERSION"

# Wait for cloud-init and automatic updates to finish (common on fresh droplets)
echo "Waiting for system initialization..."
if command -v cloud-init >/dev/null 2>&1; then
    cloud-init status --wait >/dev/null 2>&1 || true
fi

# Wait for apt/dpkg locks to be released (Ubuntu/Debian)
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    echo "Waiting for package manager locks..."
    for i in {1..30}; do
        if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            break
        fi
        echo "  Waiting for package manager to become available... ($i/30)"
        sleep 10
    done
fi

# Update package cache
echo "Updating package cache..."
case $OS in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        ;;
    centos|rhel|fedora)
        yum makecache -q || dnf makecache -q
        ;;
    *)
        echo "Warning: Unknown OS: $OS"
        ;;
esac

# Install base dependencies
echo "Installing dependencies..."
case $OS in
    ubuntu|debian)
        apt-get install -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            curl \
            rsyslog \
            logrotate \
            haproxy
        ;;
    centos|rhel|fedora)
        yum install -y -q \
            curl \
            rsyslog \
            logrotate \
            haproxy \
        || dnf install -y -q \
            curl \
            rsyslog \
            logrotate \
            haproxy
        ;;
esac

# Ensure firewall tools are available
# Install nftables on all modern distros (our test matrix uses modern distros only)
echo "Ensuring firewall tools..."
case $OS in
    ubuntu|debian)
        # Install nftables package (provides nft command)
        # Note: iptables package may already be installed, but uses nftables backend
        apt-get install -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            nftables
        systemctl enable nftables >/dev/null 2>&1 || true
        ;;
    centos|rhel|fedora)
        # Install nftables (CentOS 9+ has it in repos)
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y -q nftables
        else
            yum install -y -q nftables
        fi
        systemctl enable nftables >/dev/null 2>&1 || true
        ;;
esac

# Ensure services are running
echo "Starting services..."
systemctl start rsyslog || true
systemctl enable rsyslog || true

# HAProxy will be configured by tests
systemctl stop haproxy || true
systemctl disable haproxy || true

# Create basic HAProxy config (required for tests)
mkdir -p /etc/haproxy
if [ ! -f /etc/haproxy/haproxy.cfg ]; then
    cat > /etc/haproxy/haproxy.cfg <<'EOF'
global
    log /dev/log local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    http
    option  httplog
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend test
    bind *:8080
    default_backend test

backend test
    server test1 127.0.0.1:9999
EOF
fi

# Create ACL file
mkdir -p /etc/haproxy
touch /etc/haproxy/acl.lst

echo "=== Bootstrap complete ==="
echo "Installed packages:"
echo "  rsyslog: $(rsyslogd -v 2>&1 | head -n1)"
echo "  haproxy: $(haproxy -v 2>&1 | head -n1)"

if command -v iptables >/dev/null 2>&1; then
    echo "  iptables: $(iptables --version)"
fi

if command -v nft >/dev/null 2>&1; then
    echo "  nftables: $(nft --version)"
fi
