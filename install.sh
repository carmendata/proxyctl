#!/bin/bash
# proxyctl installation script
# Usage: curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash
#    or: wget -qO- https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO="carmendata/proxyctl"
BINARY_NAME="proxyctl"
LOGGER_INSTALLED=false

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

detect_os_arch() {
    # Detect OS
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        linux*)  OS="linux" ;;
        darwin*) OS="darwin" ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac

    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        arm64)   ARCH="arm64" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    log_info "Detected platform: ${OS}/${ARCH}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        echo "Please run with sudo:"
        echo "  curl -fsSL https://github.com/${REPO}/releases/latest/download/install.sh | sudo bash"
        exit 1
    fi
}

download_binary() {
    local download_url="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    local temp_file="/tmp/${BINARY_NAME}-${OS}-${ARCH}"

    log_info "Downloading ${BINARY_NAME} from ${download_url}..."

    if command -v curl &> /dev/null; then
        curl -fsSL -o "$temp_file" "$download_url"
    elif command -v wget &> /dev/null; then
        wget -q -O "$temp_file" "$download_url"
    else
        log_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [[ ! -f "$temp_file" ]]; then
        log_error "Failed to download binary"
        exit 1
    fi

    log_success "Downloaded ${BINARY_NAME}"
}

install_binary() {
    local temp_file="/tmp/${BINARY_NAME}-${OS}-${ARCH}"
    local target="${INSTALL_DIR}/${BINARY_NAME}"

    log_info "Installing to ${target}..."

    # Make directory if it doesn't exist
    mkdir -p "$INSTALL_DIR"

    # Move binary
    chmod +x "$temp_file"
    mv "$temp_file" "$target"

    log_success "Installed ${BINARY_NAME} to ${target}"
}

create_symlinks() {
    log_info "Creating symlinks..."

    ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/egressctl"
    ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/ingressctl"

    log_success "Created symlinks: egressctl, ingressctl"
}

detect_firewall() {
    log_info "Detecting firewall..."

    if command -v nft &> /dev/null && [[ -f /etc/nftables.conf ]]; then
        FIREWALL="nftables"
        log_info "Detected: nftables"
    elif command -v iptables &> /dev/null; then
        FIREWALL="iptables"
        log_info "Detected: iptables"
    else
        FIREWALL="none"
        log_warn "No firewall detected (iptables or nftables)"
    fi
}

check_requirements() {
    log_info "Checking system requirements..."

    # Check for rsyslog (REQUIRED for logging)
    if ! command -v rsyslogd &> /dev/null; then
        log_warn "rsyslog not found - attempting to install..."

        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            apt-get install -y rsyslog
        elif command -v yum &> /dev/null; then
            yum install -y rsyslog
        elif command -v dnf &> /dev/null; then
            dnf install -y rsyslog
        else
            log_error "Could not install rsyslog - no supported package manager found"
            log_error "Please install rsyslog manually: apt-get install rsyslog (or yum/dnf)"
            exit 1
        fi

        if ! command -v rsyslogd &> /dev/null; then
            log_error "Failed to install rsyslog"
            exit 1
        fi

        log_success "rsyslog installed"
    else
        log_info "rsyslog: found"
    fi

    # Ensure rsyslog service is running
    if command -v systemctl &> /dev/null; then
        if ! systemctl is-active --quiet rsyslog; then
            log_info "Starting rsyslog service..."
            systemctl start rsyslog
            systemctl enable rsyslog
        fi
    fi

    # Check for logrotate (recommended but not critical)
    if ! command -v logrotate &> /dev/null; then
        log_warn "logrotate not found - log rotation will not work"
        log_warn "Consider installing: apt-get install logrotate (or yum/dnf)"
    else
        log_info "logrotate: found"
    fi
}

install_logger() {
    log_info "Installing connection logger..."
    echo ""

    # Run egressctl logger install
    if "${INSTALL_DIR}/egressctl" logger install; then
        log_success "Connection logger installed and active"
        LOGGER_INSTALLED=true
    else
        log_warn "Failed to install logger automatically"
        log_warn "You can install it manually with: egressctl logger install"
        LOGGER_INSTALLED=false
    fi

    echo ""
}

show_usage() {
    local version
    version=$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null | head -1 || echo "unknown")

    echo ""
    echo "=========================================="
    echo "  proxyctl Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Version: $version"
    echo "Installed to: ${INSTALL_DIR}/${BINARY_NAME}"
    echo "Symlinks: egressctl, ingressctl"

    if [[ "$FIREWALL" != "none" ]]; then
        echo "Firewall: $FIREWALL (auto-detected)"
    fi

    echo ""

    if [[ "$LOGGER_INSTALLED" == "true" ]]; then
        echo "✅ Connection Logger: ACTIVE and monitoring all outbound connections"
        echo ""
        echo "   Log file: /var/log/proxyctl/egress.log"
        echo "   Monitoring: All TCP/UDP connections to public IPs"
        echo "   Persistence: Rules will survive reboots automatically"
        echo ""
        if [[ "$FIREWALL" == "iptables" ]]; then
            echo "   Persistence method: systemd service (egressctl-logger.service)"
        elif [[ "$FIREWALL" == "nftables" ]]; then
            echo "   Persistence method: config file (/etc/nftables.d/egress-monitor.nft)"
        fi
        echo ""
        echo "Next Steps:"
        echo ""
        echo "  # Watch live connections"
        echo "  tail -f /var/log/proxyctl/egress.log"
        echo ""
        echo "  # After 7 days, analyze patterns"
        echo "  egressctl logger analyze"
        echo ""
        echo "  # Remove logger when done"
        echo "  egressctl logger remove"
    else
        echo "Connection Logger: Not installed"
        echo ""
        echo "To start monitoring:"
        echo "  egressctl logger install"
    fi

    echo ""
    echo "Documentation:"
    echo "  https://github.com/${REPO}"
    echo ""
}

# Main installation flow
main() {
    echo "=========================================="
    echo "  proxyctl Installer"
    echo "=========================================="
    echo ""

    check_root
    detect_os_arch
    download_binary
    install_binary
    create_symlinks
    detect_firewall
    check_requirements
    install_logger
    show_usage
}

# Run main function
main
