#!/bin/bash
# proxyctl installation script
# Usage (latest): curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash
#    or: wget -qO- https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash
# Usage (specific version): curl -fsSL https://github.com/carmendata/proxyctl/releases/download/v0.1.4/install.sh | sudo bash
#    or: wget -qO- https://github.com/carmendata/proxyctl/releases/download/v0.1.4/install.sh | sudo bash

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
VERSION="${VERSION:-latest}"  # Can be set at release time (e.g., v0.1.4) or defaults to "latest"
UPGRADING=false
EXISTING_VERSION=""
LOGGER_INSTALLED=false
LOGGER_WAS_INSTALLED=false

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
    local download_url
    if [[ "$VERSION" == "latest" ]]; then
        download_url="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    else
        download_url="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY_NAME}-${OS}-${ARCH}"
    fi
    local temp_file="/tmp/${BINARY_NAME}-${OS}-${ARCH}"

    log_info "Downloading ${BINARY_NAME} ${VERSION} from ${download_url}..."

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
    log_info "Note: rsyslog and logrotate will be auto-installed when enabling connection logging"
}

detect_existing_installation() {
    # Check if proxyctl is already installed
    if command -v proxyctl &> /dev/null; then
        EXISTING_VERSION=$(proxyctl version 2>/dev/null | head -1 || echo "unknown")
        UPGRADING=true
        log_info "Detected existing installation: $EXISTING_VERSION"
    else
        UPGRADING=false
    fi
}

check_logger_installed() {
    # Check if logger is already installed
    if [[ "$FIREWALL" == "iptables" ]]; then
        if iptables -L OUTPUT -n 2>/dev/null | grep -q "EGRESS_LOG"; then
            return 0  # Logger is installed
        fi
    elif [[ "$FIREWALL" == "nftables" ]]; then
        if nft list tables 2>/dev/null | grep -q "egress_monitor"; then
            return 0  # Logger is installed
        fi
    fi
    return 1  # Logger not installed
}

cleanup_partial_installation() {
    log_warn "Cleaning up partial installation..."

    # Remove binary
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
        log_warn "  Removed ${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Remove symlinks
    if [[ -L "${INSTALL_DIR}/egressctl" ]]; then
        rm -f "${INSTALL_DIR}/egressctl"
        log_warn "  Removed ${INSTALL_DIR}/egressctl"
    fi

    if [[ -L "${INSTALL_DIR}/ingressctl" ]]; then
        rm -f "${INSTALL_DIR}/ingressctl"
        log_warn "  Removed ${INSTALL_DIR}/ingressctl"
    fi

    echo ""
    log_error "Installation failed - all files removed"
}

install_or_upgrade_logger() {
    # Check if logger is already installed
    if check_logger_installed; then
        LOGGER_WAS_INSTALLED=true

        if [[ "$UPGRADING" == "true" ]]; then
            log_info "Connection logger is currently installed"
            log_info "Upgrading logger to apply any bug fixes or improvements..."
            echo ""

            # Remove old logger
            if "${INSTALL_DIR}/egressctl" logger remove 2>/dev/null; then
                log_success "Removed old logger configuration"
            else
                log_warn "Could not remove old logger (may not have been properly installed)"
            fi

            # Install new logger
            if "${INSTALL_DIR}/egressctl" logger install; then
                log_success "Connection logger upgraded and active"
                LOGGER_INSTALLED=true
            else
                log_error "Failed to reinstall logger after upgrade"
                log_warn "You may need to manually reinstall: egressctl logger remove && egressctl logger install"
                LOGGER_INSTALLED=false
            fi
        else
            log_info "Connection logger is already installed"
            LOGGER_INSTALLED=true
        fi
    else
        LOGGER_WAS_INSTALLED=false
        log_info "Installing connection logger..."
        echo ""

        # Run egressctl logger install
        if "${INSTALL_DIR}/egressctl" logger install; then
            log_success "Connection logger installed and active"
            LOGGER_INSTALLED=true
        else
            # Logger installation failed
            echo ""
            log_error "Connection logger installation failed"

            # If this is a fresh install (not an upgrade), fail completely and clean up
            if [[ "$UPGRADING" == "false" ]]; then
                echo ""
                log_error "proxyctl is a connection monitoring tool - installation cannot continue without the logger"
                echo ""
                log_info "Common causes:"
                log_info "  • UFW firewall is active (conflicts with direct firewall access)"
                log_info "    Fix: sudo ufw disable"
                log_info ""
                log_info "  • firewalld is active (conflicts with direct firewall access)"
                log_info "    Fix: sudo systemctl stop firewalld && sudo systemctl disable firewalld"
                log_info ""
                log_info "  • Missing nftables/iptables tools"
                log_info "    Fix: sudo apt-get install nftables (or iptables-persistent)"
                echo ""

                cleanup_partial_installation
                exit 1
            else
                # During upgrade, be more lenient - warn but don't fail
                log_warn "Logger installation failed during upgrade"
                log_warn "The binary has been upgraded, but you may need to manually fix the logger"
                log_warn "Try: egressctl logger remove && egressctl logger install"
                LOGGER_INSTALLED=false
            fi
        fi
    fi

    echo ""
}

show_usage() {
    local version
    version=$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null | head -1 || echo "unknown")

    echo ""
    echo "=========================================="
    if [[ "$UPGRADING" == "true" ]]; then
        echo "  proxyctl Upgrade Complete!"
        echo "=========================================="
        echo ""
        echo "Previous version: $EXISTING_VERSION"
        echo "New version: $version"
    else
        echo "  proxyctl Installation Complete!"
        echo "=========================================="
        echo ""
        echo "Version: $version"
    fi
    echo "Release: $VERSION"
    echo "Installed to: ${INSTALL_DIR}/${BINARY_NAME}"
    echo "Symlinks: egressctl, ingressctl"

    if [[ "$FIREWALL" != "none" ]]; then
        echo "Firewall: $FIREWALL (auto-detected)"
    fi

    echo ""

    if [[ "$LOGGER_INSTALLED" == "true" ]]; then
        if [[ "$LOGGER_WAS_INSTALLED" == "true" ]] && [[ "$UPGRADING" == "true" ]]; then
            echo "✅ Connection Logger: UPGRADED and monitoring all outbound connections"
        else
            echo "✅ Connection Logger: ACTIVE and monitoring all outbound connections"
        fi
        echo ""
        echo "   Log file: /var/log/proxyctl/egress-output.log"
        echo "   Monitoring: All TCP/UDP connections to public IPs"
        echo "   Persistence: Rules will survive reboots automatically"
        echo ""
        if [[ "$FIREWALL" == "iptables" ]]; then
            echo "   Persistence method: systemd service (egressctl-logger.service)"
        elif [[ "$FIREWALL" == "nftables" ]]; then
            echo "   Persistence method: config file (/etc/nftables.d/egress-monitor.nft)"
        fi
        echo ""
        if [[ "$UPGRADING" == "true" ]] && [[ "$LOGGER_WAS_INSTALLED" == "true" ]]; then
            echo "The logger has been upgraded with the latest bug fixes."
            echo "No action needed - monitoring continues uninterrupted."
        else
            echo "Next Steps:"
            echo ""
            echo "  # Watch live connections"
            echo "  tail -f /var/log/proxyctl/egress-output.log"
            echo ""
            echo "  # After 7 days, analyze patterns"
            echo "  egressctl logger analyze"
            echo ""
            echo "  # Remove logger when done"
            echo "  egressctl logger remove"
        fi
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
    detect_existing_installation  # NEW: Check if upgrading
    detect_os_arch
    download_binary
    install_binary
    create_symlinks
    detect_firewall
    check_requirements
    install_or_upgrade_logger     # CHANGED: Handle upgrades
    show_usage
}

# Run main function
main
