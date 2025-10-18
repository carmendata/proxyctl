#!/bin/bash
# .devcontainer/setup.sh
# Development environment setup script for IAC project

set -euo pipefail

# Dynamic project configuration - workspace-aware for multi-clone support
WORKSPACE_DIR="$(pwd)"
PROJECT_NAME=$(basename "$WORKSPACE_DIR")
SANITIZED_PROJECT_NAME=$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9]//g')

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[SETUP]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root"
   exit 1
fi

# Detect environment
IS_DEVCONTAINER=false
HAS_SUDO=false

# Check for devcontainer-specific environment variables
if [[ -n "${REMOTE_CONTAINERS:-}" ]] || [[ -n "${CODESPACES:-}" ]] || [[ -f /workspaces/.devcontainer ]]; then
    IS_DEVCONTAINER=true
    info "Detected devcontainer environment"
fi

if sudo -n true 2>/dev/null; then
    HAS_SUDO=true
    info "Detected sudo access"
else
    warn "No sudo access - will install to user directories only"
fi

log "Starting $PROJECT_NAME development environment setup..."

# Install additional tools
install_tools() {
    log "Installing additional development tools..."

    if [[ "$HAS_SUDO" == "true" ]]; then
        # Update package list first
        sudo apt-get update

        # Install common tools
        sudo apt-get install -y \
            curl \
            wget \
            git \
            jq \
            tree \
            vim \
            htop \
            net-tools \
            dnsutils \
            nmap \
            telnet \
            netcat-openbsd \
            iputils-ping
    else
        # Check for required tools and install manually if missing
        local required_tools=("curl" "wget" "git" "jq")
        local missing_tools=()

        for tool in "${required_tools[@]}"; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                missing_tools+=("$tool")
            fi
        done

        if [[ ${#missing_tools[@]} -gt 0 ]]; then
            warn "Missing required tools without sudo access: ${missing_tools[*]}"
            info "Please install these tools manually or request sudo access"
        fi
    fi

    # Install doctl (DigitalOcean CLI) - works without sudo
    install_doctl

    # Install pnpm for Node.js package management (if Node.js is available)
    if command -v npm >/dev/null 2>&1; then
        install_pnpm
    else
        warn "Node.js/npm not found - skipping pnpm installation"
    fi
}

install_doctl() {
    log "Installing doctl (DigitalOcean CLI)..."

    local version="1.104.0"
    local arch="amd64"

    case $(uname -m) in
        aarch64|arm64) arch="arm64" ;;
    esac

    local download_url="https://github.com/digitalocean/doctl/releases/download/v${version}/doctl-${version}-linux-${arch}.tar.gz"
    local temp_dir=$(mktemp -d)

    cd "$temp_dir"
    curl -fsSL "$download_url" -o doctl.tar.gz
    tar -xzf doctl.tar.gz

    mv doctl "$HOME/.local/bin/"
    chmod +x "$HOME/.local/bin/doctl"

    cd - > /dev/null
    rm -rf "$temp_dir"

    log "doctl installed successfully"
}

# Setup shell aliases and functions
setup_shell() {
    log "Setting up shell aliases and functions..."

    # Add helpful aliases to bashrc
    cat >> ~/.bashrc << EOF

# $PROJECT_NAME Project Aliases
# alias ap='ansible-playbook'

EOF

    log "Shell aliases added to ~/.bashrc"
}

# Create development configuration
create_dev_config() {
    log "Creating development configuration files..."

    # Create .env template if it doesn't exist
    if [[ ! -f "$WORKSPACE_DIR/.env" && -f "$WORKSPACE_DIR/.env.example" ]]; then
        cp "$WORKSPACE_DIR/.env.example" "$WORKSPACE_DIR/.env"
        warn "Created .env file from .env.example - please update with your credentials"
    fi

    log "Development configuration setup complete"
}

# Verify installation
verify_installation() {
    log "Verifying installation..."

    local errors=0

    # Check doctl
    if command -v doctl >/dev/null 2>&1; then
        info "✓ doctl: $(doctl version | head -n1)"
    else
        error "✗ doctl not found"
        ((errors++))
    fi

    # Check netcat
    if command -v nc >/dev/null 2>&1; then
        info "✓ netcat: Available"
    else
        warn "? netcat not found (telnet available as alternative)"
    fi

    # Check core testing tools
    local testing_tools=("dig" "ssh" "telnet" "ss")
    for tool in "${testing_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            info "✓ $tool: Available"
        else
            error "✗ $tool not found (required for testing)"
            ((errors++))
        fi
    done

    if [[ $errors -eq 0 ]]; then
        log "All tools installed successfully!"
        info ""
    else
        error "Installation completed with $errors errors"
        exit 1
    fi
}

# Main execution
main() {
    info "ProxyCtl Development Environment Setup"
    info "===================================="

    install_tools
    setup_shell
    create_dev_config
    verify_installation

    log "Setup completed successfully!"
}

# Run main function
main "$@"