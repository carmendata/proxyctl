# proxyctl

**proxyctl** is a unified CLI tool for managing HAProxy-based proxy infrastructure in both egress (outbound) and ingress (inbound) modes.

## Features

### Egress Mode (Outbound Traffic Management)
- **ACL Management** - Add/remove/list IP addresses and CIDR ranges
- **Firewall Management** - Config-driven INPUT filtering and OUTPUT redirect (v0.8.0+)
- **Server Configuration** - Configure internal servers to route through egress proxy
- **Connection Logging** - Monitor outbound connections to analyze traffic patterns
- **Remote Verification** - Check configuration on internal servers via SSH

### Ingress Mode (Inbound Traffic Management)
- **Backend Management** - Manage backend servers (planned)
- **SSL Certificate Management** - Handle SSL/TLS certificates (planned)
- **Routing Rules** - Configure traffic routing (planned)

### Common Features
- **Symlink Detection** - Binary behavior changes based on name (`egressctl`, `ingressctl`, `proxyctl`)
- **Dual Firewall Support** - Automatic detection and support for both iptables and nftables
- **Multi-platform** - Linux (amd64/arm64), macOS (amd64/arm64)
- **Zero Dependencies** - Pure Go, no external runtime dependencies

## Installation

### Quick Install (Recommended)

**Install Latest Version:**

One-liner installation script (auto-detects OS/architecture and firewall):

```bash
# Using curl
curl -fsSL https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash

# Or using wget
wget -qO- https://github.com/carmendata/proxyctl/releases/latest/download/install.sh | sudo bash
```

**Install Specific Version:**

```bash
# Using curl (replace v0.1.4 with desired version)
curl -fsSL https://github.com/carmendata/proxyctl/releases/download/v0.1.4/install.sh | sudo bash

# Or using wget
wget -qO- https://github.com/carmendata/proxyctl/releases/download/v0.1.4/install.sh | sudo bash
```

This will:
- Auto-detect your OS and architecture (Linux/macOS, amd64/arm64)
- Download the appropriate binary
- Install to `/usr/local/bin/proxyctl`
- Create symlinks (`egressctl`, `ingressctl`)
- Detect your firewall (iptables or nftables)
- Show you quick start commands

### Manual Installation

If you prefer manual installation:

**Latest Version:**

```bash
# Linux (amd64)
wget https://github.com/carmendata/proxyctl/releases/latest/download/proxyctl-linux-amd64
chmod +x proxyctl-linux-amd64
sudo mv proxyctl-linux-amd64 /usr/local/bin/proxyctl

# Create symlinks
sudo ln -s /usr/local/bin/proxyctl /usr/local/bin/egressctl
sudo ln -s /usr/local/bin/proxyctl /usr/local/bin/ingressctl
```

**Specific Version:**

```bash
# Linux (amd64) - replace v0.1.4 with desired version
wget https://github.com/carmendata/proxyctl/releases/download/v0.1.4/proxyctl-linux-amd64
chmod +x proxyctl-linux-amd64
sudo mv proxyctl-linux-amd64 /usr/local/bin/proxyctl

# Create symlinks
sudo ln -s /usr/local/bin/proxyctl /usr/local/bin/egressctl
sudo ln -s /usr/local/bin/proxyctl /usr/local/bin/ingressctl
```

### Build from Source

```bash
git clone https://github.com/carmendata/proxyctl.git
cd proxyctl
make build

# Install to /usr/local/bin
sudo make install
```

## Quick Start

### Egress Proxy Management

```bash
# Check overall proxy status
egressctl status

# Add IP to ACL
egressctl acl add 10.0.1.100

# List all ACL entries
egressctl acl list

# Reload HAProxy
egressctl acl reload

# Configure firewall (v0.8.0+)
egressctl firewall apply --config /etc/proxyctl/egress-firewall.json
egressctl firewall apply --config /etc/proxyctl/egress-firewall.json --dry-run  # Preview without applying
egressctl firewall status
egressctl firewall remove

# Configure internal server (run on internal server)
egressctl server configure 10.16.0.5

# Check remote server configuration (run from egress proxy)
egressctl server check 10.0.1.100 root
```

### Connection Logger

```bash
# Install connection logger (monitors outbound traffic)
# Automatically detects and configures iptables or nftables
egressctl logger install

# Analyze collected logs (today's connections)
egressctl logger analyze

# Analyze specific date
egressctl logger analyze --date 20251012

# Remove logger
egressctl logger remove

# Verify installation (iptables)
sudo iptables -L EGRESS_LOG -n -v

# Verify installation (nftables)
sudo nft list table ip egress_monitor
```

## Operating Modes

The binary changes behavior based on its name (via symlink detection):

- **`egressctl`** → Egress mode (outbound traffic management)
- **`ingressctl`** → Ingress mode (inbound traffic management)
- **`proxyctl`** → Generic mode (requires explicit mode selection)

## Configuration

Configuration files are loaded in this order (highest priority first):

1. Environment variables (`PROXYCTL_*`)
2. `--config` flag
3. Default paths:
   - `./egress.json` or `./ingress.json`
   - `~/.config/proxyctl/{mode}.json`
   - `/etc/proxyctl/{mode}.json`
4. Built-in defaults

### Example Configuration

```json
{
  "egress": {
    "acl_file": "/etc/haproxy/acl.lst",
    "proxy_port": 8080,
    "private_ip": "10.16.0.5",
    "public_ip": "203.0.113.100",
    "auto_reload": false
  }
}
```

See `configs/*.example` for full configuration templates.

## Usage Examples

### Status Check

```bash
# View comprehensive proxy status
egressctl status

# Example output:
# Egress Proxy Status
# ===================
#
# Configuration:
#   File: /etc/proxyctl/egress.json
#   Proxy: 10.16.0.5:8080
#
# HAProxy Service:
#   Status: ✓ Running
#   PID: 1234
#   Uptime: 5 days
#
# ACL:
#   File: /etc/haproxy/acl.lst
#   Entries: 15 IP/CIDR blocks
#   Last modified: 2025-10-15 14:30:00
#
# Logger:
#   Status: ✓ Installed
#   Log directory: /var/log/proxyctl
#   Current log: egress.log (1.2 MB)
#
# Firewall:
#   Type: nftables
#   INPUT filtering: ✓ Applied
#   OUTPUT redirect: Not configured
#   Backups: 3 available
#
#   ℹ️  For detailed firewall status, run: egressctl firewall status
```

### ACL Management

```bash
# Add single IP
egressctl acl add 192.168.1.100

# Add CIDR range
egressctl acl add 10.0.1.0/24

# Remove entry
egressctl acl remove 192.168.1.100

# List all entries (JSON output)
egressctl acl list --json
```

### Server Configuration

```bash
# Configure server to route through proxy
egressctl server configure 10.16.0.5

# Configure with custom port
egressctl server configure 10.16.0.5 9090

# Remove configuration
egressctl server remove

# Check remote server (from egress proxy)
egressctl server check internal-server.example.com ubuntu
```

### Firewall Management (v0.8.0+)

```bash
# Preview changes without applying (dry-run mode)
egressctl firewall apply --config /etc/proxyctl/egress-firewall.json --dry-run

# Apply INPUT filtering (egress proxy server hardening)
cat > /etc/proxyctl/egress-firewall.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["203.0.113.50"],
    "allow_proxy_from": [{"sources": ["10.0.1.0/24"], "ports": [8080]}]
  }
}
EOF
egressctl firewall apply --config /etc/proxyctl/egress-firewall.json

# Apply OUTPUT redirect - partial (worker server testing)
cat > /etc/proxyctl/worker-partial.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  }
}
EOF
egressctl firewall apply --config /etc/proxyctl/worker-partial.json

# Apply OUTPUT redirect - full (worker server production)
cat > /etc/proxyctl/worker-full.json <<EOF
{
  "proxy": {"ip": "10.16.0.5", "port": 8080},
  "redirect": {
    "enabled": true,
    "type": "full"
  }
}
EOF
egressctl firewall apply --config /etc/proxyctl/worker-full.json

# Check firewall status
egressctl firewall status

# Remove all firewall rules
egressctl firewall remove

# Restore from backup
egressctl firewall restore --backup /var/lib/proxyctl/firewall-backups/backup-TIMESTAMP.tar.gz
```

### Connection Logging

```bash
# Install logger (1 week baseline)
egressctl logger install

# View live connections
tail -f /var/log/proxyctl/egress.log

# Analyze collected data (today's connections)
egressctl logger analyze

# Analyze specific date (YYYYMMDD format)
egressctl logger analyze --date 20251012

# Remove logger and configs
egressctl logger remove
```

## Architecture

**proxyctl** is a thin CLI wrapper that orchestrates operations:

- **Go CLI** - Command parsing, configuration loading, orchestration
- **Internal Packages** - ACL management, firewall operations, logging
- **HAProxy Integration** - Direct systemctl integration for reloads
- **Dual Firewall Support** - Automatic detection and native support for both iptables and nftables
  - Logger: Creates EGRESS_LOG chain (iptables) or egress_monitor table (nftables)
  - Firewall (v0.8.0+): Config-driven INPUT filtering and OUTPUT redirect
    - INPUT: PROXYCTL_INPUT chain (iptables) or proxyctl_filter table (nftables)
    - OUTPUT: PROXYCTL_OUTPUT chain (iptables) or proxyctl_redirect table (nftables)
  - Legacy: EGRESS_PROXY chain (iptables) or egress_proxy table (nftables)

## Development

### Prerequisites

- Go 1.25+
- Make
- HAProxy (for production use)

### Building

```bash
# Build binaries
make build

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linters
make lint

# Full CI checks
make ci

# Cross-compile for all platforms
make release

# Install Git pre-commit hooks (auto-format on commit)
make install-hooks
```

### Git Hooks

To prevent formatting errors in CI, install the pre-commit hook:

```bash
make install-hooks
```

This will automatically:
- Run `make fmt` to format Go code before each commit
- Run `make vet` to catch common mistakes
- Re-stage formatted files automatically

The hook is stored in `scripts/pre-commit.sh` and installed to `.git/hooks/pre-commit`.

### Project Structure

```
.
├── cmd/proxyctl/          # CLI entry point and commands
├── internal/
│   ├── acl/              # ACL file management
│   ├── config/           # Configuration loading
│   ├── firewall/         # iptables/nftables operations
│   ├── logger/           # Connection logger
│   └── version/          # Version info
├── configs/              # Example configurations
└── scripts/              # Legacy bash scripts (deprecated)
```

## Deployment

### Egress Proxy (Permanent Servers)
- Long-lived servers with stable IPs
- ACL managed dynamically
- Configuration at `/etc/proxyctl/egress.json`

### Ingress Proxy (Ephemeral Servers)
- Short-lived servers replaced periodically
- Reserved IPs reassigned to new servers
- Configuration pulled from Consul/Vault

## Troubleshooting

### ACL Changes Not Taking Effect

```bash
# Reload HAProxy after ACL changes
egressctl acl reload

# Or enable auto-reload in config
{
  "egress": {
    "auto_reload": true
  }
}
```

### Firewall Rules Not Persisting

```bash
# For iptables
sudo apt-get install iptables-persistent
sudo netfilter-persistent save

# For nftables
sudo systemctl enable nftables
```

### Connection Logger Not Working

```bash
# Check if rules exist (iptables)
sudo iptables -L EGRESS_LOG -n -v

# Check if rules exist (nftables)
sudo nft list table ip egress_monitor

# Check log file
tail -f /var/log/proxyctl/egress.log

# Restart rsyslog
sudo systemctl restart rsyslog

# Check which firewall is active
test -f /etc/nftables.conf && command -v nft &>/dev/null && echo "nftables" || echo "iptables"
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. **Install Git hooks**: Run `make install-hooks` to auto-format code before commits
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Code Style

- Follow Go conventions
- Install pre-commit hooks with `make install-hooks` (recommended)
- Or manually run `make fmt` before committing
- Add tests for new features
- Update documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for managing HAProxy-based proxy infrastructure
- Designed for use with DigitalOcean droplets but works anywhere
- Replaces legacy bash scripts with native Go implementation

## Support

- **Issues**: [GitHub Issues](https://github.com/carmendata/proxyctl/issues)
- **Releases**: [GitHub Releases](https://github.com/carmendata/proxyctl/releases)

---

**Status**: Pre-production (v0.x.x) - Not yet production-ready. Use with caution.
