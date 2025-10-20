# proxyctl

**Unified CLI for managing HAProxy proxy infrastructure for egress (outbound) and ingress (inbound) traffic.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://go.dev/doc/install)

> **Project Status:** MVP / Pre-Production (v0.x.x)
> Only egress mode is currently implemented. Ingress mode is planned but not yet functional.

---

## Overview

`proxyctl` is a command-line tool for managing HAProxy-based proxy infrastructure. It operates in three modes via symlinks:

- **`egressctl`** - Manage egress proxy (outbound traffic) - **IMPLEMENTED**
- **`ingressctl`** - Manage ingress proxy (inbound traffic) - **NOT YET IMPLEMENTED**
- **`proxyctl`** - Explicit mode selection using subcommands

A single binary provides all three modes through symlink detection.

## Features

### Currently Implemented (Egress Mode)

✅ **ACL Management** (79.5% test coverage)
- Add/remove/list IP addresses and CIDR blocks
- HAProxy configuration reload
- Remote server configuration checking

✅ **Firewall Management** (Integration tested)
- Dual firewall support: iptables + nftables
- INPUT filtering (restrict proxy access)
- OUTPUT redirect using DNAT (route worker traffic through proxy)
- Gateway routing using policy routing (fwmark + routing tables, v0.11.0)
- FORWARD chain rules with MASQUERADE/SNAT (v0.10.0)
- Automatic SSH lockout prevention
- Backup/restore functionality
- Dry-run mode for safe testing

✅ **Connection Logger** (Integration tested)
- Multi-chain logging support (INPUT, OUTPUT, FORWARD chains, v0.11.0)
- Per-chain log files with unique prefixes for easier analysis
- Protocol-based monitoring (TCP, UDP, ICMP)
- Configurable IP whitelists/blacklists
- Log rotation via logrotate (handles all per-chain log files)
- rsyslog integration with nftables/iptables logging
- Log analysis with summary reports (processes all per-chain logs)
- Backward compatible (defaults to OUTPUT chain if not specified)

✅ **Status Command with Drift Detection** (Integration tested)
- Comprehensive system status overview
- Configuration vs deployment drift detection
- Inferred configuration display
- Default value indicators

✅ **Server Management**
- Configure egress proxy routing
- Remove proxy configuration
- Check remote server status

### Incomplete / Placeholder Features

⚠️ **Not Implemented:**
- Ingress mode commands (all are placeholders)
- Daemon operations (placeholder in both modes)

⚠️ **Legacy Code:**
- Dual iptables/nftables support (planned for removal post-migration, see `internal/firewall/firewall.go:12-32`)

## Installation

### Quick Install (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/carmendata/proxyctl/main/install.sh | sudo bash
```

### Build from Source

**Requirements:**
- Go 1.21 or later
- Make
- Git

```bash
# Clone repository
git clone https://github.com/carmendata/proxyctl.git
cd proxyctl

# Build binary with symlinks
make build

# Install to /usr/local/bin (requires sudo)
sudo make install

# Verify installation
egressctl version
```

### Development Build

```bash
# Build and show usage examples
make dev

# Run with example config
./bin/egressctl --config configs/egress-full.json.example status
```

## Usage

### Basic Commands

```bash
# Show version
egressctl version

# Show comprehensive status
egressctl status

# Show help
egressctl --help
egressctl acl --help
```

### ACL Management

```bash
# Add IP to ACL
egressctl acl add 10.0.1.100

# Add CIDR block
egressctl acl add 10.0.2.0/24

# List all ACL entries
egressctl acl list

# Remove entry
egressctl acl remove 10.0.1.100

# Reload HAProxy after changes
egressctl acl reload
```

### Firewall Management

```bash
# Apply firewall rules from config (INPUT/OUTPUT/FORWARD with safety check)
egressctl firewall apply

# Dry-run mode (show what would be applied)
egressctl firewall apply --dry-run

# Show firewall status
egressctl firewall status

# Remove all proxyctl firewall rules
egressctl firewall remove

# Restore from backup
egressctl firewall restore /var/backups/proxyctl/firewall-20231012-143022.bak
```

### Logger Management

```bash
# Install connection logger
egressctl logger install

# Analyze today's logs
egressctl logger analyze

# Analyze specific date
egressctl logger analyze --date 20231012

# Remove logger
egressctl logger remove
```

### Server Management

```bash
# Configure egress proxy routing
egressctl server configure

# Remove proxy configuration
egressctl server remove

# Check remote server configuration
egressctl server check 10.0.1.50
```

## Configuration

Configuration uses **V2 format** (v0.8.0+). The old V1 format was removed in v0.9.0.

### Config File Locations

Searched in order:
1. `--config` flag (highest priority)
2. `./{mode}.json` (current directory)
3. `~/.config/proxyctl/{mode}.json` (user config)
4. `/etc/proxyctl/{mode}.json` (system config)

### Example Configuration

```json
{
  "proxy": {
    "ip": "10.16.0.5",
    "port": 8080
  },
  "acl": {
    "file": "/etc/haproxy/acl.txt"
  },
  "firewall": {
    "enabled": true,
    "input_policy": "drop",
    "allow_ssh_from": ["203.0.113.50"],
    "allow_proxy_from": [
      {"sources": ["10.0.1.0/24"], "ports": [8080]}
    ],
    "forward_policy": "drop",
    "allow_forward_from": [
      {
        "sources": ["10.0.1.0/24"],
        "destinations": ["0.0.0.0/0"],
        "protocols": ["tcp", "udp"],
        "masquerade": true
      }
    ]
  },
  "redirect": {
    "enabled": true,
    "type": "partial",
    "targets": ["8.8.8.8", "1.1.1.1"]
  },
  "logger": {
    "enabled": true,
    "name": "egress",
    "protocols": ["tcp", "udp"]
  }
}
```

See [`configs/README.md`](configs/README.md) for detailed configuration documentation and examples.

## Architecture

### Binary Mode Detection

The main binary detects its operating mode from `argv[0]` (symlink detection) in `cmd/proxyctl/main.go:40-51`. This allows a single binary to operate as three different commands.

### Dual Firewall Support

The firewall package supports both **iptables** and **nftables**:

- Legacy production servers still use iptables-based distros
- Integration tests cover both: Rocky Linux 8 (iptables) + Ubuntu/Debian/CentOS 9 (nftables)
- Auto-detection and conflict checking (UFW, firewalld, CSF, Shorewall)
- See `internal/firewall/firewall.go:12-32` for migration plan

**Future:** Once all production servers migrate to nftables-based distros, iptables support will be removed.

### Package Structure

```
cmd/proxyctl/       - Main binary and command implementations
internal/
  acl/              - HAProxy ACL file management (79.5% coverage)
  config/           - Configuration loading and validation (66.5% coverage)
  firewall/         - Firewall rule management - iptables/nftables (3.0% coverage)
    input.go        - INPUT chain filtering
    output.go       - OUTPUT chain redirect
    forward.go      - FORWARD chain with MASQUERADE (v0.10.0)
  logger/           - Connection logging functionality (15.6% coverage)
  pkgmgr/           - Package manager abstraction (21.1% coverage)
  version/          - Version information
  testutil/         - Testing utilities
test/integration/   - Integration tests on real infrastructure
configs/            - Configuration examples
```

### Test Coverage Summary

```
cmd/proxyctl         7.3%
internal/acl        79.5%
internal/config     66.5%
internal/firewall    3.0%
internal/logger     15.6%
internal/pkgmgr     21.1%
internal/testutil    0.0%
internal/version   (no tests)
```

**Note:** Low coverage in `cmd/proxyctl` and `internal/firewall` is supplemented by comprehensive integration tests that run on real DigitalOcean droplets.

## Development

### Prerequisites

- Go 1.21+
- Make
- Git
- DigitalOcean account (for integration tests)

### Commands

```bash
# Build binary
make build

# Run tests
make test

# Generate coverage report
make coverage

# Format code
make fmt

# Run linter
make lint

# Run CI checks (lint + test)
make ci
```

### Integration Testing

Integration tests run on real DigitalOcean droplets:

```bash
cd test/integration

# Prerequisites: Clean git working tree + DO_API_TOKEN in .env
cp .env.example .env  # Add your DigitalOcean API token

# Run on all supported distros
./run-integration-tests.sh --all

# Run on specific distro
./run-integration-tests.sh --os ubuntu-22-04

# Keep droplet alive for debugging
./run-integration-tests.sh --os ubuntu-22-04 --keep-alive
```

**Tested Distributions:**
- Ubuntu 22.04 LTS (nftables)
- Debian 12 (nftables)
- CentOS Stream 9 (nftables)
- Rocky Linux 8 (iptables)

### Git Hooks

```bash
# Install pre-commit and pre-push hooks
make install-hooks
```

## Releasing

```bash
# Create and push a new release
make release
```

The release process:
1. Verifies clean git working tree
2. Checks that integration tests have passed on current commit
3. Runs unit tests
4. Creates git tag
5. Pushes to GitHub, triggering release workflow

**Force release without integration tests (NOT recommended):**
```bash
FORCE_RELEASE=true make release
```

## Known Issues and TODOs

### Incomplete Features (from code inspection)

1. **Ingress Mode** (`cmd/proxyctl/commands.go:320-361`)
   - All commands show "coming soon" messages
   - Not functional

2. **Daemon Operations** (`cmd/proxyctl/commands.go:311-316, 356-360`)
   - Placeholder in both egress and ingress modes
   - Shows "coming soon" message

3. **iptables Support** (`internal/firewall/firewall.go:12-32`)
   - Legacy code supporting iptables-based distros
   - Planned for removal after production server migration
   - See `MIGRATION PLAN` comment in code

### Configuration Sections Not Yet Implemented

The following config sections are defined but not yet used:
- `haproxy` section
- `daemon` section
- `logging` section (distinct from `logger`)
- `alerts` section

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `make ci` to verify
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Links

- **GitHub:** https://github.com/carmendata/proxyctl
- **Issues:** https://github.com/carmendata/proxyctl/issues
- **Releases:** https://github.com/carmendata/proxyctl/releases

## Support

For bugs, feature requests, or questions:
- Open an issue on GitHub
- See documentation in `configs/README.md`
