# proxyctl

**proxyctl** is a unified CLI tool for managing proxy infrastructure for both egress (outbound) and ingress (inbound) traffic.

## Features

TODO

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


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/carmendata/proxyctl/issues)
- **Releases**: [GitHub Releases](https://github.com/carmendata/proxyctl/releases)

---

**Status**: Pre-production (v0.x.x) - Not yet production-ready. Use with caution.
