package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// ApplyOutputRedirect applies OUTPUT redirect rules based on redirect configuration
// Creates PROXYCTL_OUTPUT chain (iptables) or proxyctl_redirect table (nftables)
// Uses DNAT to redirect traffic to proxy while preserving original destination
func (m *Manager) ApplyOutputRedirect(cfg *config.RedirectConfig, proxyIP string, proxyPort int) error {
	switch m.Type {
	case TypeIPTables:
		return m.applyOutputRedirectIPTables(cfg, proxyIP, proxyPort)
	case TypeNFTables:
		return m.applyOutputRedirectNFTables(cfg, proxyIP, proxyPort)
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// RemoveOutputRedirect removes all proxyctl OUTPUT redirect rules
func (m *Manager) RemoveOutputRedirect() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeOutputRedirectIPTables()
	case TypeNFTables:
		return m.removeOutputRedirectNFTables()
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// applyOutputRedirectIPTables creates PROXYCTL_OUTPUT chain with iptables DNAT rules
func (m *Manager) applyOutputRedirectIPTables(cfg *config.RedirectConfig, proxyIP string, proxyPort int) error {
	// Create custom chain for proxyctl OUTPUT redirect rules
	cmd := exec.Command("iptables", "-t", "nat", "-N", "PROXYCTL_OUTPUT")
	cmd.Run() // Ignore error if chain already exists

	// Flush existing rules in PROXYCTL_OUTPUT chain
	if err := exec.Command("iptables", "-t", "nat", "-F", "PROXYCTL_OUTPUT").Run(); err != nil {
		return fmt.Errorf("failed to flush PROXYCTL_OUTPUT chain: %w", err)
	}

	// Skip redirect for traffic to proxy itself (prevent redirect loop)
	cmd = exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_OUTPUT",
		"-d", proxyIP, "-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add proxy bypass rule: %w", err)
	}

	// Skip redirect for loopback traffic
	cmd = exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_OUTPUT",
		"-o", "lo", "-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add loopback bypass rule: %w", err)
	}

	// Skip redirect for local network traffic (RFC 1918)
	localNetworks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, network := range localNetworks {
		cmd = exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_OUTPUT",
			"-d", network, "-j", "RETURN")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add local network bypass rule for %s: %w", network, err)
		}
	}

	// Add redirect rules based on type
	switch cfg.Type {
	case "partial":
		// Redirect only specific targets
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("partial redirect requires at least one target")
		}
		for _, target := range cfg.Targets {
			// DNAT to proxy on port 80 and 443
			for _, port := range []int{80, 443} {
				cmd = exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_OUTPUT",
					"-p", "tcp", "-d", target, "--dport", fmt.Sprintf("%d", port),
					"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", proxyIP, proxyPort))
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to add DNAT rule for %s:%d: %w", target, port, err)
				}
			}
		}
	case "full":
		// Redirect all HTTP/HTTPS traffic
		for _, port := range []int{80, 443} {
			cmd = exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_OUTPUT",
				"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", proxyIP, proxyPort))
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add full DNAT rule for port %d: %w", port, err)
			}
		}
	default:
		return fmt.Errorf("invalid redirect type: %s (must be 'partial' or 'full')", cfg.Type)
	}

	// Remove existing jump to PROXYCTL_OUTPUT if it exists (idempotent)
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "PROXYCTL_OUTPUT").Run()

	// Insert jump to our custom chain at position 1 (highest priority)
	cmd = exec.Command("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", "PROXYCTL_OUTPUT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to insert jump rule at position 1: %w", err)
	}

	// Save rules
	return m.saveIPTables()
}

// applyOutputRedirectNFTables creates proxyctl_redirect table with nftables DNAT rules
func (m *Manager) applyOutputRedirectNFTables(cfg *config.RedirectConfig, proxyIP string, proxyPort int) error {
	// Build nftables configuration
	var configBuilder strings.Builder

	configBuilder.WriteString("# proxyctl OUTPUT Redirect Rules\n")
	configBuilder.WriteString("# Created by proxyctl for egress proxy redirection\n")
	configBuilder.WriteString("# Priority: -100 (processed before default OUTPUT rules)\n\n")

	configBuilder.WriteString("table ip proxyctl_redirect {\n")
	configBuilder.WriteString("    chain output {\n")
	configBuilder.WriteString("        type nat hook output priority -100; policy accept;\n\n")

	// Skip redirect for traffic to proxy itself (prevent redirect loop)
	configBuilder.WriteString("        # Skip redirect for traffic to proxy itself\n")
	configBuilder.WriteString(fmt.Sprintf("        ip daddr %s return\n\n", proxyIP))

	// Skip redirect for loopback traffic
	configBuilder.WriteString("        # Skip redirect for loopback traffic\n")
	configBuilder.WriteString("        oif lo return\n\n")

	// Skip redirect for local network traffic (RFC 1918)
	configBuilder.WriteString("        # Skip redirect for local network traffic (RFC 1918)\n")
	configBuilder.WriteString("        ip daddr 10.0.0.0/8 return\n")
	configBuilder.WriteString("        ip daddr 172.16.0.0/12 return\n")
	configBuilder.WriteString("        ip daddr 192.168.0.0/16 return\n\n")

	// Add redirect rules based on type
	switch cfg.Type {
	case "partial":
		// Redirect only specific targets
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("partial redirect requires at least one target")
		}
		configBuilder.WriteString("        # Redirect specific targets to proxy (partial redirect)\n")
		for _, target := range cfg.Targets {
			configBuilder.WriteString(fmt.Sprintf("        ip daddr %s tcp dport { 80, 443 } dnat to %s:%d\n",
				target, proxyIP, proxyPort))
		}
	case "full":
		// Redirect all HTTP/HTTPS traffic
		configBuilder.WriteString("        # Redirect all HTTP/HTTPS traffic to proxy (full redirect)\n")
		configBuilder.WriteString(fmt.Sprintf("        tcp dport { 80, 443 } dnat to %s:%d\n",
			proxyIP, proxyPort))
	default:
		return fmt.Errorf("invalid redirect type: %s (must be 'partial' or 'full')", cfg.Type)
	}

	configBuilder.WriteString("    }\n")
	configBuilder.WriteString("}\n")

	// Create nftables.d directory if needed
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/nftables.d: %w", err)
	}

	// Write configuration file
	configPath := "/etc/nftables.d/proxyctl-redirect.nft"
	if err := os.WriteFile(configPath, []byte(configBuilder.String()), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Delete existing table to make idempotent (ignore error if doesn't exist)
	exec.Command("nft", "delete", "table", "ip", "proxyctl_redirect").Run()

	// Load the configuration immediately
	cmd := exec.Command("nft", "-f", configPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to load nftables rules: %w", err)
	}

	// Add include to main nftables.conf if not already present
	if err := m.addNFTablesInclude(configPath); err != nil {
		// Non-fatal - rules are already loaded, just won't persist across full reload
		fmt.Printf("Warning: could not add include to nftables.conf: %v\n", err)
	}

	return nil
}

// removeOutputRedirectIPTables removes PROXYCTL_OUTPUT chain
func (m *Manager) removeOutputRedirectIPTables() error {
	// Remove jump to PROXYCTL_OUTPUT chain
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "PROXYCTL_OUTPUT").Run()

	// Flush and delete PROXYCTL_OUTPUT chain
	exec.Command("iptables", "-t", "nat", "-F", "PROXYCTL_OUTPUT").Run()
	exec.Command("iptables", "-t", "nat", "-X", "PROXYCTL_OUTPUT").Run()

	// Save changes
	return m.saveIPTables()
}

// removeOutputRedirectNFTables removes proxyctl_redirect table
func (m *Manager) removeOutputRedirectNFTables() error {
	// Remove table
	exec.Command("nft", "delete", "table", "ip", "proxyctl_redirect").Run()

	// Remove configuration file
	os.Remove("/etc/nftables.d/proxyctl-redirect.nft")

	// Remove include from main config
	if err := m.removeNFTablesInclude("/etc/nftables.d/proxyctl-redirect.nft"); err != nil {
		// Non-fatal error - log but continue
		fmt.Printf("Warning: could not remove include from nftables.conf: %v\n", err)
	}

	return nil
}
