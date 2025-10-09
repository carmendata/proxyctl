package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Type represents the firewall type
type Type string

const (
	TypeIPTables Type = "iptables"
	TypeNFTables Type = "nftables"
	TypeUnknown  Type = "unknown"
)

// Manager handles firewall operations
type Manager struct {
	Type Type
}

// Detect detects the firewall type on the system
func Detect() (Type, error) {
	// Check for nftables first (prefer on newer systems)
	if _, err := exec.LookPath("nft"); err == nil {
		if _, err := os.Stat("/etc/nftables.conf"); err == nil {
			return TypeNFTables, nil
		}
	}

	// Check for iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		return TypeIPTables, nil
	}

	return TypeUnknown, fmt.Errorf("no firewall tool detected (iptables or nftables required)")
}

// EnsureFirewall ensures a firewall is available, installing one if necessary
// Returns the firewall type that is now available
func EnsureFirewall() (Type, error) {
	// First try to detect existing firewall
	fwType, err := Detect()
	if err == nil {
		return fwType, nil
	}

	// Before installing, check for conflicting firewall managers
	if err := checkConflictingFirewallManagers(); err != nil {
		return TypeUnknown, err
	}

	// No firewall detected, try to install one
	fmt.Println("No firewall detected. Attempting to install...")

	// Try to install nftables first (preferred on modern systems)
	if err := installNFTables(); err == nil {
		fmt.Println("✓ nftables installed successfully with permissive rules")
		return TypeNFTables, nil
	}

	// Fallback to iptables
	if err := installIPTables(); err == nil {
		fmt.Println("✓ iptables installed successfully with permissive rules")
		return TypeIPTables, nil
	}

	return TypeUnknown, fmt.Errorf("failed to install any firewall (tried nftables and iptables)")
}

// checkConflictingFirewallManagers checks for firewalld or ufw which would conflict
func checkConflictingFirewallManagers() error {
	// Check for firewalld
	if isFirewalldActive() {
		return fmt.Errorf("cannot proceed: firewalld is active on this system\n\n" +
			"Reason: firewalld is a management layer that controls iptables/nftables.\n" +
			"Directly manipulating firewall rules while firewalld is active causes conflicts:\n" +
			"  - Our rules may be overwritten when firewalld reloads\n" +
			"  - Rule priority and ordering becomes unpredictable\n" +
			"  - firewalld's state becomes out of sync with actual rules\n\n" +
			"Options:\n" +
			"  1. Disable firewalld and manage rules directly:\n" +
			"     systemctl stop firewalld && systemctl disable firewalld\n" +
			"     Then run this command again\n\n" +
			"  2. Use firewalld's native commands instead:\n" +
			"     firewall-cmd --permanent --direct --add-rule ...\n" +
			"     (See firewalld documentation for connection logging)")
	}

	// Check for ufw
	if isUFWActive() {
		return fmt.Errorf("cannot proceed: ufw is active on this system\n\n" +
			"Reason: ufw is a management layer that controls iptables.\n" +
			"Directly manipulating firewall rules while ufw is active causes conflicts:\n" +
			"  - Our rules may be overwritten when ufw reloads\n" +
			"  - Rule priority and ordering becomes unpredictable\n" +
			"  - ufw's state becomes out of sync with actual rules\n\n" +
			"Options:\n" +
			"  1. Disable ufw and manage rules directly:\n" +
			"     ufw disable\n" +
			"     Then run this command again\n\n" +
			"  2. Use ufw's native commands instead:\n" +
			"     (Note: ufw has limited support for custom logging rules)")
	}

	return nil
}

// isFirewalldActive checks if firewalld is installed and active
func isFirewalldActive() bool {
	// Check if firewall-cmd exists
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return false
	}

	// Check if firewalld service is active
	cmd := exec.Command("systemctl", "is-active", "firewalld")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(output)) == "active"
}

// isUFWActive checks if ufw is installed and active
func isUFWActive() bool {
	// Check if ufw exists
	if _, err := exec.LookPath("ufw"); err != nil {
		return false
	}

	// Check if ufw is active
	cmd := exec.Command("ufw", "status")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Status: active")
}

// installNFTables installs nftables with permissive rules
func installNFTables() error {
	// Check if nft binary is available (might be installed but not configured)
	if _, err := exec.LookPath("nft"); err != nil {
		// Try to install nftables package
		if err := installPackage("nftables"); err != nil {
			return fmt.Errorf("failed to install nftables package: %w", err)
		}
	}

	// Create initial permissive nftables.conf
	permissiveConfig := `#!/usr/sbin/nft -f
# Initial nftables configuration - created by proxyctl
# All traffic is ACCEPTED by default (permissive mode)

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
	}

	chain forward {
		type filter hook forward priority 0; policy accept;
	}

	chain output {
		type filter hook output priority 0; policy accept;
	}
}
`

	// Write configuration file
	if err := os.WriteFile("/etc/nftables.conf", []byte(permissiveConfig), 0644); err != nil {
		return fmt.Errorf("failed to write nftables.conf: %w", err)
	}

	// Create nftables.d directory for modular configs
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create nftables.d directory: %w", err)
	}

	// Enable and start nftables service
	if err := exec.Command("systemctl", "enable", "nftables").Run(); err != nil {
		return fmt.Errorf("failed to enable nftables service: %w", err)
	}

	if err := exec.Command("systemctl", "start", "nftables").Run(); err != nil {
		return fmt.Errorf("failed to start nftables service: %w", err)
	}

	return nil
}

// installIPTables installs iptables with permissive rules
func installIPTables() error {
	// Check if iptables binary is available
	if _, err := exec.LookPath("iptables"); err != nil {
		// Try to install iptables package
		if err := installPackage("iptables"); err != nil {
			return fmt.Errorf("failed to install iptables package: %w", err)
		}
	}

	// Set permissive policies (accept all by default)
	policies := [][]string{
		{"INPUT", "ACCEPT"},
		{"FORWARD", "ACCEPT"},
		{"OUTPUT", "ACCEPT"},
	}

	for _, policy := range policies {
		cmd := exec.Command("iptables", "-P", policy[0], policy[1])
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set %s policy: %w", policy[0], err)
		}
	}

	// Try to install persistence tool
	installPackage("iptables-persistent")  // Best effort, ignore errors
	installPackage("netfilter-persistent") // Best effort, ignore errors

	// Try to save the rules if persistence tools are available
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		exec.Command("netfilter-persistent", "save").Run()
	} else if _, err := exec.LookPath("iptables-save"); err == nil {
		// Create directory if needed
		os.MkdirAll("/etc/iptables", 0755)
		exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4").Run()
	}

	return nil
}

// installPackage attempts to install a package using the system's package manager
func installPackage(packageName string) error {
	// Try apt-get (Debian/Ubuntu)
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd := exec.Command("apt-get", "update")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}

		cmd = exec.Command("apt-get", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apt-get install failed: %w", err)
		}
		return nil
	}

	// Try yum (RHEL/CentOS)
	if _, err := exec.LookPath("yum"); err == nil {
		cmd := exec.Command("yum", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("yum install failed: %w", err)
		}
		return nil
	}

	// Try dnf (Fedora/RHEL 8+)
	if _, err := exec.LookPath("dnf"); err == nil {
		cmd := exec.Command("dnf", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dnf install failed: %w", err)
		}
		return nil
	}

	return fmt.Errorf("no supported package manager found (tried apt-get, yum, dnf)")
}

// NewManager creates a new firewall manager
func NewManager() (*Manager, error) {
	fwType, err := Detect()
	if err != nil {
		return nil, err
	}

	return &Manager{Type: fwType}, nil
}

// RemoveEgressProxyRules removes egress proxy firewall rules
func (m *Manager) RemoveEgressProxyRules() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeIPTablesRules()
	case TypeNFTables:
		return m.removeNFTablesRules()
	default:
		return fmt.Errorf("unknown firewall type")
	}
}

// RemoveEgressLoggerRules removes egress logger firewall rules
func (m *Manager) RemoveEgressLoggerRules() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeIPTablesLoggerRules()
	case TypeNFTables:
		return m.removeNFTablesLoggerRules()
	default:
		return fmt.Errorf("unknown firewall type")
	}
}

// removeIPTablesRules removes EGRESS_PROXY chain
func (m *Manager) removeIPTablesRules() error {
	// Remove jump to EGRESS_PROXY chain
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "EGRESS_PROXY").Run()

	// Flush and delete EGRESS_PROXY chain
	exec.Command("iptables", "-t", "nat", "-F", "EGRESS_PROXY").Run()
	exec.Command("iptables", "-t", "nat", "-X", "EGRESS_PROXY").Run()

	// Save changes
	return m.saveIPTables()
}

// removeNFTablesRules removes egress_proxy table
func (m *Manager) removeNFTablesRules() error {
	// Remove table
	exec.Command("nft", "delete", "table", "ip", "egress_proxy").Run()

	// Remove configuration file
	os.Remove("/etc/nftables.d/egress-proxy.nft")

	// Remove include from main config
	if err := removeIncludeFromNFTablesConf(); err != nil {
		// Non-fatal error - log but continue
	}

	// Reload nftables
	cmd := exec.Command("systemctl", "reload", "nftables")
	cmd.Run()

	return nil
}

// removeIncludeFromNFTablesConf removes the egress-proxy.nft include line from nftables.conf
func removeIncludeFromNFTablesConf() error {
	confFile := "/etc/nftables.conf"

	// Read the file
	content, err := os.ReadFile(confFile)
	if err != nil {
		return err
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")
	var newLines []string
	includePattern := `include "/etc/nftables.d/egress-proxy.nft"`

	// Filter out the include line
	for _, line := range lines {
		if !strings.Contains(line, includePattern) {
			newLines = append(newLines, line)
		}
	}

	// Write back if something was removed
	if len(newLines) != len(lines) {
		newContent := strings.Join(newLines, "\n")
		return os.WriteFile(confFile, []byte(newContent), 0644)
	}

	return nil
}

// removeIPTablesLoggerRules removes EGRESS_LOG chain
func (m *Manager) removeIPTablesLoggerRules() error {
	// Remove jump to EGRESS_LOG chain
	exec.Command("iptables", "-D", "OUTPUT", "-j", "EGRESS_LOG").Run()

	// Flush and delete EGRESS_LOG chain
	exec.Command("iptables", "-F", "EGRESS_LOG").Run()
	exec.Command("iptables", "-X", "EGRESS_LOG").Run()

	return nil
}

// removeNFTablesLoggerRules removes egress_monitor table
func (m *Manager) removeNFTablesLoggerRules() error {
	// Remove table
	exec.Command("nft", "delete", "table", "ip", "egress_monitor").Run()

	// Remove configuration file
	os.Remove("/etc/nftables.d/egress-monitor.nft")

	// Remove include from main config
	if err := removeIncludeFromNFTablesConf(); err != nil {
		// Non-fatal error - continue even if this fails
	}

	// Reload nftables
	cmd := exec.Command("systemctl", "reload", "nftables")
	cmd.Run()

	return nil
}

// saveIPTables saves iptables rules
func (m *Manager) saveIPTables() error {
	// Try netfilter-persistent first
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		cmd := exec.Command("netfilter-persistent", "save")
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Fallback: iptables-save
	if _, err := exec.LookPath("iptables-save"); err == nil {
		cmd := exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
		return cmd.Run()
	}

	return nil
}

// ConfigureEgressProxy configures egress proxy rules
func (m *Manager) ConfigureEgressProxy(proxyIP string, proxyPort int) error {
	switch m.Type {
	case TypeIPTables:
		return m.setupIPTablesEgressRules(proxyIP, proxyPort)
	case TypeNFTables:
		return m.setupNFTablesEgressRules(proxyIP, proxyPort)
	default:
		return fmt.Errorf("unknown firewall type")
	}
}

// setupIPTablesEgressRules sets up iptables EGRESS_PROXY chain
func (m *Manager) setupIPTablesEgressRules(proxyIP string, proxyPort int) error {
	// Create custom chain for egress proxy rules
	cmd := exec.Command("iptables", "-t", "nat", "-N", "EGRESS_PROXY")
	cmd.Run() // Ignore error if exists

	// Flush existing rules
	exec.Command("iptables", "-t", "nat", "-F", "EGRESS_PROXY").Run()

	// Private IP ranges to exclude
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}

	// Exclude private IP ranges
	for _, ipRange := range privateRanges {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "EGRESS_PROXY", "-d", ipRange, "-j", "RETURN")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add private range exclusion: %w", err)
		}
	}

	// Exclude egress proxy IP itself
	cmd = exec.Command("iptables", "-t", "nat", "-A", "EGRESS_PROXY", "-d", proxyIP, "-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to exclude proxy IP: %w", err)
	}

	// Redirect traffic to egress proxy
	ports := []string{"80", "443", "22"}
	for _, port := range ports {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "EGRESS_PROXY",
			"-p", "tcp", "--dport", port,
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", proxyIP, proxyPort))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add DNAT rule for port %s: %w", port, err)
		}
	}

	// Remove existing jump to EGRESS_PROXY if it exists
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "EGRESS_PROXY").Run()

	// Insert jump to our custom chain at the beginning of OUTPUT
	cmd = exec.Command("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", "EGRESS_PROXY")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to insert jump rule: %w", err)
	}

	// Save rules
	return m.saveIPTables()
}

// setupNFTablesEgressRules sets up nftables egress_proxy table
func (m *Manager) setupNFTablesEgressRules(proxyIP string, proxyPort int) error {
	// Create nftables configuration for egress proxy
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}

	// Build nftables config content
	var config strings.Builder
	config.WriteString("# HAProxy Egress Proxy - Outbound Traffic Routing\n")
	config.WriteString("# Redirects HTTP, HTTPS, and SSH to transparent egress proxy\n\n")
	config.WriteString("table ip egress_proxy {\n")
	config.WriteString("    chain output {\n")
	config.WriteString("        type nat hook output priority -100; policy accept;\n\n")
	config.WriteString("        # Exclude private IP ranges (preserve internal connectivity)\n")

	for _, ipRange := range privateRanges {
		config.WriteString(fmt.Sprintf("        ip daddr %s return\n", ipRange))
	}

	config.WriteString(fmt.Sprintf("\n        # Exclude egress proxy IP itself\n"))
	config.WriteString(fmt.Sprintf("        ip daddr %s return\n\n", proxyIP))
	config.WriteString("        # Redirect outbound traffic to egress proxy\n")

	ports := []string{"80", "443", "22"}
	for _, port := range ports {
		config.WriteString(fmt.Sprintf("        tcp dport %s dnat to %s:%d\n", port, proxyIP, proxyPort))
	}

	config.WriteString("    }\n")
	config.WriteString("}\n")

	// Create nftables.d directory if needed
	os.MkdirAll("/etc/nftables.d", 0755)

	// Write config file
	if err := os.WriteFile("/etc/nftables.d/egress-proxy.nft", []byte(config.String()), 0644); err != nil {
		return fmt.Errorf("failed to write nftables config: %w", err)
	}

	// Include in main nftables config if not already present
	mainConf, err := os.ReadFile("/etc/nftables.conf")
	if err == nil {
		if !containsSubstring(string(mainConf), `include "/etc/nftables.d/egress-proxy.nft"`) {
			f, err := os.OpenFile("/etc/nftables.conf", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("failed to open nftables.conf: %w", err)
			}
			defer f.Close()

			if _, err := f.WriteString(`include "/etc/nftables.d/egress-proxy.nft"` + "\n"); err != nil {
				return fmt.Errorf("failed to write to nftables.conf: %w", err)
			}
		}
	}

	// Reload nftables
	cmd := exec.Command("systemctl", "reload", "nftables")
	if err := cmd.Run(); err != nil {
		// Fallback: direct load
		cmd = exec.Command("nft", "-f", "/etc/nftables.conf")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to reload nftables: %w", err)
		}
	}

	// Enable nftables service
	exec.Command("systemctl", "enable", "nftables").Run()

	return nil
}

// containsSubstring checks if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(strings.Contains(s, substr)))
}
