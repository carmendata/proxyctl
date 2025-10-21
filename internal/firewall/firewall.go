package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/pkgmgr"
)

// DUAL FIREWALL SUPPORT: iptables + nftables
//
// This package supports both iptables and nftables to accommodate existing
// production servers that have not yet migrated to nftables-based distributions.
//
// MIGRATION PLAN:
// Once all production servers are upgraded to nftables-based distributions
// (Ubuntu 22.04+, Debian 12+, RHEL 9+), we can simplify this package by:
//
//   1. Remove TypeIPTables constant
//   2. Remove all iptables-specific functions (setupIPTablesEgressRules, etc.)
//   3. Remove Rocky Linux 8 from integration test matrix (test/integration/run-integration-tests.sh)
//   4. Simplify Detect() to only check for nftables
//   5. Update documentation to remove iptables references
//
// CURRENT STATUS:
// - Legacy production servers still running iptables-based distros
// - Integration tests cover both: Rocky Linux 8 (iptables) + Ubuntu/Debian/CentOS 9 (nftables)
// - See test/integration/README.md for current distro matrix
//
// TODO (post-migration): Search codebase for "MIGRATION PLAN" to find all iptables code to remove

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
	// CRITICAL: Check for conflicting high-level firewall managers FIRST
	// UFW and firewalld sit on top of nftables/iptables and will conflict
	// with direct rule manipulation
	if err := checkConflictingFirewallManagers(); err != nil {
		return TypeUnknown, err
	}

	// Prefer nftables on modern systems (Debian 12+, Ubuntu 22.04+, RHEL 9+)
	// No config file check needed - apply functions create configs as needed
	if _, err := exec.LookPath("nft"); err == nil {
		return TypeNFTables, nil
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

// checkConflictingFirewallManagers checks for high-level firewall managers that would conflict
// These tools MANAGE the firewall exclusively and would conflict with direct rule manipulation
// Tools that just ADD rules (Docker, fail2ban, etc.) are fine and don't conflict
func checkConflictingFirewallManagers() error {
	// Check for firewalld
	if isFirewalldActive() {
		return fmt.Errorf("cannot proceed: firewalld is active on this system\n\n" +
			"PROBLEM:\n" +
			"  firewalld is a high-level firewall manager that controls nftables/iptables.\n" +
			"  proxyctl detected nftables/iptables on your system, but cannot use them directly\n" +
			"  because firewalld is managing them.\n\n" +
			"WHY THIS MATTERS:\n" +
			"  • proxyctl's rules would bypass firewalld (hidden from 'firewall-cmd --list-all')\n" +
			"  • Your rules may be overwritten when firewalld reloads\n" +
			"  • Mixed rule sources make security auditing and troubleshooting difficult\n" +
			"  • You wouldn't be able to see or manage proxyctl's rules through firewalld\n\n" +
			"SOLUTION - Choose one:\n\n" +
			"  Option 1: Disable firewalld (recommended for proxyctl)\n" +
			"    sudo systemctl stop firewalld\n" +
			"    sudo systemctl disable firewalld\n" +
			"    Then run this command again\n\n" +
			"  Option 2: Keep firewalld and integrate manually\n" +
			"    Use firewalld's direct rule interface:\n" +
			"    firewall-cmd --permanent --direct --add-rule ...\n" +
			"    (Note: This requires manual configuration. See firewalld docs)\n\n" +
			"  Option 3: Remove proxyctl\n" +
			"    If you prefer to keep firewalld, proxyctl cannot be used on this system.")
	}

	// Check for ufw
	if isUFWActive() {
		return fmt.Errorf("cannot proceed: ufw is active on this system\n\n" +
			"PROBLEM:\n" +
			"  ufw (Uncomplicated Firewall) is a high-level firewall manager that controls\n" +
			"  iptables/nftables. proxyctl detected nftables/iptables on your system, but\n" +
			"  cannot use them directly because ufw is managing them.\n\n" +
			"WHY THIS MATTERS:\n" +
			"  • proxyctl's rules would bypass ufw (hidden from 'ufw status')\n" +
			"  • Your rules may be overwritten when ufw reloads\n" +
			"  • Mixed rule sources make security auditing and troubleshooting difficult\n" +
			"  • You wouldn't be able to see or manage proxyctl's rules through ufw\n\n" +
			"SOLUTION - Choose one:\n\n" +
			"  Option 1: Disable ufw (recommended for proxyctl)\n" +
			"    sudo ufw disable\n" +
			"    Then run this command again\n\n" +
			"  Option 2: Keep ufw and integrate manually\n" +
			"    Add custom iptables rules through ufw's before.rules:\n" +
			"    Edit /etc/ufw/before.rules and add logging rules\n" +
			"    (Note: This requires manual configuration and iptables knowledge)\n\n" +
			"  Option 3: Remove proxyctl\n" +
			"    If you prefer to keep ufw, proxyctl cannot be used on this system.\n\n" +
			"Ubuntu/Debian users: This is expected on systems with default UFW configuration.\n" +
			"You must choose whether to use ufw or proxyctl for firewall management.")
	}

	// Check for CSF (ConfigServer Security & Firewall)
	if isCSFActive() {
		return fmt.Errorf("cannot proceed: CSF (ConfigServer Security & Firewall) is active on this system\n\n" +
			"PROBLEM:\n" +
			"  CSF is a high-level firewall manager commonly used with cPanel/WHM.\n" +
			"  proxyctl cannot use iptables/nftables directly because CSF is managing them.\n\n" +
			"SOLUTION - Choose one:\n\n" +
			"  Option 1: Disable CSF (recommended for proxyctl)\n" +
			"    csf -x\n" +
			"    systemctl disable csf\n" +
			"    Then run this command again\n\n" +
			"  Option 2: Keep CSF and integrate manually\n" +
			"    Add custom rules through CSF's custom rule files\n" +
			"    (Note: This requires manual configuration. See CSF documentation)\n\n" +
			"  Option 3: Remove proxyctl\n" +
			"    If you prefer to keep CSF, proxyctl cannot be used on this system.")
	}

	// Check for Shorewall
	if isShorewallActive() {
		return fmt.Errorf("cannot proceed: Shorewall is active on this system\n\n" +
			"PROBLEM:\n" +
			"  Shorewall is a high-level firewall manager that controls iptables/nftables.\n" +
			"  proxyctl cannot use iptables/nftables directly because Shorewall is managing them.\n\n" +
			"SOLUTION - Choose one:\n\n" +
			"  Option 1: Disable Shorewall (recommended for proxyctl)\n" +
			"    shorewall stop\n" +
			"    systemctl disable shorewall\n" +
			"    Then run this command again\n\n" +
			"  Option 2: Keep Shorewall and integrate manually\n" +
			"    Add custom rules through Shorewall's rule files\n" +
			"    (Note: This requires manual configuration. See Shorewall documentation)\n\n" +
			"  Option 3: Remove proxyctl\n" +
			"    If you prefer to keep Shorewall, proxyctl cannot be used on this system.")
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

// isCSFActive checks if CSF (ConfigServer Security & Firewall) is installed and active
func isCSFActive() bool {
	// Check if csf command exists
	if _, err := exec.LookPath("csf"); err != nil {
		return false
	}

	// Check if CSF is running by checking for the lfd daemon (CSF's login failure daemon)
	// CSF itself doesn't have a persistent service, but lfd does
	cmd := exec.Command("systemctl", "is-active", "lfd")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return true
	}

	// Fallback: Check if CSF rules are present in iptables
	// CSF typically adds comments with "csf" in them
	cmd = exec.Command("iptables", "-L", "-n")
	output, err = cmd.Output()
	if err != nil {
		return false
	}

	// If we see CSF-specific chains or comments, it's likely active
	return strings.Contains(string(output), "Chain LOCALINPUT") || // CSF creates this chain
		strings.Contains(string(output), "Chain LOCALOUTPUT") // CSF creates this chain
}

// isShorewallActive checks if Shorewall is installed and active
func isShorewallActive() bool {
	// Check if shorewall command exists
	if _, err := exec.LookPath("shorewall"); err != nil {
		return false
	}

	// Check if shorewall service is active
	cmd := exec.Command("systemctl", "is-active", "shorewall")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		return true
	}

	// Fallback: Try shorewall status command
	cmd = exec.Command("shorewall", "status")
	err = cmd.Run()
	// If shorewall status returns 0, it's running
	return err == nil
}

// installNFTables installs nftables with permissive rules
func installNFTables() error {
	// Check if nft binary is available (might be installed but not configured)
	if _, err := exec.LookPath("nft"); err != nil {
		// Try to install nftables package
		if err := pkgmgr.InstallPackage("nftables"); err != nil {
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
		if err := pkgmgr.InstallPackage("iptables"); err != nil {
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
	pkgmgr.InstallPackage("iptables-persistent")  // Best effort, ignore errors
	pkgmgr.InstallPackage("netfilter-persistent") // Best effort, ignore errors

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

// isHAProxyInstalled checks if HAProxy is installed on the system
func isHAProxyInstalled() bool {
	_, err := exec.LookPath("haproxy")
	return err == nil
}

// installHAProxy installs HAProxy package
func installHAProxy() error {
	// Check if haproxy binary is available (might be installed but not in PATH)
	if _, err := exec.LookPath("haproxy"); err != nil {
		fmt.Println("HAProxy not found. Installing...")
		// Try to install haproxy package
		if err := pkgmgr.InstallPackage("haproxy"); err != nil {
			return fmt.Errorf("failed to install haproxy package: %w", err)
		}
	}

	// Verify installation
	if _, err := exec.LookPath("haproxy"); err != nil {
		return fmt.Errorf("haproxy binary not found after installation")
	}

	// Enable HAProxy service (but don't start - config needs to be created first)
	exec.Command("systemctl", "enable", "haproxy").Run() // Best effort

	fmt.Println("✓ HAProxy installed successfully")
	return nil
}

// EnsureHAProxy ensures HAProxy is installed, installing it if necessary
// Returns error if installation fails
func EnsureHAProxy() error {
	// Check if already installed
	if isHAProxyInstalled() {
		return nil
	}

	// Try to install
	return installHAProxy()
}

// NewManager creates a new firewall manager
// Automatically installs nftables if no firewall is detected (unless conflicts exist)
func NewManager() (*Manager, error) {
	fwType, err := Detect()
	if err != nil {
		// Check if the error is due to no firewall being detected
		// If so, try to install one automatically
		if strings.Contains(err.Error(), "no firewall tool detected") {
			fmt.Println("No firewall detected. Installing nftables...")
			fwType, err = EnsureFirewall()
			if err != nil {
				return nil, fmt.Errorf("failed to install firewall: %w", err)
			}
			fmt.Printf("✓ Firewall installed: %s\n\n", fwType)
		} else {
			// Some other error (e.g., conflicting manager detected)
			return nil, err
		}
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
	// Try netfilter-persistent first (preferred method - handles both v4 and v6)
	if _, err := exec.LookPath("netfilter-persistent"); err == nil {
		cmd := exec.Command("netfilter-persistent", "save")
		if err := cmd.Run(); err == nil {
			return nil
		}
		// If netfilter-persistent exists but fails, try to install iptables-persistent package
		fmt.Println("Warning: netfilter-persistent save failed, attempting to install iptables-persistent...")
		if installErr := pkgmgr.InstallPackage("iptables-persistent"); installErr == nil {
			// Retry after installation
			retryCmd := exec.Command("netfilter-persistent", "save")
			if retryErr := retryCmd.Run(); retryErr == nil {
				return nil
			}
		}
	}

	// Fallback: Manual iptables-save to file
	if _, err := exec.LookPath("iptables-save"); err == nil {
		// Ensure /etc/iptables directory exists
		if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
			return fmt.Errorf("failed to create /etc/iptables directory: %w", err)
		}

		// Save iptables rules
		cmd := exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to save iptables rules to /etc/iptables/rules.v4: %w\n\n"+
				"This usually means iptables-persistent is not installed.\n"+
				"SOLUTION:\n"+
				"  Install iptables-persistent:\n"+
				"    Debian/Ubuntu: sudo apt-get install -y iptables-persistent\n"+
				"    RHEL/CentOS:   Rules are persisted differently on RHEL (no action needed)", err)
		}
		return nil
	}

	// No save method available - rules will not persist across reboot
	fmt.Println("Warning: No iptables persistence method found. Rules will not survive reboot.")
	fmt.Println("Consider installing: apt-get install iptables-persistent")
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

	config.WriteString("\n        # Exclude egress proxy IP itself\n")
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
