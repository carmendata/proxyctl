package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// InterceptPorts configures PREROUTING rules to redirect specified ports to HAProxy
// This is used on the transparent egress proxy server itself
func (m *Manager) InterceptPorts(cfg *config.Config) error {
	if cfg.Proxy == nil || !cfg.Proxy.Enabled {
		return fmt.Errorf("proxy configuration is not enabled")
	}

	if cfg.Proxy.Intercept == nil {
		return fmt.Errorf("intercept configuration is required")
	}

	// Resolve interfaces to physical names
	fromInterface, ok := cfg.Interfaces[cfg.Proxy.Intercept.FromInterface]
	if !ok {
		return fmt.Errorf("interface '%s' not found in configuration", cfg.Proxy.Intercept.FromInterface)
	}

	bindInterface, ok := cfg.Interfaces[cfg.Proxy.Bind.Interface]
	if !ok {
		return fmt.Errorf("interface '%s' not found in configuration", cfg.Proxy.Bind.Interface)
	}

	switch m.Type {
	case TypeIPTables:
		return m.interceptPortsIPTables(fromInterface, bindInterface, cfg.Proxy.Intercept.Ports, cfg.Proxy.Bind.Port)
	case TypeNFTables:
		return m.interceptPortsNFTables(fromInterface, bindInterface, cfg.Proxy.Intercept.Ports, cfg.Proxy.Bind.Port)
	default:
		return fmt.Errorf("unsupported firewall type: %s", m.Type)
	}
}

// RemoveIntercept removes PREROUTING port interception rules
func (m *Manager) RemoveIntercept() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeInterceptIPTables()
	case TypeNFTables:
		return m.removeInterceptNFTables()
	default:
		return fmt.Errorf("unsupported firewall type: %s", m.Type)
	}
}

// interceptPortsIPTables sets up iptables PREROUTING redirect rules
func (m *Manager) interceptPortsIPTables(fromInterface, bindInterface string, ports []int, bindPort int) error {
	// Note: REDIRECT target doesn't need the bind IP, only the port
	// The kernel automatically determines the local IP to redirect to
	_ = bindInterface // Validated by caller, not needed for REDIRECT

	// Create custom chain for intercept rules
	cmd := exec.Command("iptables", "-t", "nat", "-N", "PROXYCTL_INTERCEPT")
	cmd.Run() // Ignore error if chain already exists

	// Flush existing rules in the chain
	exec.Command("iptables", "-t", "nat", "-F", "PROXYCTL_INTERCEPT").Run()

	// Add redirect rules for each port
	for _, port := range ports {
		// Redirect traffic coming from the specified interface to HAProxy
		cmd := exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_INTERCEPT",
			"-i", fromInterface,
			"-p", "tcp", "--dport", fmt.Sprintf("%d", port),
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", bindPort))

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add redirect rule for port %d: %w", port, err)
		}
	}

	// Remove existing jump to PROXYCTL_INTERCEPT if it exists
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PROXYCTL_INTERCEPT").Run()

	// Insert jump to our custom chain at the beginning of PREROUTING
	cmd = exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PROXYCTL_INTERCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to insert PREROUTING jump rule: %w", err)
	}

	// Save rules
	return m.saveIPTables()
}

// interceptPortsNFTables sets up nftables PREROUTING redirect rules
func (m *Manager) interceptPortsNFTables(fromInterface, bindInterface string, ports []int, bindPort int) error {
	// Note: redirect target doesn't need the bind IP, only the port
	// The kernel automatically determines the local IP to redirect to
	_ = bindInterface // Validated by caller, not needed for redirect

	// Build nftables config content
	var config strings.Builder
	config.WriteString("#!/usr/sbin/nft -f\n")
	config.WriteString("# HAProxy Port Interception - Transparent Egress Proxy\n")
	config.WriteString("# Redirects incoming traffic on specified ports to HAProxy\n\n")
	config.WriteString("table ip proxyctl_intercept {\n")
	config.WriteString("    chain prerouting {\n")
	config.WriteString("        type nat hook prerouting priority -100; policy accept;\n\n")
	config.WriteString(fmt.Sprintf("        # Redirect traffic from %s interface to HAProxy\n", fromInterface))

	// Add redirect rule for each port
	for _, port := range ports {
		config.WriteString(fmt.Sprintf("        iifname \"%s\" tcp dport %d redirect to :%d\n",
			fromInterface, port, bindPort))
	}

	config.WriteString("    }\n")
	config.WriteString("}\n")

	// Create nftables.d directory if needed
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create nftables.d directory: %w", err)
	}

	// Write config file
	configFile := "/etc/nftables.d/proxyctl_intercept.conf"
	if err := os.WriteFile(configFile, []byte(config.String()), 0644); err != nil {
		return fmt.Errorf("failed to write nftables config: %w", err)
	}

	// Load the configuration immediately
	cmd := exec.Command("nft", "-f", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nftables intercept config: %w (output: %s)", err, string(output))
	}

	// Ensure it's included in main nftables.conf
	if err := ensureNFTablesInclude(configFile); err != nil {
		return fmt.Errorf("failed to ensure nftables include: %w", err)
	}

	// Enable nftables service
	exec.Command("systemctl", "enable", "nftables").Run()

	return nil
}

// removeInterceptIPTables removes iptables PREROUTING intercept rules
func (m *Manager) removeInterceptIPTables() error {
	// Remove jump to PROXYCTL_INTERCEPT chain
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PROXYCTL_INTERCEPT").Run()

	// Flush and delete PROXYCTL_INTERCEPT chain
	exec.Command("iptables", "-t", "nat", "-F", "PROXYCTL_INTERCEPT").Run()
	exec.Command("iptables", "-t", "nat", "-X", "PROXYCTL_INTERCEPT").Run()

	// Save changes
	return m.saveIPTables()
}

// removeInterceptNFTables removes nftables PREROUTING intercept rules
func (m *Manager) removeInterceptNFTables() error {
	// Delete the table
	exec.Command("nft", "delete", "table", "ip", "proxyctl_intercept").Run()

	// Remove configuration file
	configFile := "/etc/nftables.d/proxyctl_intercept.conf"
	if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	// Remove include from main config
	if err := removeNFTablesInclude(configFile); err != nil {
		// Non-fatal - log but continue
		fmt.Printf("Warning: failed to remove include from nftables.conf: %v\n", err)
	}

	return nil
}

// GetInterceptStatus checks if port interception is enabled
func (m *Manager) GetInterceptStatus() (bool, error) {
	switch m.Type {
	case TypeIPTables:
		return m.getInterceptStatusIPTables()
	case TypeNFTables:
		return m.getInterceptStatusNFTables()
	default:
		return false, fmt.Errorf("unsupported firewall type: %s", m.Type)
	}
}

// getInterceptStatusIPTables checks if iptables intercept chain exists and has rules
func (m *Manager) getInterceptStatusIPTables() (bool, error) {
	cmd := exec.Command("iptables", "-t", "nat", "-L", "PROXYCTL_INTERCEPT", "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Chain doesn't exist
		return false, nil
	}

	// Check if chain has redirect rules
	return strings.Contains(string(output), "REDIRECT"), nil
}

// getInterceptStatusNFTables checks if nftables intercept table exists and has rules
func (m *Manager) getInterceptStatusNFTables() (bool, error) {
	cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_intercept")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Table doesn't exist
		return false, nil
	}

	// Check if table has redirect rules
	return strings.Contains(string(output), "redirect"), nil
}

// ensureNFTablesInclude ensures a config file is included in main nftables.conf
func ensureNFTablesInclude(configFile string) error {
	mainConf := "/etc/nftables.conf"
	includeLine := fmt.Sprintf(`include "%s"`, configFile)

	// Read main config
	data, err := os.ReadFile(mainConf)
	if err != nil {
		if os.IsNotExist(err) {
			// Create basic nftables.conf
			baseConfig := fmt.Sprintf(`#!/usr/sbin/nft -f

flush ruleset

%s
`, includeLine)
			return os.WriteFile(mainConf, []byte(baseConfig), 0755)
		}
		return fmt.Errorf("failed to read %s: %w", mainConf, err)
	}

	// Check if include already exists
	if strings.Contains(string(data), includeLine) {
		return nil
	}

	// Add include line
	lines := strings.Split(string(data), "\n")
	newLines := []string{}

	// Add after flush ruleset or at beginning
	added := false
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.Contains(line, "flush ruleset") && !added {
			newLines = append(newLines, "")
			newLines = append(newLines, includeLine)
			added = true
		}
	}

	// If not added after flush ruleset, add at end
	if !added {
		newLines = append(newLines, "")
		newLines = append(newLines, includeLine)
	}

	content := strings.Join(newLines, "\n")
	return os.WriteFile(mainConf, []byte(content), 0755)
}

// removeNFTablesInclude removes a config file include from main nftables.conf
func removeNFTablesInclude(configFile string) error {
	mainConf := "/etc/nftables.conf"
	includeLine := fmt.Sprintf(`include "%s"`, configFile)

	// Read main config
	data, err := os.ReadFile(mainConf)
	if err != nil {
		return err
	}

	// Split into lines
	lines := strings.Split(string(data), "\n")
	var newLines []string

	// Filter out the include line
	for _, line := range lines {
		if !strings.Contains(line, includeLine) {
			newLines = append(newLines, line)
		}
	}

	// Write back if something was removed
	if len(newLines) != len(lines) {
		content := strings.Join(newLines, "\n")
		return os.WriteFile(mainConf, []byte(content), 0755)
	}

	return nil
}

// getInterfaceIP gets the IPv4 address of a network interface
func getInterfaceIP(interfaceName string) (string, error) {
	cmd := exec.Command("ip", "-4", "addr", "show", interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w", err)
	}

	// Parse output to find inet address
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			// Extract IP address (format: "inet 10.0.1.5/24 ...")
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ipWithCIDR := parts[1]
				// Remove CIDR notation
				ip := strings.Split(ipWithCIDR, "/")[0]
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}
