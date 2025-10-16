package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// ApplyInputFiltering applies INPUT filtering rules based on firewall configuration
// Creates PROXYCTL_INPUT chain (iptables) or proxyctl_filter table (nftables)
// Rules are applied at highest priority to be evaluated first
//
// IMPORTANT: INPUT filtering is used on egress proxy servers, which require HAProxy.
// This function will automatically install HAProxy if not present.
func (m *Manager) ApplyInputFiltering(cfg *config.FirewallConfig) error {
	// INPUT filtering is for egress proxy servers - they need HAProxy
	// Detect and install HAProxy if missing
	fmt.Println("Checking HAProxy installation (required for egress proxy)...")
	if err := EnsureHAProxy(); err != nil {
		return fmt.Errorf("cannot apply INPUT filtering: HAProxy is required for egress proxy servers\n\n"+
			"Failed to install HAProxy: %w\n\n"+
			"SOLUTION:\n"+
			"  Install HAProxy manually:\n"+
			"    Ubuntu/Debian: sudo apt-get install -y haproxy\n"+
			"    RHEL/CentOS:   sudo dnf install -y haproxy\n\n"+
			"  Then run this command again.", err)
	}
	fmt.Println("✓ HAProxy is installed")

	switch m.Type {
	case TypeIPTables:
		return m.applyInputFilteringIPTables(cfg)
	case TypeNFTables:
		return m.applyInputFilteringNFTables(cfg)
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// RemoveInputFiltering removes all proxyctl INPUT filtering rules
func (m *Manager) RemoveInputFiltering() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeInputFilteringIPTables()
	case TypeNFTables:
		return m.removeInputFilteringNFTables()
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// applyInputFilteringIPTables creates PROXYCTL_INPUT chain with iptables
func (m *Manager) applyInputFilteringIPTables(cfg *config.FirewallConfig) error {
	// Create custom chain for proxyctl INPUT rules
	cmd := exec.Command("iptables", "-N", "PROXYCTL_INPUT")
	cmd.Run() // Ignore error if chain already exists

	// Flush existing rules in PROXYCTL_INPUT chain
	if err := exec.Command("iptables", "-F", "PROXYCTL_INPUT").Run(); err != nil {
		return fmt.Errorf("failed to flush PROXYCTL_INPUT chain: %w", err)
	}

	// Allow loopback traffic (always allowed)
	cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT", "-i", "lo", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add loopback rule: %w", err)
	}

	// Allow established and related connections (always allowed)
	cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add established connections rule: %w", err)
	}

	// Add SSH allow rules
	for _, ip := range cfg.AllowSSHFrom {
		cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT",
			"-s", ip, "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add SSH rule for %s: %w", ip, err)
		}
	}

	// Add proxy allow rules
	for _, rule := range cfg.AllowProxyFrom {
		for _, source := range rule.Sources {
			if len(rule.Ports) == 0 {
				// No ports specified - allow all ports from this source
				cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT",
					"-s", source, "-j", "ACCEPT")
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to add allow-all rule for %s: %w", source, err)
				}
			} else {
				// Specific ports specified
				for _, port := range rule.Ports {
					cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT",
						"-s", source, "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT")
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to add port %d rule for %s: %w", port, source, err)
					}
				}
			}
		}
	}

	// Add final rule based on input_policy
	switch cfg.InputPolicy {
	case "drop":
		// Silently drop unmatched traffic
		cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT", "-j", "DROP")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add DROP rule: %w", err)
		}
	case "block":
		// Reject with ICMP response
		cmd = exec.Command("iptables", "-A", "PROXYCTL_INPUT",
			"-j", "REJECT", "--reject-with", "icmp-host-prohibited")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add REJECT rule: %w", err)
		}
	case "ignore":
		// No final rule - return to INPUT chain for other rules to process
		// This is intentional - do nothing
	default:
		return fmt.Errorf("invalid input_policy: %s (must be 'drop', 'block', or 'ignore')", cfg.InputPolicy)
	}

	// Remove existing jump to PROXYCTL_INPUT if it exists (idempotent)
	exec.Command("iptables", "-D", "INPUT", "-j", "PROXYCTL_INPUT").Run()

	// Insert jump to our custom chain at position 1 (highest priority)
	cmd = exec.Command("iptables", "-I", "INPUT", "1", "-j", "PROXYCTL_INPUT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to insert jump rule at position 1: %w", err)
	}

	// Save rules
	return m.saveIPTables()
}

// applyInputFilteringNFTables creates proxyctl_filter table with nftables
func (m *Manager) applyInputFilteringNFTables(cfg *config.FirewallConfig) error {
	// Build nftables configuration
	var config strings.Builder

	config.WriteString("# proxyctl INPUT Filtering Rules\n")
	config.WriteString("# Created by proxyctl for egress proxy security\n")
	config.WriteString("# Priority: -1 (highest - processed before other rules)\n\n")

	config.WriteString("table inet proxyctl_filter {\n")
	config.WriteString("    chain input {\n")
	config.WriteString("        type filter hook input priority -1; policy accept;\n\n")

	// Allow loopback (always)
	config.WriteString("        # Allow loopback traffic\n")
	config.WriteString("        iif lo accept\n\n")

	// Allow established and related connections (always)
	config.WriteString("        # Allow established and related connections\n")
	config.WriteString("        ct state established,related accept\n\n")

	// Add SSH allow rules
	if len(cfg.AllowSSHFrom) > 0 {
		config.WriteString("        # Allow SSH from trusted IPs\n")
		for _, ip := range cfg.AllowSSHFrom {
			config.WriteString(fmt.Sprintf("        ip saddr %s tcp dport 22 accept\n", ip))
		}
		config.WriteString("\n")
	}

	// Add proxy allow rules
	if len(cfg.AllowProxyFrom) > 0 {
		config.WriteString("        # Allow proxy ports from worker IPs\n")
		for _, rule := range cfg.AllowProxyFrom {
			for _, source := range rule.Sources {
				if len(rule.Ports) == 0 {
					// No ports specified - allow all ports
					config.WriteString(fmt.Sprintf("        ip saddr %s accept\n", source))
				} else {
					// Specific ports
					for _, port := range rule.Ports {
						config.WriteString(fmt.Sprintf("        ip saddr %s tcp dport %d accept\n", source, port))
					}
				}
			}
		}
		config.WriteString("\n")
	}

	// Add final rule based on input_policy
	switch cfg.InputPolicy {
	case "drop":
		config.WriteString("        # Drop all other traffic (strict mode)\n")
		config.WriteString("        drop\n")
	case "block":
		config.WriteString("        # Reject all other traffic with ICMP response (strict + informative mode)\n")
		config.WriteString("        reject with icmp type host-prohibited\n")
	case "ignore":
		config.WriteString("        # No final rule - continue to next priority chain (coexistence mode)\n")
		config.WriteString("        # Other firewall rules will be evaluated\n")
	default:
		return fmt.Errorf("invalid input_policy: %s (must be 'drop', 'block', or 'ignore')", cfg.InputPolicy)
	}

	config.WriteString("    }\n")
	config.WriteString("}\n")

	// Create nftables.d directory if needed
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/nftables.d: %w", err)
	}

	// Write configuration file
	configPath := "/etc/nftables.d/proxyctl-filter.nft"
	if err := os.WriteFile(configPath, []byte(config.String()), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	// Delete existing table to make idempotent (ignore error if doesn't exist)
	exec.Command("nft", "delete", "table", "inet", "proxyctl_filter").Run()

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

// removeInputFilteringIPTables removes PROXYCTL_INPUT chain
func (m *Manager) removeInputFilteringIPTables() error {
	// Remove jump to PROXYCTL_INPUT chain
	exec.Command("iptables", "-D", "INPUT", "-j", "PROXYCTL_INPUT").Run()

	// Flush and delete PROXYCTL_INPUT chain
	exec.Command("iptables", "-F", "PROXYCTL_INPUT").Run()
	exec.Command("iptables", "-X", "PROXYCTL_INPUT").Run()

	// Save changes
	return m.saveIPTables()
}

// removeInputFilteringNFTables removes proxyctl_filter table
func (m *Manager) removeInputFilteringNFTables() error {
	// Remove table
	exec.Command("nft", "delete", "table", "inet", "proxyctl_filter").Run()

	// Remove configuration file
	os.Remove("/etc/nftables.d/proxyctl-filter.nft")

	// Remove include from main config
	if err := m.removeNFTablesInclude("/etc/nftables.d/proxyctl-filter.nft"); err != nil {
		// Non-fatal error - log but continue
		fmt.Printf("Warning: could not remove include from nftables.conf: %v\n", err)
	}

	return nil
}

// addNFTablesInclude adds an include directive to nftables.conf if not present
func (m *Manager) addNFTablesInclude(configPath string) error {
	mainConfPath := "/etc/nftables.conf"

	// Read main config, create if missing
	content, err := os.ReadFile(mainConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create basic permissive nftables.conf
			baseConfig := `#!/usr/sbin/nft -f
# nftables configuration - created by proxyctl
# Base config with permissive policies (accept all by default)

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
			if err := os.WriteFile(mainConfPath, []byte(baseConfig), 0644); err != nil {
				return fmt.Errorf("failed to create %s: %w", mainConfPath, err)
			}
			content = []byte(baseConfig)
		} else {
			return fmt.Errorf("failed to read %s: %w", mainConfPath, err)
		}
	}

	includeLine := fmt.Sprintf(`include "%s"`, configPath)

	// Check if already included
	if strings.Contains(string(content), includeLine) {
		return nil // Already present
	}

	// Append include directive
	f, err := os.OpenFile(mainConfPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", mainConfPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + includeLine + "\n"); err != nil {
		return fmt.Errorf("failed to write to %s: %w", mainConfPath, err)
	}

	return nil
}

// removeNFTablesInclude removes an include directive from nftables.conf
func (m *Manager) removeNFTablesInclude(configPath string) error {
	mainConfPath := "/etc/nftables.conf"

	// Read the file
	content, err := os.ReadFile(mainConfPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", mainConfPath, err)
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")
	var newLines []string
	includeLine := fmt.Sprintf(`include "%s"`, configPath)

	// Filter out the include line
	for _, line := range lines {
		if !strings.Contains(line, includeLine) {
			newLines = append(newLines, line)
		}
	}

	// Write back if something was removed
	if len(newLines) != len(lines) {
		newContent := strings.Join(newLines, "\n")
		return os.WriteFile(mainConfPath, []byte(newContent), 0644)
	}

	return nil
}

// CheckInputFilteringPriorityConflict checks if highest priority is already taken by non-proxyctl rules
// Returns error if conflict detected, nil if safe to proceed
func (m *Manager) CheckInputFilteringPriorityConflict() error {
	switch m.Type {
	case TypeIPTables:
		return m.checkIPTablesInputPriorityConflict()
	case TypeNFTables:
		return m.checkNFTablesInputPriorityConflict()
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// checkIPTablesInputPriorityConflict checks if position 1 in INPUT chain is available
func (m *Manager) checkIPTablesInputPriorityConflict() error {
	// List INPUT chain with line numbers
	cmd := exec.Command("iptables", "-L", "INPUT", "-n", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list INPUT chain: %w", err)
	}

	lines := strings.Split(string(output), "\n")

	// Skip header lines (first 2 lines)
	if len(lines) < 3 {
		// No rules exist - safe to proceed
		return nil
	}

	// Check line 3 (first rule, position 1)
	firstRule := strings.TrimSpace(lines[2])

	// If no rule at position 1, safe to proceed
	if firstRule == "" {
		return nil
	}

	// Check if first rule is our jump to PROXYCTL_INPUT
	if strings.Contains(firstRule, "PROXYCTL_INPUT") {
		// Our rule is already at position 1 - safe to reapply
		return nil
	}

	// Position 1 is taken by something else - conflict!
	return fmt.Errorf("cannot apply INPUT filtering: position 1 in INPUT chain is already taken by non-proxyctl rules.\n\n"+
		"First rule in INPUT chain:\n  %s\n\n"+
		"proxyctl requires the highest priority (position 1) to ensure rules are processed first.\n\n"+
		"Options:\n"+
		"  1. Remove conflicting rules at position 1\n"+
		"  2. Change input_policy to 'ignore' in config (proxyctl rules will be lower priority)\n"+
		"  3. If rules are managed by Docker/other tool, consider using input_policy: 'ignore'",
		firstRule)
}

// checkNFTablesInputPriorityConflict checks if priority < 0 is available for input hook
func (m *Manager) checkNFTablesInputPriorityConflict() error {
	// List all input hooks with their priorities
	cmd := exec.Command("nft", "list", "chains", "inet")
	output, err := cmd.Output()
	if err != nil {
		// If nft command fails, assume no conflicts
		return nil
	}

	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for input hook chains
		if !strings.Contains(line, "type filter hook input") {
			continue
		}

		// Check if this is our proxyctl_filter table
		// We need to look at context, but a simple check is if line contains "proxyctl"
		// For now, parse priority from the line
		if strings.Contains(line, "priority -") {
			// Extract priority value
			// Format: "type filter hook input priority -X; policy accept;"
			if !strings.Contains(line, "priority -1") {
				// There's a chain with priority < -1 (higher than ours)
				// But only error if it's not our chain (in a table named proxyctl_filter)
				// This is a simplified check - in practice we'd need better parsing
				return fmt.Errorf("cannot apply INPUT filtering: detected input hook chain with priority < 0 that is not managed by proxyctl.\n\n"+
					"Chain found:\n  %s\n\n"+
					"proxyctl requires the highest priority (-1) to ensure rules are processed first.\n\n"+
					"Options:\n"+
					"  1. Remove conflicting nftables tables/chains with priority < 0\n"+
					"  2. Change input_policy to 'ignore' in config (accept lower priority)\n"+
					"  3. If rules are managed by another tool, consider using input_policy: 'ignore'",
					line)
			}
			// Priority -1 found - if it's our table, that's fine (reapplication)
			// We'll allow it and let the apply operation handle it
		}
	}

	// No conflicts found
	return nil
}
