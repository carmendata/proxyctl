package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// EnableIPForwarding enables IP forwarding via sysctl
func (m *Manager) EnableIPForwarding() error {
	// Check if already enabled
	cmd := exec.Command("sysctl", "-n", "net.ipv4.ip_forward")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "1" {
		// Already enabled
		return nil
	}

	// Enable IP forwarding
	cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Make it persistent by adding to /etc/sysctl.conf if not present
	return m.makeIPForwardingPersistent()
}

// DisableIPForwarding disables IP forwarding via sysctl
func (m *Manager) DisableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to disable IP forwarding: %w", err)
	}

	// Remove from /etc/sysctl.conf
	return m.removeIPForwardingFromSysctl()
}

// makeIPForwardingPersistent adds IP forwarding to /etc/sysctl.conf
func (m *Manager) makeIPForwardingPersistent() error {
	sysctlFile := "/etc/sysctl.conf"

	// Read current content
	content, err := os.ReadFile(sysctlFile)
	if err != nil {
		// File doesn't exist or can't read - that's ok, we'll check later
		return nil
	}

	// Check if already present
	if strings.Contains(string(content), "net.ipv4.ip_forward=1") ||
		strings.Contains(string(content), "net.ipv4.ip_forward = 1") {
		return nil // Already present
	}

	// Append to file
	f, err := os.OpenFile(sysctlFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't write, just log and continue - runtime setting worked
		return nil
	}
	defer f.Close()

	if _, err := f.WriteString("\n# Added by proxyctl for forwarding support\nnet.ipv4.ip_forward=1\n"); err != nil {
		return nil // Non-fatal
	}

	return nil
}

// removeIPForwardingFromSysctl removes IP forwarding from /etc/sysctl.conf
func (m *Manager) removeIPForwardingFromSysctl() error {
	sysctlFile := "/etc/sysctl.conf"

	content, err := os.ReadFile(sysctlFile)
	if err != nil {
		return nil // File doesn't exist - nothing to do
	}

	// Split into lines and filter out IP forwarding entries
	lines := strings.Split(string(content), "\n")
	var newLines []string
	skipNext := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip the comment line we added
		if trimmed == "# Added by proxyctl for forwarding support" {
			skipNext = true
			continue
		}

		// Skip IP forwarding lines
		if skipNext || strings.HasPrefix(trimmed, "net.ipv4.ip_forward") {
			skipNext = false
			continue
		}

		newLines = append(newLines, line)
	}

	// Write back
	newContent := strings.Join(newLines, "\n")
	return os.WriteFile(sysctlFile, []byte(newContent), 0644)
}

// ApplyForwardRules applies FORWARD chain rules and MASQUERADE
func (m *Manager) ApplyForwardRules(cfg *config.FirewallConfig) error {
	// Enable IP forwarding first
	if err := m.EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	switch m.Type {
	case TypeIPTables:
		return m.applyIPTablesForwardRules(cfg)
	case TypeNFTables:
		return m.applyNFTablesForwardRules(cfg)
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// RemoveForwardRules removes all FORWARD chain rules
func (m *Manager) RemoveForwardRules() error {
	switch m.Type {
	case TypeIPTables:
		return m.removeIPTablesForwardRules()
	case TypeNFTables:
		return m.removeNFTablesForwardRules()
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// applyNFTablesForwardRules creates nftables FORWARD rules
func (m *Manager) applyNFTablesForwardRules(cfg *config.FirewallConfig) error {
	// Determine policy (default: drop)
	policy := "drop"
	if cfg.ForwardPolicy != "" {
		policy = cfg.ForwardPolicy
	}

	// Build nftables configuration
	var nftConfig strings.Builder

	nftConfig.WriteString("#!/usr/sbin/nft -f\n")
	nftConfig.WriteString("# proxyctl FORWARD Rules\n")
	nftConfig.WriteString(fmt.Sprintf("# Generated: %s\n", "proxyctl"))
	nftConfig.WriteString("# Policy: " + policy + "\n\n")

	nftConfig.WriteString("table ip proxyctl_forward {\n")

	// FORWARD chain
	nftConfig.WriteString("    chain forward {\n")
	nftConfig.WriteString(fmt.Sprintf("        type filter hook forward priority 0; policy %s;\n\n", policy))

	// Allow established/related connections
	nftConfig.WriteString("        # Allow established/related connections\n")
	nftConfig.WriteString("        ct state established,related accept\n\n")

	// Add rules for each ForwardRule
	for i, rule := range cfg.AllowForwardFrom {
		nftConfig.WriteString(fmt.Sprintf("        # Rule %d", i+1))
		if rule.Comment != "" {
			nftConfig.WriteString(": " + rule.Comment)
		}
		nftConfig.WriteString("\n")

		// Build rules - each protocol needs its own rule
		for _, source := range rule.Sources {
			// If no protocols specified, create a single rule for all traffic
			if len(rule.Protocols) == 0 {
				ruleStr := fmt.Sprintf("        ip saddr %s", source)

				// Add destination match if specified
				if len(rule.Destinations) > 0 {
					for _, dest := range rule.Destinations {
						ruleStr += fmt.Sprintf(" ip daddr %s", dest)
					}
				}

				ruleStr += " accept\n"
				nftConfig.WriteString(ruleStr)
			} else {
				// Create a separate rule for each protocol
				for _, proto := range rule.Protocols {
					protoLower := strings.ToLower(proto)

					// For each destination (or once if no destinations)
					destinations := rule.Destinations
					if len(destinations) == 0 {
						destinations = []string{""}
					}

					for _, dest := range destinations {
						ruleStr := fmt.Sprintf("        ip saddr %s", source)

						if dest != "" {
							ruleStr += fmt.Sprintf(" ip daddr %s", dest)
						}

						// Add protocol match
						if (protoLower == "tcp" || protoLower == "udp") && len(rule.Ports) > 0 {
							// With ports, use implicit protocol match
							ruleStr += fmt.Sprintf(" %s", protoLower)
							portList := make([]string, len(rule.Ports))
							for j, port := range rule.Ports {
								portList[j] = fmt.Sprintf("%d", port)
							}
							ruleStr += fmt.Sprintf(" dport { %s }", strings.Join(portList, ", "))
						} else {
							// Without ports, use meta l4proto
							ruleStr += fmt.Sprintf(" meta l4proto %s", protoLower)
						}

						ruleStr += " accept\n"
						nftConfig.WriteString(ruleStr)
					}
				}
			}
		}

		nftConfig.WriteString("\n")
	}

	nftConfig.WriteString("    }\n\n")

	// POSTROUTING chain for MASQUERADE
	hasAnyMasquerade := false
	for _, rule := range cfg.AllowForwardFrom {
		if rule.Masquerade {
			hasAnyMasquerade = true
			break
		}
	}

	if hasAnyMasquerade {
		nftConfig.WriteString("    chain postrouting {\n")
		nftConfig.WriteString("        type nat hook postrouting priority 100; policy accept;\n\n")

		// Add MASQUERADE rules
		for i, rule := range cfg.AllowForwardFrom {
			if !rule.Masquerade {
				continue
			}

			nftConfig.WriteString(fmt.Sprintf("        # MASQUERADE for rule %d\n", i+1))
			for _, source := range rule.Sources {
				nftConfig.WriteString(fmt.Sprintf("        ip saddr %s oifname \"eth0\" masquerade\n", source))
			}
		}

		nftConfig.WriteString("    }\n")
	}

	nftConfig.WriteString("}\n")

	// Write to file
	forwardFile := "/etc/nftables.d/proxyctl-forward.nft"
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create nftables.d directory: %w", err)
	}

	if err := os.WriteFile(forwardFile, []byte(nftConfig.String()), 0644); err != nil {
		return fmt.Errorf("failed to write nftables config: %w", err)
	}

	// Add include to main config if not present
	if err := m.addNFTablesInclude(forwardFile); err != nil {
		return err
	}

	// Apply the rules
	cmd := exec.Command("nft", "-f", forwardFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// applyIPTablesForwardRules creates iptables FORWARD rules
func (m *Manager) applyIPTablesForwardRules(cfg *config.FirewallConfig) error {
	// Determine policy (default: drop)
	policy := "DROP"
	if cfg.ForwardPolicy == "accept" {
		policy = "ACCEPT"
	}

	// Create custom chain
	chainName := "PROXYCTL_FORWARD"
	exec.Command("iptables", "-N", chainName).Run() // Ignore error if exists

	// Flush existing rules
	if err := exec.Command("iptables", "-F", chainName).Run(); err != nil {
		return fmt.Errorf("failed to flush chain %s: %w", chainName, err)
	}

	// Set default FORWARD policy
	if err := exec.Command("iptables", "-P", "FORWARD", policy).Run(); err != nil {
		return fmt.Errorf("failed to set FORWARD policy: %w", err)
	}

	// Allow established/related connections
	cmd := exec.Command("iptables", "-A", chainName,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
		"-m", "comment", "--comment", "Allow established connections")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add established/related rule: %w", err)
	}

	// Add rules for each ForwardRule
	for i, rule := range cfg.AllowForwardFrom {
		for _, source := range rule.Sources {
			// Build rule arguments
			args := []string{"-A", chainName, "-s", source}

			// Add destination if specified
			if len(rule.Destinations) > 0 {
				for _, dest := range rule.Destinations {
					args = append(args, "-d", dest)
				}
			}

			// Add protocol if specified
			if len(rule.Protocols) > 0 {
				for _, proto := range rule.Protocols {
					args = append(args, "-p", strings.ToLower(proto))

					// Add ports if specified for TCP/UDP
					if (strings.ToLower(proto) == "tcp" || strings.ToLower(proto) == "udp") && len(rule.Ports) > 0 {
						portList := make([]string, len(rule.Ports))
						for j, port := range rule.Ports {
							portList[j] = fmt.Sprintf("%d", port)
						}
						args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
					}
				}
			}

			// Add accept and comment
			args = append(args, "-j", "ACCEPT")
			comment := fmt.Sprintf("Forward rule %d", i+1)
			if rule.Comment != "" {
				comment = rule.Comment
			}
			args = append(args, "-m", "comment", "--comment", comment)

			cmd := exec.Command("iptables", args...)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add forward rule: %w", err)
			}
		}
	}

	// Remove existing jump to chain and add at top
	exec.Command("iptables", "-D", "FORWARD", "-j", chainName).Run() // Ignore error
	if err := exec.Command("iptables", "-I", "FORWARD", "1", "-j", chainName).Run(); err != nil {
		return fmt.Errorf("failed to insert jump to %s: %w", chainName, err)
	}

	// Apply MASQUERADE rules
	for i, rule := range cfg.AllowForwardFrom {
		if !rule.Masquerade {
			continue
		}

		for _, source := range rule.Sources {
			// Remove existing rule if present
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
				"-s", source, "-o", "eth0", "-j", "MASQUERADE").Run()

			// Add MASQUERADE rule
			comment := fmt.Sprintf("MASQUERADE rule %d", i+1)
			cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
				"-s", source, "-o", "eth0", "-j", "MASQUERADE",
				"-m", "comment", "--comment", comment)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
			}
		}
	}

	// Save rules
	return m.saveIPTables()
}

// removeNFTablesForwardRules removes nftables FORWARD rules
func (m *Manager) removeNFTablesForwardRules() error {
	// Delete table
	exec.Command("nft", "delete", "table", "ip", "proxyctl_forward").Run() // Ignore error if doesn't exist

	// Remove configuration file
	os.Remove("/etc/nftables.d/proxyctl-forward.nft")

	// Remove include from main config
	m.removeNFTablesInclude("/etc/nftables.d/proxyctl-forward.nft")

	return nil
}

// removeIPTablesForwardRules removes iptables FORWARD rules
func (m *Manager) removeIPTablesForwardRules() error {
	chainName := "PROXYCTL_FORWARD"

	// Remove jump to chain
	exec.Command("iptables", "-D", "FORWARD", "-j", chainName).Run()

	// Flush and delete chain
	exec.Command("iptables", "-F", chainName).Run()
	exec.Command("iptables", "-X", chainName).Run()

	// Reset FORWARD policy to ACCEPT (default)
	exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()

	// Remove MASQUERADE rules (find and remove all with our comment)
	// This is a best-effort cleanup
	exec.Command("sh", "-c",
		"iptables -t nat -L POSTROUTING --line-numbers -n | grep 'MASQUERADE rule' | awk '{print $1}' | tac | xargs -r -I {} iptables -t nat -D POSTROUTING {}").Run()

	// Save rules
	return m.saveIPTables()
}

// Note: addNFTablesInclude, removeNFTablesInclude, and saveIPTables
// are already defined in input.go and firewall.go

// AreForwardRulesDeployed checks if FORWARD rules are currently deployed
func (m *Manager) AreForwardRulesDeployed() (bool, error) {
	switch m.Type {
	case TypeIPTables:
		// Check if PROXYCTL_FORWARD chain exists
		cmd := exec.Command("iptables", "-L", "PROXYCTL_FORWARD", "-n")
		err := cmd.Run()
		return err == nil, nil

	case TypeNFTables:
		// Check if proxyctl_forward table exists
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_forward")
		err := cmd.Run()
		return err == nil, nil

	default:
		return false, fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// CheckForwardRulesDrift checks if deployed rules match config
// Returns true if drift detected, false if matched
func (m *Manager) CheckForwardRulesDrift(cfg *config.FirewallConfig) (bool, error) {
	// For now, just check if rules are deployed
	// Full drift detection would require parsing and comparing rules
	// which is complex and can be implemented later
	deployed, err := m.AreForwardRulesDeployed()
	if err != nil {
		return false, err
	}

	// If config has rules but nothing deployed, that's drift
	if len(cfg.AllowForwardFrom) > 0 && !deployed {
		return true, nil
	}

	// If no config rules but something is deployed, that's also drift
	if len(cfg.AllowForwardFrom) == 0 && deployed {
		return true, nil
	}

	// More sophisticated drift detection could be added here
	// For now, assume no drift if basic checks pass
	return false, nil
}
