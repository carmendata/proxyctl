package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// CheckChainExists checks if an iptables chain exists in a table
func (m *Manager) CheckChainExists(table, chain string) (bool, error) {
	if m.Type != TypeIPTables {
		return false, fmt.Errorf("CheckChainExists only works with iptables")
	}

	cmd := exec.Command("iptables", "-t", table, "-L", chain, "-n")
	err := cmd.Run()
	if err != nil {
		// Chain doesn't exist or other error
		return false, nil
	}
	return true, nil
}

// GetChainRuleCount returns the number of rules in an iptables chain
func (m *Manager) GetChainRuleCount(table, chain string) (int, error) {
	if m.Type != TypeIPTables {
		return 0, fmt.Errorf("GetChainRuleCount only works with iptables")
	}

	cmd := exec.Command("iptables", "-t", table, "-L", chain, "-n", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to list chain rules: %w", err)
	}

	// Count lines that start with a number (rule lines)
	count := 0
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		// Check if line starts with a digit (rule line)
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			count++
		}
	}

	return count, nil
}

// ListChainRules lists rules in an iptables chain (limited to N rules)
func (m *Manager) ListChainRules(table, chain string, limit int) ([]string, error) {
	if m.Type != TypeIPTables {
		return nil, fmt.Errorf("ListChainRules only works with iptables")
	}

	cmd := exec.Command("iptables", "-t", table, "-L", chain, "-n", "-v", "--line-numbers")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list chain rules: %w", err)
	}

	var rules []string
	lines := strings.Split(string(output), "\n")
	ruleCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// Check if line starts with a digit (rule line)
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			if ruleCount >= limit {
				break
			}
			rules = append(rules, line)
			ruleCount++
		}
	}

	return rules, nil
}

// CheckTableExists checks if an nftables table exists
func (m *Manager) CheckTableExists(family, table string) (bool, error) {
	if m.Type != TypeNFTables {
		return false, fmt.Errorf("CheckTableExists only works with nftables")
	}

	cmd := exec.Command("nft", "list", "table", family, table)
	err := cmd.Run()
	if err != nil {
		// Table doesn't exist or other error
		return false, nil
	}
	return true, nil
}

// ListTableChains lists chains in an nftables table
func (m *Manager) ListTableChains(family, table string) ([]string, error) {
	if m.Type != TypeNFTables {
		return nil, fmt.Errorf("ListTableChains only works with nftables")
	}

	cmd := exec.Command("nft", "list", "table", family, table)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list table: %w", err)
	}

	var chains []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for chain definitions: "chain NAME {"
		if strings.HasPrefix(line, "chain ") && strings.Contains(line, "{") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				chainName := parts[1]
				chains = append(chains, chainName)
			}
		}
	}

	return chains, nil
}

// ShowTableSummary shows a summary of an nftables table
func (m *Manager) ShowTableSummary(family, table string) error {
	if m.Type != TypeNFTables {
		return fmt.Errorf("ShowTableSummary only works with nftables")
	}

	cmd := exec.Command("nft", "list", "table", family, table)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list table: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	inChain := false
	chainName := ""
	ruleCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect chain start
		if strings.HasPrefix(trimmed, "chain ") && strings.Contains(trimmed, "{") {
			// Print previous chain summary if exists
			if inChain && chainName != "" {
				fmt.Printf("    %s: %d rules\n", chainName, ruleCount)
			}

			// Start new chain
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				chainName = parts[1]
				inChain = true
				ruleCount = 0
			}
		} else if inChain && trimmed == "}" {
			// End of chain
			if chainName != "" {
				fmt.Printf("    %s: %d rules\n", chainName, ruleCount)
			}
			inChain = false
			chainName = ""
			ruleCount = 0
		} else if inChain && len(trimmed) > 0 && !strings.HasPrefix(trimmed, "chain ") && trimmed != "{" && trimmed != "}" {
			// Count non-empty lines inside chain as rules
			// Skip lines that are just metadata (type, hook, priority, policy)
			if !strings.HasPrefix(trimmed, "type ") &&
				!strings.HasPrefix(trimmed, "hook ") &&
				!strings.HasPrefix(trimmed, "priority ") &&
				!strings.HasPrefix(trimmed, "policy ") {
				ruleCount++
			}
		}
	}

	// Print last chain if exists
	if inChain && chainName != "" {
		fmt.Printf("    %s: %d rules\n", chainName, ruleCount)
	}

	return nil
}

// GetIPTablesRuleSummary returns a formatted summary of iptables rules in a chain
func (m *Manager) GetIPTablesRuleSummary(table, chain string) (string, error) {
	if m.Type != TypeIPTables {
		return "", fmt.Errorf("GetIPTablesRuleSummary only works with iptables")
	}

	count, err := m.GetChainRuleCount(table, chain)
	if err != nil {
		return "", err
	}

	if count == 0 {
		return "No rules", nil
	}

	return fmt.Sprintf("%d rule(s)", count), nil
}

// GetNFTablesRuleSummary returns a formatted summary of nftables rules in a table
func (m *Manager) GetNFTablesRuleSummary(family, table string) (string, error) {
	if m.Type != TypeNFTables {
		return "", fmt.Errorf("GetNFTablesRuleSummary only works with nftables")
	}

	chains, err := m.ListTableChains(family, table)
	if err != nil {
		return "", err
	}

	if len(chains) == 0 {
		return "No chains", nil
	}

	return fmt.Sprintf("%d chain(s)", len(chains)), nil
}

// ShowDetailedChainRules shows detailed rules for an iptables chain
func (m *Manager) ShowDetailedChainRules(table, chain string, maxRules int) error {
	if m.Type != TypeIPTables {
		return fmt.Errorf("ShowDetailedChainRules only works with iptables")
	}

	rules, err := m.ListChainRules(table, chain, maxRules)
	if err != nil {
		return err
	}

	if len(rules) == 0 {
		fmt.Println("    No rules")
		return nil
	}

	for _, rule := range rules {
		fmt.Printf("    %s\n", rule)
	}

	count, _ := m.GetChainRuleCount(table, chain)
	if count > maxRules {
		fmt.Printf("    ... and %d more rule(s)\n", count-maxRules)
	}

	return nil
}
