package firewall

import (
	"os/exec"
	"testing"
)

// TestCheckChainExists tests the CheckChainExists function
func TestCheckChainExists(t *testing.T) {
	// Skip if iptables not available
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}

	m := &Manager{Type: TypeIPTables}

	// Test with a chain that should always exist (INPUT in filter table)
	exists, err := m.CheckChainExists("filter", "INPUT")
	if err != nil {
		t.Fatalf("CheckChainExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected INPUT chain to exist in filter table")
	}

	// Test with a chain that likely doesn't exist
	exists, err = m.CheckChainExists("filter", "NONEXISTENT_CHAIN_TEST_12345")
	if err != nil {
		t.Fatalf("CheckChainExists failed: %v", err)
	}
	if exists {
		t.Error("Expected nonexistent chain to not exist")
	}

	// Test with wrong firewall type
	m.Type = TypeNFTables
	_, err = m.CheckChainExists("filter", "INPUT")
	if err == nil {
		t.Error("Expected error when using CheckChainExists with nftables")
	}
}

// TestGetChainRuleCount tests the GetChainRuleCount function
func TestGetChainRuleCount(t *testing.T) {
	// Skip if iptables not available
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}

	m := &Manager{Type: TypeIPTables}

	// Test with INPUT chain (should have some rules or 0)
	count, err := m.GetChainRuleCount("filter", "INPUT")
	if err != nil {
		t.Fatalf("GetChainRuleCount failed: %v", err)
	}
	if count < 0 {
		t.Errorf("Expected non-negative rule count, got %d", count)
	}

	// Test with wrong firewall type
	m.Type = TypeNFTables
	_, err = m.GetChainRuleCount("filter", "INPUT")
	if err == nil {
		t.Error("Expected error when using GetChainRuleCount with nftables")
	}
}

// TestListChainRules tests the ListChainRules function
func TestListChainRules(t *testing.T) {
	// Skip if iptables not available
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}

	m := &Manager{Type: TypeIPTables}

	// Test listing rules with a limit
	rules, err := m.ListChainRules("filter", "INPUT", 5)
	if err != nil {
		t.Fatalf("ListChainRules failed: %v", err)
	}

	// Rules can be empty or have content
	if len(rules) > 5 {
		t.Errorf("Expected at most 5 rules, got %d", len(rules))
	}

	// Test with wrong firewall type
	m.Type = TypeNFTables
	_, err = m.ListChainRules("filter", "INPUT", 5)
	if err == nil {
		t.Error("Expected error when using ListChainRules with nftables")
	}
}

// TestCheckTableExists tests the CheckTableExists function
func TestCheckTableExists(t *testing.T) {
	// Skip if nft not available
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}

	m := &Manager{Type: TypeNFTables}

	// We can't reliably test for specific tables as they may not exist
	// Just test that the function doesn't crash
	_, err := m.CheckTableExists("ip", "nonexistent_table_test_12345")
	if err != nil {
		// Some systems may return error for nonexistent tables, that's ok
		t.Logf("CheckTableExists returned error: %v", err)
	}

	// Test with wrong firewall type
	m.Type = TypeIPTables
	_, err = m.CheckTableExists("ip", "filter")
	if err == nil {
		t.Error("Expected error when using CheckTableExists with iptables")
	}
}

// TestListTableChains tests the ListTableChains function
func TestListTableChains(t *testing.T) {
	// Skip if nft not available
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}

	m := &Manager{Type: TypeNFTables}

	// Test with a nonexistent table (should return error)
	_, err := m.ListTableChains("ip", "nonexistent_table_test_12345")
	if err == nil {
		t.Log("ListTableChains succeeded for nonexistent table (may be expected)")
	}

	// Test with wrong firewall type
	m.Type = TypeIPTables
	_, err = m.ListTableChains("ip", "filter")
	if err == nil {
		t.Error("Expected error when using ListTableChains with iptables")
	}
}

// TestShowTableSummary tests the ShowTableSummary function
func TestShowTableSummary(t *testing.T) {
	// Skip if nft not available
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}

	m := &Manager{Type: TypeNFTables}

	// Test with a nonexistent table (should return error)
	err := m.ShowTableSummary("ip", "nonexistent_table_test_12345")
	if err == nil {
		t.Log("ShowTableSummary succeeded for nonexistent table (may be expected)")
	}

	// Test with wrong firewall type
	m.Type = TypeIPTables
	err = m.ShowTableSummary("ip", "filter")
	if err == nil {
		t.Error("Expected error when using ShowTableSummary with iptables")
	}
}

// TestGetIPTablesRuleSummary tests the GetIPTablesRuleSummary function
func TestGetIPTablesRuleSummary(t *testing.T) {
	// Skip if iptables not available
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}

	m := &Manager{Type: TypeIPTables}

	// Test with INPUT chain
	summary, err := m.GetIPTablesRuleSummary("filter", "INPUT")
	if err != nil {
		t.Fatalf("GetIPTablesRuleSummary failed: %v", err)
	}
	if summary == "" {
		t.Error("Expected non-empty summary")
	}

	// Test with wrong firewall type
	m.Type = TypeNFTables
	_, err = m.GetIPTablesRuleSummary("filter", "INPUT")
	if err == nil {
		t.Error("Expected error when using GetIPTablesRuleSummary with nftables")
	}
}

// TestGetNFTablesRuleSummary tests the GetNFTablesRuleSummary function
func TestGetNFTablesRuleSummary(t *testing.T) {
	// Skip if nft not available
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not available")
	}

	m := &Manager{Type: TypeNFTables}

	// Test with a nonexistent table
	_, err := m.GetNFTablesRuleSummary("ip", "nonexistent_table_test_12345")
	if err == nil {
		t.Log("GetNFTablesRuleSummary succeeded for nonexistent table (may be expected)")
	}

	// Test with wrong firewall type
	m.Type = TypeIPTables
	_, err = m.GetNFTablesRuleSummary("ip", "filter")
	if err == nil {
		t.Error("Expected error when using GetNFTablesRuleSummary with iptables")
	}
}

// TestShowDetailedChainRules tests the ShowDetailedChainRules function
func TestShowDetailedChainRules(t *testing.T) {
	// Skip if iptables not available
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables not available")
	}

	m := &Manager{Type: TypeIPTables}

	// Test with INPUT chain (just ensure it doesn't crash)
	err := m.ShowDetailedChainRules("filter", "INPUT", 3)
	if err != nil {
		t.Fatalf("ShowDetailedChainRules failed: %v", err)
	}

	// Test with wrong firewall type
	m.Type = TypeNFTables
	err = m.ShowDetailedChainRules("filter", "INPUT", 3)
	if err == nil {
		t.Error("Expected error when using ShowDetailedChainRules with nftables")
	}
}
