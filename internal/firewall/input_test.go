package firewall

import (
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

// NOTE: V1 tests have been removed during V2 migration.
// These tests need to be rewritten to test the V2 rules-based firewall implementation.
//
// TODO: Add comprehensive tests for:
// - applyInputFilteringIPTables with various rule configurations
// - applyInputFilteringNFTables with various rule configurations
// - Default policy handling (drop, block, accept)
// - Multiple rules with different protocols and ports
// - Edge cases and error conditions
//
// The V2 firewall implementation uses a Rules[] array instead of simple
// AllowSSHFrom/AllowProxyFrom fields, requiring different test strategies.

// TestInputFiltering_Placeholder is a placeholder test to prevent "no tests" errors
func TestInputFiltering_Placeholder(t *testing.T) {
	// Basic sanity check that FirewallConfig validation works with V2 schema
	cfg := &config.FirewallConfig{
		Enabled:       true,
		DefaultPolicy: "drop",
		Rules: []config.FirewallRule{
			{
				Name:      "allow-ssh",
				Interface: "public",
				Sources:   []string{"203.0.113.50"},
				Protocol:  "tcp",
				Ports:     []int{22},
				Action:    "accept",
			},
		},
	}

	interfaces := config.InterfacesConfig{
		"public": "eth0",
	}

	err := cfg.Validate(interfaces)
	if err != nil {
		t.Errorf("Expected valid config to pass validation, got error: %v", err)
	}
}

// TestInputPolicy_Validation tests default policy validation
func TestInputPolicy_Validation(t *testing.T) {
	interfaces := config.InterfacesConfig{
		"public": "eth0",
	}

	tests := []struct {
		name          string
		defaultPolicy string
		wantErr       bool
	}{
		{"valid drop policy", "drop", false},
		{"valid block policy", "block", false},
		{"valid accept policy", "accept", false},
		{"invalid policy", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.FirewallConfig{
				Enabled:       true,
				DefaultPolicy: tt.defaultPolicy,
			}

			err := cfg.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
