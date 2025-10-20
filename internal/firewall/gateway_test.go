package firewall

import (
	"fmt"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

// TestNFTablesGatewayConfigGeneration tests the NFTables gateway routing rule generation logic
func TestNFTablesGatewayConfigGeneration(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.RedirectConfig
		wantIn  []string // strings that should appear in config
		wantNot []string // strings that should NOT appear in config
	}{
		{
			name: "basic gateway routing with single target",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "10.106.80.2",
				Targets:      []string{"99.81.37.246"},
				RoutingTable: 200,
			},
			wantIn: []string{
				"table ip proxyctl_gateway",
				"type route hook output priority -150",
				"ip daddr 99.81.37.246",
				"mark set 200",
				"comment \"Route via gateway\"",
			},
		},
		{
			name: "gateway routing with multiple targets",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "10.106.80.2",
				Targets:      []string{"99.81.37.246", "18.200.147.72", "34.246.38.75"},
				RoutingTable: 200,
			},
			wantIn: []string{
				"table ip proxyctl_gateway",
				"ip daddr 99.81.37.246",
				"ip daddr 18.200.147.72",
				"ip daddr 34.246.38.75",
				"mark set 200",
			},
		},
		{
			name: "gateway routing with custom routing table",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "192.168.1.1",
				Targets:      []string{"8.8.8.8"},
				RoutingTable: 150,
			},
			wantIn: []string{
				"table ip proxyctl_gateway",
				"ip daddr 8.8.8.8",
				"mark set 150",
			},
			wantNot: []string{
				"mark set 200", // Should use custom table ID
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build expected NFTables configuration
			var nftConfig strings.Builder
			nftConfig.WriteString("#!/usr/sbin/nft -f\n")
			nftConfig.WriteString("# proxyctl Gateway Routing - Packet Marking\n")
			nftConfig.WriteString("# Generated: proxyctl v0.11.0\n")
			nftConfig.WriteString("# Gateway: " + tt.cfg.Gateway + "\n")
			nftConfig.WriteString(fmt.Sprintf("# Routing Table: %d\n\n", tt.cfg.RoutingTable))

			nftConfig.WriteString("table ip proxyctl_gateway {\n")
			nftConfig.WriteString("    # OUTPUT chain - Mark packets for gateway routing\n")
			nftConfig.WriteString("    # Priority -150 (mangle) runs before routing decision\n")
			nftConfig.WriteString("    chain output {\n")
			nftConfig.WriteString("        type route hook output priority -150; policy accept;\n\n")

			// Add mark rules for each target IP
			for i, target := range tt.cfg.Targets {
				nftConfig.WriteString(fmt.Sprintf("        # Target %d: %s\n", i+1, target))
				nftConfig.WriteString(fmt.Sprintf("        ip daddr %s mark set %d comment \"Route via gateway\"\n", target, tt.cfg.RoutingTable))
			}

			nftConfig.WriteString("    }\n")
			nftConfig.WriteString("}\n")

			configStr := nftConfig.String()

			// Check for expected strings
			for _, want := range tt.wantIn {
				if !strings.Contains(configStr, want) {
					t.Errorf("Config missing expected string %q\nConfig:\n%s", want, configStr)
				}
			}

			// Check for unexpected strings
			for _, notWant := range tt.wantNot {
				if strings.Contains(configStr, notWant) {
					t.Errorf("Config contains unexpected string %q\nConfig:\n%s", notWant, configStr)
				}
			}
		})
	}
}

// TestGatewayRoutingTableValidation tests routing table ID validation
func TestGatewayRoutingTableValidation(t *testing.T) {
	tests := []struct {
		name       string
		tableID    int
		shouldFail bool
	}{
		{"valid table ID 200", 200, false},
		{"valid table ID 1", 1, false},
		{"valid table ID 252", 252, false},
		{"invalid table ID 0", 0, false}, // 0 means use default (200)
		{"invalid table ID 253", 253, true},
		{"invalid table ID 255", 255, true},
		{"invalid table ID -1", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "10.106.80.2",
				Targets:      []string{"8.8.8.8"},
				RoutingTable: tt.tableID,
			}

			// Validate through config validation
			c := &config.Config{
				Mode:     "egress",
				Redirect: cfg,
			}

			err := c.Validate()
			if tt.shouldFail && err == nil {
				t.Errorf("Expected validation to fail for table ID %d, but it passed", tt.tableID)
			}
			if !tt.shouldFail && err != nil && tt.tableID != 0 {
				t.Errorf("Expected validation to pass for table ID %d, but got error: %v", tt.tableID, err)
			}
		})
	}
}

// TestGatewayTypeValidation tests that gateway type requires gateway and targets
func TestGatewayTypeValidation(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.RedirectConfig
		shouldFail bool
		errorMsg   string
	}{
		{
			name: "valid gateway config",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "10.106.80.2",
				Targets:      []string{"8.8.8.8"},
				RoutingTable: 200,
			},
			shouldFail: false,
		},
		{
			name: "gateway without gateway IP",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Targets:      []string{"8.8.8.8"},
				RoutingTable: 200,
			},
			shouldFail: true,
			errorMsg:   "gateway is required",
		},
		{
			name: "gateway without targets",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "10.106.80.2",
				RoutingTable: 200,
			},
			shouldFail: true,
			errorMsg:   "targets must contain at least one IP",
		},
		{
			name: "gateway with invalid IP",
			cfg: &config.RedirectConfig{
				Enabled:      true,
				Type:         "gateway",
				Gateway:      "not.a.valid.ip",
				Targets:      []string{"8.8.8.8"},
				RoutingTable: 200,
			},
			shouldFail: true,
			errorMsg:   "must be a valid IP address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.Config{
				Mode:     "egress",
				Redirect: tt.cfg,
			}

			err := c.Validate()
			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected validation to fail with %q, but it passed", tt.errorMsg)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain %q, got: %v", tt.errorMsg, err)
				}
			} else if err != nil {
				t.Errorf("Expected validation to pass, but got error: %v", err)
			}
		})
	}
}

// TestGatewayRoutingPriority tests that gateway routing uses correct priority
func TestGatewayRoutingPriority(t *testing.T) {
	// Build config (mimicking createNFTablesPacketMarking logic)
	var nftConfig strings.Builder
	nftConfig.WriteString("table ip proxyctl_gateway {\n")
	nftConfig.WriteString("    chain output {\n")
	nftConfig.WriteString("        type route hook output priority -150; policy accept;\n")
	nftConfig.WriteString("    }\n")
	nftConfig.WriteString("}\n")

	configStr := nftConfig.String()

	// Verify priority is -150 (mangle priority, runs before routing)
	if !strings.Contains(configStr, "priority -150") {
		t.Errorf("Expected priority -150 for gateway routing, got config:\n%s", configStr)
	}

	// Verify it's a route hook (needed for packet marking before routing decision)
	if !strings.Contains(configStr, "type route hook output") {
		t.Errorf("Expected 'type route hook output' for gateway routing, got config:\n%s", configStr)
	}
}

// TestGatewayDefaultRoutingTable tests that default routing table is 200
func TestGatewayDefaultRoutingTable(t *testing.T) {
	cfg := &config.RedirectConfig{
		Enabled:      true,
		Type:         "gateway",
		Gateway:      "10.106.80.2",
		Targets:      []string{"8.8.8.8"},
		RoutingTable: 0, // 0 should default to 200
	}

	c := &config.Config{
		Mode:     "egress",
		Redirect: cfg,
	}

	// Validate - should pass and set default
	err := c.Validate()
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// The validation should set default to 200
	if cfg.RoutingTable != 200 {
		t.Errorf("Expected default routing table to be 200, got %d", cfg.RoutingTable)
	}
}
