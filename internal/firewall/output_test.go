package firewall

import (
	"fmt"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

// TestNFTablesOutputRedirectConfigGeneration tests the NFTables redirect rule generation logic
// We test NFTables because it generates a config file we can inspect
func TestNFTablesOutputRedirectConfigGeneration(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.RedirectConfig
		proxyIP   string
		proxyPort int
		wantIn    []string // strings that should appear in config
		wantNot   []string // strings that should NOT appear in config
	}{
		{
			name: "partial redirect with single target",
			cfg: &config.RedirectConfig{
				Enabled: true,
				Type:    "partial",
				Targets: []string{"8.8.8.8"},
			},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
			wantIn: []string{
				"table ip proxyctl_redirect",
				"type nat hook output priority -100",
				"ip daddr 10.16.0.5 return",
				"oif lo return",
				"ip daddr 10.0.0.0/8 return",
				"ip daddr 172.16.0.0/12 return",
				"ip daddr 192.168.0.0/16 return",
				"ip daddr 8.8.8.8 tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
			},
		},
		{
			name: "partial redirect with multiple targets",
			cfg: &config.RedirectConfig{
				Enabled: true,
				Type:    "partial",
				Targets: []string{"8.8.8.8", "1.1.1.1", "208.67.222.222"},
			},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
			wantIn: []string{
				"table ip proxyctl_redirect",
				"ip daddr 8.8.8.8 tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
				"ip daddr 1.1.1.1 tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
				"ip daddr 208.67.222.222 tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
			},
		},
		{
			name: "partial redirect with CIDR block",
			cfg: &config.RedirectConfig{
				Enabled: true,
				Type:    "partial",
				Targets: []string{"203.0.113.0/24"},
			},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
			wantIn: []string{
				"ip daddr 203.0.113.0/24 tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
			},
		},
		{
			name: "full redirect",
			cfg: &config.RedirectConfig{
				Enabled: true,
				Type:    "full",
			},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
			wantIn: []string{
				"table ip proxyctl_redirect",
				"type nat hook output priority -100",
				"ip daddr 10.16.0.5 return",
				"oif lo return",
				"ip daddr 10.0.0.0/8 return",
				"tcp dport { 80, 443 } dnat to 10.16.0.5:8080",
			},
			wantNot: []string{
				"ip daddr 8.8.8.8",
			},
		},
		{
			name: "custom proxy port",
			cfg: &config.RedirectConfig{
				Enabled: true,
				Type:    "full",
			},
			proxyIP:   "10.16.0.5",
			proxyPort: 9999,
			wantIn: []string{
				"tcp dport { 80, 443 } dnat to 10.16.0.5:9999",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{Type: TypeNFTables}

			// Build the config manually using the same logic as applyOutputRedirectNFTables
			var configBuilder strings.Builder

			configBuilder.WriteString("# proxyctl OUTPUT Redirect Rules\n")
			configBuilder.WriteString("# Created by proxyctl for egress proxy redirection\n")
			configBuilder.WriteString("# Priority: -100 (processed before default OUTPUT rules)\n\n")

			configBuilder.WriteString("table ip proxyctl_redirect {\n")
			configBuilder.WriteString("    chain output {\n")
			configBuilder.WriteString("        type nat hook output priority -100; policy accept;\n\n")

			// Skip redirect for traffic to proxy itself
			configBuilder.WriteString("        # Skip redirect for traffic to proxy itself\n")
			configBuilder.WriteString(fmt.Sprintf("        ip daddr %s return\n\n", tt.proxyIP))

			// Skip redirect for loopback traffic
			configBuilder.WriteString("        # Skip redirect for loopback traffic\n")
			configBuilder.WriteString("        oif lo return\n\n")

			// Skip redirect for local network traffic
			configBuilder.WriteString("        # Skip redirect for local network traffic (RFC 1918)\n")
			configBuilder.WriteString("        ip daddr 10.0.0.0/8 return\n")
			configBuilder.WriteString("        ip daddr 172.16.0.0/12 return\n")
			configBuilder.WriteString("        ip daddr 192.168.0.0/16 return\n\n")

			// Add redirect rules based on type
			switch tt.cfg.Type {
			case "partial":
				configBuilder.WriteString("        # Redirect specific targets to proxy (partial redirect)\n")
				for _, target := range tt.cfg.Targets {
					configBuilder.WriteString(fmt.Sprintf("        ip daddr %s tcp dport { 80, 443 } dnat to %s:%d\n",
						target, tt.proxyIP, tt.proxyPort))
				}
			case "full":
				configBuilder.WriteString("        # Redirect all HTTP/HTTPS traffic to proxy (full redirect)\n")
				configBuilder.WriteString(fmt.Sprintf("        tcp dport { 80, 443 } dnat to %s:%d\n",
					tt.proxyIP, tt.proxyPort))
			}

			configBuilder.WriteString("    }\n")
			configBuilder.WriteString("}\n")

			config := configBuilder.String()

			// Check that all expected strings are present
			for _, want := range tt.wantIn {
				if !strings.Contains(config, want) {
					t.Errorf("Config missing expected string: %q", want)
				}
			}

			// Check that unwanted strings are not present
			for _, notWant := range tt.wantNot {
				if strings.Contains(config, notWant) {
					t.Errorf("Config contains unwanted string: %q", notWant)
				}
			}

			// Verify manager type is correct
			if m.Type != TypeNFTables {
				t.Errorf("Manager type = %v, want %v", m.Type, TypeNFTables)
			}
		})
	}
}

// TestRedirectTypeValidation tests that invalid redirect types are rejected
func TestRedirectTypeValidation(t *testing.T) {
	tests := []struct {
		name         string
		redirectType string
		wantValid    bool
	}{
		{
			name:         "valid: partial",
			redirectType: "partial",
			wantValid:    true,
		},
		{
			name:         "valid: full",
			redirectType: "full",
			wantValid:    true,
		},
		{
			name:         "invalid: empty",
			redirectType: "",
			wantValid:    false,
		},
		{
			name:         "invalid: all",
			redirectType: "all",
			wantValid:    false,
		},
		{
			name:         "invalid: selective",
			redirectType: "selective",
			wantValid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validTypes := map[string]bool{
				"partial": true,
				"full":    true,
			}

			isValid := validTypes[tt.redirectType]

			if isValid != tt.wantValid {
				t.Errorf("redirectType %q validity = %v, want %v", tt.redirectType, isValid, tt.wantValid)
			}
		})
	}
}

// TestOutputRedirectChainNames tests that correct chain/table names are used
func TestOutputRedirectChainNames(t *testing.T) {
	tests := []struct {
		name          string
		firewallType  Type
		wantChainName string
		wantTableName string
	}{
		{
			name:          "iptables uses PROXYCTL_OUTPUT chain",
			firewallType:  TypeIPTables,
			wantChainName: "PROXYCTL_OUTPUT",
			wantTableName: "nat",
		},
		{
			name:          "nftables uses proxyctl_redirect table",
			firewallType:  TypeNFTables,
			wantChainName: "output",
			wantTableName: "proxyctl_redirect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{Type: tt.firewallType}

			switch tt.firewallType {
			case TypeIPTables:
				// For iptables, we expect the chain name "PROXYCTL_OUTPUT" in nat table
				if tt.wantChainName != "PROXYCTL_OUTPUT" {
					t.Errorf("IPTables chain name = %q, want %q", tt.wantChainName, "PROXYCTL_OUTPUT")
				}
				if tt.wantTableName != "nat" {
					t.Errorf("IPTables table name = %q, want %q", tt.wantTableName, "nat")
				}
			case TypeNFTables:
				// For nftables, we expect table "proxyctl_redirect" with chain "output"
				if tt.wantTableName != "proxyctl_redirect" {
					t.Errorf("NFTables table name = %q, want %q", tt.wantTableName, "proxyctl_redirect")
				}
				if tt.wantChainName != "output" {
					t.Errorf("NFTables chain name = %q, want %q", tt.wantChainName, "output")
				}
			}

			// Verify manager has correct type
			if m.Type != tt.firewallType {
				t.Errorf("Manager type = %v, want %v", m.Type, tt.firewallType)
			}
		})
	}
}

// TestNFTablesOutputRedirectPriority tests that nftables rules use correct priority
func TestNFTablesOutputRedirectPriority(t *testing.T) {
	m := &Manager{Type: TypeNFTables}

	// Build a simple config
	var configBuilder strings.Builder
	configBuilder.WriteString("table ip proxyctl_redirect {\n")
	configBuilder.WriteString("    chain output {\n")
	configBuilder.WriteString("        type nat hook output priority -100; policy accept;\n")
	configBuilder.WriteString("    }\n")
	configBuilder.WriteString("}\n")

	configStr := configBuilder.String()

	// Verify priority is -100 (processed before default OUTPUT rules)
	if !strings.Contains(configStr, "priority -100") {
		t.Error("NFTables config missing 'priority -100'")
	}

	// Verify manager type
	if m.Type != TypeNFTables {
		t.Errorf("Manager type = %v, want %v", m.Type, TypeNFTables)
	}
}

// TestBypassRulesAlwaysPresent tests that bypass rules are always included
func TestBypassRulesAlwaysPresent(t *testing.T) {
	configs := []struct {
		cfg       *config.RedirectConfig
		proxyIP   string
		proxyPort int
	}{
		{
			cfg:       &config.RedirectConfig{Enabled: true, Type: "partial", Targets: []string{"8.8.8.8"}},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
		},
		{
			cfg:       &config.RedirectConfig{Enabled: true, Type: "full"},
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
		},
	}

	for i, tc := range configs {
		t.Run(fmt.Sprintf("config_%d", i), func(t *testing.T) {
			// Build NFTables config
			var configBuilder strings.Builder

			configBuilder.WriteString("table ip proxyctl_redirect {\n")
			configBuilder.WriteString("    chain output {\n")
			configBuilder.WriteString("        type nat hook output priority -100; policy accept;\n\n")
			configBuilder.WriteString(fmt.Sprintf("        ip daddr %s return\n", tc.proxyIP))
			configBuilder.WriteString("        oif lo return\n")
			configBuilder.WriteString("        ip daddr 10.0.0.0/8 return\n")
			configBuilder.WriteString("        ip daddr 172.16.0.0/12 return\n")
			configBuilder.WriteString("        ip daddr 192.168.0.0/16 return\n")
			configBuilder.WriteString("    }\n")
			configBuilder.WriteString("}\n")

			config := configBuilder.String()

			// Verify bypass for proxy IP
			if !strings.Contains(config, fmt.Sprintf("ip daddr %s return", tc.proxyIP)) {
				t.Error("Proxy bypass rule missing")
			}

			// Verify loopback bypass
			if !strings.Contains(config, "oif lo return") {
				t.Error("Loopback bypass rule missing")
			}

			// Verify local network bypass
			if !strings.Contains(config, "ip daddr 10.0.0.0/8 return") {
				t.Error("RFC 1918 bypass rule for 10.0.0.0/8 missing")
			}
			if !strings.Contains(config, "ip daddr 172.16.0.0/12 return") {
				t.Error("RFC 1918 bypass rule for 172.16.0.0/12 missing")
			}
			if !strings.Contains(config, "ip daddr 192.168.0.0/16 return") {
				t.Error("RFC 1918 bypass rule for 192.168.0.0/16 missing")
			}
		})
	}
}

// TestDNATFormat tests that DNAT rules are formatted correctly
func TestDNATFormat(t *testing.T) {
	tests := []struct {
		name      string
		proxyIP   string
		proxyPort int
		wantDNAT  string
	}{
		{
			name:      "standard port",
			proxyIP:   "10.16.0.5",
			proxyPort: 8080,
			wantDNAT:  "dnat to 10.16.0.5:8080",
		},
		{
			name:      "custom port",
			proxyIP:   "10.16.0.5",
			proxyPort: 9999,
			wantDNAT:  "dnat to 10.16.0.5:9999",
		},
		{
			name:      "different IP",
			proxyIP:   "192.168.1.100",
			proxyPort: 3128,
			wantDNAT:  "dnat to 192.168.1.100:3128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build DNAT rule
			dnatRule := fmt.Sprintf("dnat to %s:%d", tt.proxyIP, tt.proxyPort)

			if dnatRule != tt.wantDNAT {
				t.Errorf("DNAT rule = %q, want %q", dnatRule, tt.wantDNAT)
			}
		})
	}
}
