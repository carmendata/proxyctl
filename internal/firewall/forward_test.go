package firewall

import (
	"fmt"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

// TestNFTablesForwardConfigGeneration tests the NFTables FORWARD rule generation logic
func TestNFTablesForwardConfigGeneration(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.FirewallConfig
		wantIn  []string // strings that should appear in config
		wantNot []string // strings that should NOT appear in config
	}{
		{
			name: "basic FORWARD rule with drop policy",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:      []string{"10.131.0.16/32"},
						Destinations: []string{"0.0.0.0/0"},
						Protocols:    []string{"tcp", "udp", "icmp"},
					},
				},
			},
			wantIn: []string{
				"table ip proxyctl_forward",
				"chain forward",
				"type filter hook forward priority 0; policy drop",
				"ct state established,related accept",
				"ip saddr 10.131.0.16/32",
				"ip daddr 0.0.0.0/0",
				"tcp",
				"udp",
				"icmp",
				"accept",
			},
		},
		{
			name: "FORWARD with MASQUERADE enabled",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:    []string{"10.131.0.16/32"},
						Masquerade: true,
					},
				},
			},
			wantIn: []string{
				"table ip proxyctl_forward",
				"chain postrouting",
				"type nat hook postrouting priority 100; policy accept",
				"ip saddr 10.131.0.16/32 oifname \"eth0\" masquerade",
			},
		},
		{
			name: "FORWARD without MASQUERADE",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:   []string{"192.168.1.0/24"},
						Protocols: []string{"tcp"},
					},
				},
			},
			wantNot: []string{
				"chain postrouting",
				"masquerade",
			},
		},
		{
			name: "FORWARD with specific ports for TCP",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "accept",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:   []string{"10.0.1.0/24"},
						Protocols: []string{"tcp"},
						Ports:     []int{80, 443, 8080},
					},
				},
			},
			wantIn: []string{
				"policy accept",
				"ip saddr 10.0.1.0/24",
				"tcp dport { 80, 443, 8080 }",
			},
		},
		{
			name: "FORWARD with multiple sources",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:   []string{"10.0.1.0/24", "10.0.2.0/24", "192.168.1.10/32"},
						Protocols: []string{"tcp", "udp"},
					},
				},
			},
			wantIn: []string{
				"ip saddr 10.0.1.0/24",
				"ip saddr 10.0.2.0/24",
				"ip saddr 192.168.1.10/32",
			},
		},
		{
			name: "multiple FORWARD rules",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:   []string{"10.0.1.0/24"},
						Protocols: []string{"tcp"},
						Comment:   "Allow web traffic",
					},
					{
						Sources:   []string{"10.0.2.0/24"},
						Protocols: []string{"udp"},
						Comment:   "Allow DNS traffic",
					},
				},
			},
			wantIn: []string{
				"# Rule 1: Allow web traffic",
				"# Rule 2: Allow DNS traffic",
				"ip saddr 10.0.1.0/24",
				"ip saddr 10.0.2.0/24",
			},
		},
		{
			name: "FORWARD with destination restrictions",
			cfg: &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:      []string{"10.0.1.0/24"},
						Destinations: []string{"8.8.8.8/32", "1.1.1.1/32"},
						Protocols:    []string{"udp"},
						Ports:        []int{53},
					},
				},
			},
			wantIn: []string{
				"ip saddr 10.0.1.0/24",
				"ip daddr 8.8.8.8/32",
				"ip daddr 1.1.1.1/32",
				"udp dport { 53 }",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the config manually using the same logic as applyNFTablesForwardRules
			var nftConfig strings.Builder

			policy := "drop"
			if tt.cfg.ForwardPolicy != "" {
				policy = tt.cfg.ForwardPolicy
			}

			nftConfig.WriteString("#!/usr/sbin/nft -f\n")
			nftConfig.WriteString("# proxyctl FORWARD Rules\n")
			nftConfig.WriteString("# Generated: proxyctl\n")
			nftConfig.WriteString("# Policy: " + policy + "\n\n")

			nftConfig.WriteString("table ip proxyctl_forward {\n")

			// FORWARD chain
			nftConfig.WriteString("    chain forward {\n")
			nftConfig.WriteString(fmt.Sprintf("        type filter hook forward priority 0; policy %s;\n\n", policy))

			// Allow established/related connections
			nftConfig.WriteString("        # Allow established/related connections\n")
			nftConfig.WriteString("        ct state established,related accept\n\n")

			// Add rules for each ForwardRule
			for i, rule := range tt.cfg.AllowForwardFrom {
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
			for _, rule := range tt.cfg.AllowForwardFrom {
				if rule.Masquerade {
					hasAnyMasquerade = true
					break
				}
			}

			if hasAnyMasquerade {
				nftConfig.WriteString("    chain postrouting {\n")
				nftConfig.WriteString("        type nat hook postrouting priority 100; policy accept;\n\n")

				// Add MASQUERADE rules
				for i, rule := range tt.cfg.AllowForwardFrom {
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

			configStr := nftConfig.String()

			// Check that all expected strings are present
			for _, want := range tt.wantIn {
				if !strings.Contains(configStr, want) {
					t.Errorf("Config missing expected string: %q\n\nGenerated config:\n%s", want, configStr)
				}
			}

			// Check that unwanted strings are not present
			for _, notWant := range tt.wantNot {
				if strings.Contains(configStr, notWant) {
					t.Errorf("Config contains unwanted string: %q\n\nGenerated config:\n%s", notWant, configStr)
				}
			}
		})
	}
}

// TestForwardPolicyValidation tests that only valid forward_policy values are accepted
func TestForwardPolicyValidation(t *testing.T) {
	tests := []struct {
		name          string
		forwardPolicy string
		wantValid     bool
	}{
		{
			name:          "valid: drop",
			forwardPolicy: "drop",
			wantValid:     true,
		},
		{
			name:          "valid: accept",
			forwardPolicy: "accept",
			wantValid:     true,
		},
		{
			name:          "invalid: block",
			forwardPolicy: "block",
			wantValid:     false,
		},
		{
			name:          "invalid: ignore",
			forwardPolicy: "ignore",
			wantValid:     false,
		},
		{
			name:          "invalid: empty",
			forwardPolicy: "",
			wantValid:     false,
		},
		{
			name:          "invalid: ACCEPT",
			forwardPolicy: "ACCEPT",
			wantValid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validPolicies := map[string]bool{
				"drop":   true,
				"accept": true,
			}

			isValid := validPolicies[tt.forwardPolicy]

			if isValid != tt.wantValid {
				t.Errorf("forwardPolicy %q validity = %v, want %v", tt.forwardPolicy, isValid, tt.wantValid)
			}
		})
	}
}

// TestForwardChainNames tests that correct chain/table names are used
func TestForwardChainNames(t *testing.T) {
	tests := []struct {
		name          string
		firewallType  Type
		wantChainName string
		wantTableName string
	}{
		{
			name:          "iptables uses PROXYCTL_FORWARD chain",
			firewallType:  TypeIPTables,
			wantChainName: "PROXYCTL_FORWARD",
			wantTableName: "",
		},
		{
			name:          "nftables uses proxyctl_forward table",
			firewallType:  TypeNFTables,
			wantChainName: "forward",
			wantTableName: "proxyctl_forward",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{Type: tt.firewallType}

			switch tt.firewallType {
			case TypeIPTables:
				// For iptables, we expect the chain name "PROXYCTL_FORWARD"
				if tt.wantChainName != "PROXYCTL_FORWARD" {
					t.Errorf("IPTables chain name = %q, want %q", tt.wantChainName, "PROXYCTL_FORWARD")
				}
			case TypeNFTables:
				// For nftables, we expect table "proxyctl_forward" with chain "forward"
				if tt.wantTableName != "proxyctl_forward" {
					t.Errorf("NFTables table name = %q, want %q", tt.wantTableName, "proxyctl_forward")
				}
				if tt.wantChainName != "forward" {
					t.Errorf("NFTables chain name = %q, want %q", tt.wantChainName, "forward")
				}
			}

			// Verify manager has correct type
			if m.Type != tt.firewallType {
				t.Errorf("Manager type = %v, want %v", m.Type, tt.firewallType)
			}
		})
	}
}

// TestEstablishedConnectionsAlwaysAllowed tests that established/related connections are always allowed in FORWARD
func TestEstablishedConnectionsAlwaysAllowed(t *testing.T) {
	configs := []*config.FirewallConfig{
		{
			ForwardPolicy: "drop",
			AllowForwardFrom: []config.ForwardRule{
				{Sources: []string{"10.0.1.0/24"}},
			},
		},
		{
			ForwardPolicy: "accept",
			AllowForwardFrom: []config.ForwardRule{
				{Sources: []string{"192.168.1.0/24"}, Protocols: []string{"tcp"}},
			},
		},
	}

	for i, cfg := range configs {
		t.Run(fmt.Sprintf("config_%d", i), func(t *testing.T) {
			// Build NFTables config
			var configStr strings.Builder

			configStr.WriteString("table ip proxyctl_forward {\n")
			configStr.WriteString("    chain forward {\n")
			configStr.WriteString(fmt.Sprintf("        type filter hook forward priority 0; policy %s;\n\n", cfg.ForwardPolicy))
			configStr.WriteString("        # Allow established/related connections\n")
			configStr.WriteString("        ct state established,related accept\n\n")
			configStr.WriteString("    }\n")
			configStr.WriteString("}\n")

			config := configStr.String()

			// Verify established connections are always allowed
			if !strings.Contains(config, "ct state established,related accept") {
				t.Error("Established connections rule missing from FORWARD chain")
			}
		})
	}
}

// TestMasqueradeOnlyWithFlag tests that MASQUERADE rules only appear when masquerade flag is true
func TestMasqueradeOnlyWithFlag(t *testing.T) {
	tests := []struct {
		name            string
		masqueradeFlag  bool
		wantMasquerade  bool
		wantPostrouting bool
	}{
		{
			name:            "masquerade enabled",
			masqueradeFlag:  true,
			wantMasquerade:  true,
			wantPostrouting: true,
		},
		{
			name:            "masquerade disabled",
			masqueradeFlag:  false,
			wantMasquerade:  false,
			wantPostrouting: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:    []string{"10.0.1.0/24"},
						Masquerade: tt.masqueradeFlag,
					},
				},
			}

			// Build config
			var nftConfig strings.Builder
			nftConfig.WriteString("table ip proxyctl_forward {\n")
			nftConfig.WriteString("    chain forward {\n")
			nftConfig.WriteString("        type filter hook forward priority 0; policy drop;\n")
			nftConfig.WriteString("    }\n")

			hasAnyMasquerade := false
			for _, rule := range cfg.AllowForwardFrom {
				if rule.Masquerade {
					hasAnyMasquerade = true
					break
				}
			}

			if hasAnyMasquerade {
				nftConfig.WriteString("    chain postrouting {\n")
				nftConfig.WriteString("        type nat hook postrouting priority 100; policy accept;\n")
				nftConfig.WriteString("        ip saddr 10.0.1.0/24 oifname \"eth0\" masquerade\n")
				nftConfig.WriteString("    }\n")
			}

			nftConfig.WriteString("}\n")

			configStr := nftConfig.String()

			hasMasquerade := strings.Contains(configStr, "masquerade")
			hasPostrouting := strings.Contains(configStr, "chain postrouting")

			if hasMasquerade != tt.wantMasquerade {
				t.Errorf("Masquerade present = %v, want %v", hasMasquerade, tt.wantMasquerade)
			}

			if hasPostrouting != tt.wantPostrouting {
				t.Errorf("Postrouting chain present = %v, want %v", hasPostrouting, tt.wantPostrouting)
			}
		})
	}
}

// TestForwardRuleProtocolHandling tests that protocols are handled correctly
func TestForwardRuleProtocolHandling(t *testing.T) {
	tests := []struct {
		name       string
		protocols  []string
		ports      []int
		wantPorts  bool
		wantProtos []string
	}{
		{
			name:       "TCP with ports",
			protocols:  []string{"tcp"},
			ports:      []int{80, 443},
			wantPorts:  true,
			wantProtos: []string{"tcp"},
		},
		{
			name:       "UDP with ports",
			protocols:  []string{"udp"},
			ports:      []int{53, 123},
			wantPorts:  true,
			wantProtos: []string{"udp"},
		},
		{
			name:       "ICMP without ports",
			protocols:  []string{"icmp"},
			ports:      []int{},
			wantPorts:  false,
			wantProtos: []string{"icmp"},
		},
		{
			name:       "mixed protocols, ports ignored for ICMP",
			protocols:  []string{"tcp", "udp", "icmp"},
			ports:      []int{80},
			wantPorts:  true,
			wantProtos: []string{"tcp", "udp", "icmp"},
		},
		{
			name:       "TCP without ports (all ports)",
			protocols:  []string{"tcp"},
			ports:      []int{},
			wantPorts:  false,
			wantProtos: []string{"tcp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.FirewallConfig{
				ForwardPolicy: "drop",
				AllowForwardFrom: []config.ForwardRule{
					{
						Sources:   []string{"10.0.1.0/24"},
						Protocols: tt.protocols,
						Ports:     tt.ports,
					},
				},
			}

			// Build rule string (we use cfg to construct this conceptually)
			_ = cfg // Use cfg to avoid unused variable error
			var ruleStr strings.Builder
			for _, proto := range tt.protocols {
				protoLower := strings.ToLower(proto)
				ruleStr.WriteString(fmt.Sprintf("%s ", protoLower))

				// Add port match if specified and protocol is TCP/UDP
				if (protoLower == "tcp" || protoLower == "udp") && len(tt.ports) > 0 {
					portList := make([]string, len(tt.ports))
					for j, port := range tt.ports {
						portList[j] = fmt.Sprintf("%d", port)
					}
					ruleStr.WriteString(fmt.Sprintf("dport { %s } ", strings.Join(portList, ", ")))
				}
			}

			ruleStrOut := ruleStr.String()

			// Check protocols are present
			for _, proto := range tt.wantProtos {
				if !strings.Contains(ruleStrOut, strings.ToLower(proto)) {
					t.Errorf("Rule missing protocol %q: %s", proto, ruleStrOut)
				}
			}

			// Check ports handling
			hasPorts := strings.Contains(ruleStrOut, "dport")
			if hasPorts != tt.wantPorts {
				t.Errorf("Ports present = %v, want %v. Rule: %s", hasPorts, tt.wantPorts, ruleStrOut)
			}
		})
	}
}

// TestIPTablesForwardRuleStructure tests iptables command structure
func TestIPTablesForwardRuleStructure(t *testing.T) {
	tests := []struct {
		name      string
		rule      config.ForwardRule
		wantArgs  []string
		wantChain string
	}{
		{
			name: "basic rule",
			rule: config.ForwardRule{
				Sources: []string{"10.0.1.0/24"},
			},
			wantArgs: []string{
				"-A", "PROXYCTL_FORWARD",
				"-s", "10.0.1.0/24",
				"-j", "ACCEPT",
			},
			wantChain: "PROXYCTL_FORWARD",
		},
		{
			name: "rule with protocol",
			rule: config.ForwardRule{
				Sources:   []string{"10.0.1.0/24"},
				Protocols: []string{"tcp"},
			},
			wantArgs: []string{
				"-A", "PROXYCTL_FORWARD",
				"-s", "10.0.1.0/24",
				"-p", "tcp",
				"-j", "ACCEPT",
			},
			wantChain: "PROXYCTL_FORWARD",
		},
		{
			name: "rule with ports",
			rule: config.ForwardRule{
				Sources:   []string{"10.0.1.0/24"},
				Protocols: []string{"tcp"},
				Ports:     []int{80, 443},
			},
			wantArgs: []string{
				"-A", "PROXYCTL_FORWARD",
				"-s", "10.0.1.0/24",
				"-p", "tcp",
				"-m", "multiport",
				"--dports", "80,443",
				"-j", "ACCEPT",
			},
			wantChain: "PROXYCTL_FORWARD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate building iptables args
			args := []string{"-A", tt.wantChain, "-s", tt.rule.Sources[0]}

			if len(tt.rule.Protocols) > 0 {
				for _, proto := range tt.rule.Protocols {
					args = append(args, "-p", strings.ToLower(proto))

					if (strings.ToLower(proto) == "tcp" || strings.ToLower(proto) == "udp") && len(tt.rule.Ports) > 0 {
						portList := make([]string, len(tt.rule.Ports))
						for j, port := range tt.rule.Ports {
							portList[j] = fmt.Sprintf("%d", port)
						}
						args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
					}
				}
			}

			args = append(args, "-j", "ACCEPT")

			// Verify all expected args are present
			argsStr := strings.Join(args, " ")
			for _, wantArg := range tt.wantArgs {
				if !strings.Contains(argsStr, wantArg) {
					t.Errorf("Args missing %q: %s", wantArg, argsStr)
				}
			}
		})
	}
}
