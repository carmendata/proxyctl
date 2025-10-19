package config

import (
	"encoding/json"
	"testing"
)

// TestProxyStringParsing tests all three formats of proxy configuration
func TestProxyStringParsing(t *testing.T) {
	tests := []struct {
		name       string
		jsonConfig string
		wantIP     string
		wantPort   int
		wantErr    bool
	}{
		{
			name:       "string format without port (defaults to 8080)",
			jsonConfig: `{"proxy": "10.16.0.5"}`,
			wantIP:     "10.16.0.5",
			wantPort:   8080,
			wantErr:    false,
		},
		{
			name:       "string format with port",
			jsonConfig: `{"proxy": "10.16.0.5:9999"}`,
			wantIP:     "10.16.0.5",
			wantPort:   9999,
			wantErr:    false,
		},
		{
			name:       "object format with port",
			jsonConfig: `{"proxy": {"ip": "10.16.0.5", "port": 8888}}`,
			wantIP:     "10.16.0.5",
			wantPort:   8888,
			wantErr:    false,
		},
		{
			name:       "object format without port (defaults to 0, validated later)",
			jsonConfig: `{"proxy": {"ip": "10.16.0.5"}}`,
			wantIP:     "10.16.0.5",
			wantPort:   0,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.jsonConfig), &cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if cfg.Proxy == nil {
					t.Fatal("Proxy is nil after unmarshal")
				}
				if cfg.Proxy.IP != tt.wantIP {
					t.Errorf("Proxy.IP = %v, want %v", cfg.Proxy.IP, tt.wantIP)
				}
				if cfg.Proxy.Port != tt.wantPort {
					t.Errorf("Proxy.Port = %v, want %v", cfg.Proxy.Port, tt.wantPort)
				}
			}
		})
	}
}

// TestFirewallValidation tests firewall configuration validation
func TestFirewallValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid firewall config with drop policy",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:      true,
					InputPolicy:  "drop",
					AllowSSHFrom: []string{"203.0.113.50"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid firewall config with block policy",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:      true,
					InputPolicy:  "block",
					AllowSSHFrom: []string{"203.0.113.50"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid firewall config with ignore policy",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:     true,
					InputPolicy: "ignore",
					AllowProxyFrom: []AllowProxyFromRule{
						{Sources: []string{"10.0.1.0/24"}, Ports: []int{8080}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "firewall enabled without input_policy",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:      true,
					AllowSSHFrom: []string{"203.0.113.50"},
				},
			},
			wantErr: true,
			errMsg:  "input_policy is required",
		},
		{
			name: "firewall with invalid input_policy",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:      true,
					InputPolicy:  "invalid",
					AllowSSHFrom: []string{"203.0.113.50"},
				},
			},
			wantErr: true,
			errMsg:  "input_policy must be 'drop', 'block', or 'ignore'",
		},
		{
			name: "firewall enabled without any allow rules",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:     true,
					InputPolicy: "drop",
				},
			},
			wantErr: true,
			errMsg:  "at least one of allow_ssh_from or allow_proxy_from must be specified",
		},
		{
			name: "firewall with empty sources in allow_proxy_from",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:     true,
					InputPolicy: "drop",
					AllowProxyFrom: []AllowProxyFromRule{
						{Sources: []string{}, Ports: []int{8080}},
					},
				},
			},
			wantErr: true,
			errMsg:  "sources cannot be empty",
		},
		{
			name: "firewall with optional ports in allow_proxy_from",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Firewall: &FirewallConfig{
					Enabled:     true,
					InputPolicy: "drop",
					AllowProxyFrom: []AllowProxyFromRule{
						{Sources: []string{"10.0.1.0/24"}}, // No ports specified - should be valid
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestRedirectValidation tests redirect configuration validation
func TestRedirectValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid partial redirect",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Redirect: &RedirectConfig{
					Enabled: true,
					Type:    "partial",
					Targets: []string{"8.8.8.8", "1.1.1.1"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid full redirect",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Redirect: &RedirectConfig{
					Enabled: true,
					Type:    "full",
				},
			},
			wantErr: false,
		},
		{
			name: "partial redirect without targets",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Redirect: &RedirectConfig{
					Enabled: true,
					Type:    "partial",
					Targets: []string{},
				},
			},
			wantErr: true,
			errMsg:  "redirect.targets must contain at least one IP",
		},
		{
			name: "redirect with invalid type",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
				Redirect: &RedirectConfig{
					Enabled: true,
					Type:    "invalid",
				},
			},
			wantErr: true,
			errMsg:  "redirect.type must be 'partial' or 'full'",
		},
		{
			name: "redirect without proxy config",
			config: &Config{
				Mode: "egress",
				Redirect: &RedirectConfig{
					Enabled: true,
					Type:    "full",
				},
			},
			wantErr: true,
			errMsg:  "proxy configuration required when redirect is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestProxyValidation tests proxy configuration validation
func TestProxyValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid proxy with default port",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080},
			},
			wantErr: false,
		},
		{
			name: "valid proxy with custom port",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 9999},
			},
			wantErr: false,
		},
		{
			name: "valid proxy with stats port",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080, StatsPort: 9000},
			},
			wantErr: false,
		},
		{
			name: "proxy with empty IP",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "", Port: 8080},
			},
			wantErr: true,
			errMsg:  "proxy.ip cannot be empty",
		},
		{
			name: "proxy with invalid port (0 gets set to default 8080)",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 0},
			},
			wantErr: false, // Port 0 is set to 8080 in validation
		},
		{
			name: "proxy with port too high",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 70000},
			},
			wantErr: true,
			errMsg:  "proxy.port must be between 1 and 65535",
		},
		{
			name: "proxy with invalid stats port",
			config: &Config{
				Mode:  "egress",
				Proxy: &ProxyConfig{IP: "10.16.0.5", Port: 8080, StatsPort: 70000},
			},
			wantErr: true,
			errMsg:  "proxy.stats_port must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestCompleteConfigExamples tests complete config examples from the example files
func TestCompleteConfigExamples(t *testing.T) {
	tests := []struct {
		name       string
		jsonConfig string
		wantErr    bool
	}{
		{
			name: "egress proxy with firewall",
			jsonConfig: `{
				"proxy": {"ip": "10.16.0.5", "port": 8080, "stats_port": 9000},
				"acl": {"file": "/etc/haproxy/egress-acl.lst"},
				"firewall": {
					"enabled": true,
					"input_policy": "drop",
					"allow_ssh_from": ["203.0.113.50", "203.0.113.51"],
					"allow_proxy_from": [
						{"sources": ["10.0.1.100", "10.0.1.101"], "ports": [8080]},
						{"sources": ["10.0.1.0/24"], "ports": [8080, 9000]},
						{"sources": ["192.168.1.0/24"]}
					]
				},
				"logger": {"enabled": true, "output": "/var/log/proxyctl/egress.log"}
			}`,
			wantErr: false,
		},
		{
			name: "worker with partial redirect (string format)",
			jsonConfig: `{
				"proxy": "10.16.0.5",
				"redirect": {
					"enabled": true,
					"type": "partial",
					"targets": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
				}
			}`,
			wantErr: false,
		},
		{
			name: "worker with full redirect",
			jsonConfig: `{
				"proxy": "10.16.0.5",
				"redirect": {"enabled": true, "type": "full"}
			}`,
			wantErr: false,
		},
		{
			name: "worker with custom port (string format)",
			jsonConfig: `{
				"proxy": "10.16.0.5:9999",
				"redirect": {
					"enabled": true,
					"type": "partial",
					"targets": ["203.0.113.100", "203.0.113.0/24"]
				}
			}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.jsonConfig), &cfg)
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}

			// Set mode for validation
			cfg.Mode = "egress"

			err = cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoggerValidation tests logger configuration validation
func TestLoggerValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid logger config with defaults",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled: true,
					Output:  "/var/log/proxyctl/egress.log",
				},
			},
			wantErr: false,
		},
		{
			name: "valid logger with all options",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:          true,
					Output:           "/var/log/proxyctl/all.log",
					Chains:           []string{"OUTPUT", "INPUT"},
					Protocols:        []string{"tcp", "udp", "icmp"},
					IncludePrivate:   true,
					IncludeLoopback:  true,
					IncludeMulticast: true,
					IncludeRanges:    []string{"8.8.8.8", "1.1.1.1"},
					ExcludeRanges:    []string{"10.0.0.0/8"},
				},
			},
			wantErr: false,
		},
		{
			name: "logger with invalid chain",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled: true,
					Output:  "/var/log/proxyctl/egress.log",
					Chains:  []string{"INVALID"},
				},
			},
			wantErr: true,
			errMsg:  "invalid chain: INVALID",
		},
		{
			name: "logger with mixed case chain (should work)",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled: true,
					Output:  "/var/log/proxyctl/egress.log",
					Chains:  []string{"output", "Input"},
				},
			},
			wantErr: false,
		},
		{
			name: "logger with invalid protocol",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:   true,
					Output:    "/var/log/proxyctl/egress.log",
					Protocols: []string{"invalid"},
				},
			},
			wantErr: true,
			errMsg:  "invalid protocol: invalid",
		},
		{
			name: "logger with all protocols",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:   true,
					Output:    "/var/log/proxyctl/egress.log",
					Protocols: []string{"all"},
				},
			},
			wantErr: false,
		},
		{
			name: "logger with mixed case protocols (should work)",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:   true,
					Output:    "/var/log/proxyctl/egress.log",
					Protocols: []string{"TCP", "Udp", "ICMP"},
				},
			},
			wantErr: false,
		},
		{
			name: "logger with invalid IP in include_ranges",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:       true,
					Output:        "/var/log/proxyctl/egress.log",
					IncludeRanges: []string{"not-an-ip"},
				},
			},
			wantErr: true,
			errMsg:  "invalid include_ranges",
		},
		{
			name: "logger with valid CIDR in include_ranges",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:       true,
					Output:        "/var/log/proxyctl/egress.log",
					IncludeRanges: []string{"10.0.0.0/8", "192.168.1.0/24"},
				},
			},
			wantErr: false,
		},
		{
			name: "logger with invalid CIDR in exclude_ranges",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:       true,
					Output:        "/var/log/proxyctl/egress.log",
					ExcludeRanges: []string{"10.0.0.0/99"},
				},
			},
			wantErr: true,
			errMsg:  "invalid exclude_ranges",
		},
		{
			name: "logger with mixed IPs and CIDRs",
			config: &Config{
				Mode: "egress",
				Logger: &LoggerConfig{
					Enabled:       true,
					Output:        "/var/log/proxyctl/egress.log",
					IncludeRanges: []string{"8.8.8.8", "10.0.0.0/8", "1.1.1.1"},
					ExcludeRanges: []string{"192.168.1.100", "172.16.0.0/12"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want to contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestLoggerConfigJSON tests that logger config can be unmarshaled from JSON
func TestLoggerConfigJSON(t *testing.T) {
	tests := []struct {
		name       string
		jsonConfig string
		wantErr    bool
		validate   func(*testing.T, *LoggerConfig)
	}{
		{
			name: "basic logger config",
			jsonConfig: `{
				"logger": {
					"enabled": true,
					"output": "/var/log/test.log"
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, l *LoggerConfig) {
				if !l.Enabled {
					t.Error("Expected Enabled to be true")
				}
				if l.Output != "/var/log/test.log" {
					t.Errorf("Output = %v, want /var/log/test.log", l.Output)
				}
			},
		},
		{
			name: "logger with comprehensive monitoring",
			jsonConfig: `{
				"logger": {
					"enabled": true,
					"output": "/var/log/all.log",
					"chains": ["OUTPUT", "INPUT", "FORWARD"],
					"protocols": ["tcp", "udp", "icmp"],
					"include_private": true,
					"include_loopback": true,
					"include_multicast": true
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, l *LoggerConfig) {
				if len(l.Chains) != 3 {
					t.Errorf("Chains length = %d, want 3", len(l.Chains))
				}
				if len(l.Protocols) != 3 {
					t.Errorf("Protocols length = %d, want 3", len(l.Protocols))
				}
				if !l.IncludePrivate || !l.IncludeLoopback || !l.IncludeMulticast {
					t.Error("Expected all include flags to be true")
				}
			},
		},
		{
			name: "logger with whitelist mode",
			jsonConfig: `{
				"logger": {
					"enabled": true,
					"output": "/var/log/whitelist.log",
					"include_ranges": ["8.8.8.8", "1.1.1.1", "10.0.0.0/8"],
					"exclude_ranges": ["10.99.0.0/16"]
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, l *LoggerConfig) {
				if len(l.IncludeRanges) != 3 {
					t.Errorf("IncludeRanges length = %d, want 3", len(l.IncludeRanges))
				}
				if len(l.ExcludeRanges) != 1 {
					t.Errorf("ExcludeRanges length = %d, want 1", len(l.ExcludeRanges))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := json.Unmarshal([]byte(tt.jsonConfig), &cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && cfg.Logger != nil && tt.validate != nil {
				tt.validate(t, cfg.Logger)
			}
		})
	}
}

// TestValidateIPOrCIDR tests the IP/CIDR validation helper
func TestValidateIPOrCIDR(t *testing.T) {
	tests := []struct {
		name    string
		ipRange string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 CIDR", "192.168.1.0/24", false},
		{"valid IPv4 /32", "8.8.8.8/32", false},
		{"valid IPv4 /8", "10.0.0.0/8", false},
		{"invalid IP", "999.999.999.999", true},
		{"invalid CIDR prefix", "192.168.1.0/99", true},
		{"invalid format", "not-an-ip", true},
		{"empty string", "", true},
		{"partial IP", "192.168", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPOrCIDR(tt.ipRange)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateIPOrCIDR(%q) error = %v, wantErr %v", tt.ipRange, err, tt.wantErr)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
