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
