package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

func TestShowConfigurationSummary(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		expectedOutput []string
	}{
		{
			name: "INPUT filtering only",
			cfg: &config.Config{
				Firewall: &config.FirewallConfig{
					Enabled:     true,
					InputPolicy: "drop",
					AllowSSHFrom: []string{
						"203.0.113.50",
						"10.0.1.0/24",
					},
					AllowProxyFrom: []config.AllowProxyFromRule{
						{
							Sources: []string{"10.0.1.0/24"},
							Ports:   []int{8080},
						},
					},
				},
			},
			expectedOutput: []string{
				"Configuration Summary:",
				"INPUT Filtering: ENABLED",
				"Policy: drop",
				"SSH allowed from: 203.0.113.50, 10.0.1.0/24",
				"Proxy access: 1 rule(s)",
			},
		},
		{
			name: "OUTPUT redirect - partial",
			cfg: &config.Config{
				Proxy: &config.ProxyConfig{
					IP:   "10.16.0.5",
					Port: 8080,
				},
				Redirect: &config.RedirectConfig{
					Enabled: true,
					Type:    "partial",
					Targets: []string{"8.8.8.8", "1.1.1.1"},
				},
			},
			expectedOutput: []string{
				"Configuration Summary:",
				"OUTPUT Redirect: ENABLED",
				"Type: partial",
				"Proxy: 10.16.0.5:8080",
				"Targets: 8.8.8.8, 1.1.1.1",
			},
		},
		{
			name: "OUTPUT redirect - full",
			cfg: &config.Config{
				Proxy: &config.ProxyConfig{
					IP:   "10.16.0.5",
					Port: 8080,
				},
				Redirect: &config.RedirectConfig{
					Enabled: true,
					Type:    "full",
				},
			},
			expectedOutput: []string{
				"Configuration Summary:",
				"OUTPUT Redirect: ENABLED",
				"Type: full",
				"Proxy: 10.16.0.5:8080",
			},
		},
		{
			name: "Both INPUT filtering and OUTPUT redirect",
			cfg: &config.Config{
				Proxy: &config.ProxyConfig{
					IP:   "10.16.0.5",
					Port: 8080,
				},
				Firewall: &config.FirewallConfig{
					Enabled:      true,
					InputPolicy:  "drop",
					AllowSSHFrom: []string{"0.0.0.0/0"},
					AllowProxyFrom: []config.AllowProxyFromRule{
						{
							Sources: []string{"10.0.1.0/24"},
							Ports:   []int{8080, 8443},
						},
					},
				},
				Redirect: &config.RedirectConfig{
					Enabled: true,
					Type:    "partial",
					Targets: []string{"8.8.8.8"},
				},
			},
			expectedOutput: []string{
				"Configuration Summary:",
				"INPUT Filtering: ENABLED",
				"Policy: drop",
				"SSH allowed from: 0.0.0.0/0",
				"OUTPUT Redirect: ENABLED",
				"Type: partial",
				"Targets: 8.8.8.8",
			},
		},
		{
			name: "Firewall disabled",
			cfg: &config.Config{
				Firewall: &config.FirewallConfig{
					Enabled: false,
				},
			},
			expectedOutput: []string{
				"Configuration Summary:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run function
			showConfigurationSummary(tt.cfg)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Verify expected strings are present
			for _, expected := range tt.expectedOutput {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain %q, but it didn't.\nFull output:\n%s", expected, output)
				}
			}
		})
	}
}

func TestShowConfigurationSummary_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		shouldNotExist []string
	}{
		{
			name: "No SSH rules",
			cfg: &config.Config{
				Firewall: &config.FirewallConfig{
					Enabled:     true,
					InputPolicy: "drop",
					AllowProxyFrom: []config.AllowProxyFromRule{
						{Sources: []string{"10.0.1.0/24"}, Ports: []int{8080}},
					},
				},
			},
			shouldNotExist: []string{"SSH allowed from"},
		},
		{
			name: "No proxy rules",
			cfg: &config.Config{
				Firewall: &config.FirewallConfig{
					Enabled:      true,
					InputPolicy:  "drop",
					AllowSSHFrom: []string{"0.0.0.0/0"},
				},
			},
			shouldNotExist: []string{"Proxy access"},
		},
		{
			name: "Partial redirect without targets shown",
			cfg: &config.Config{
				Proxy: &config.ProxyConfig{
					IP:   "10.16.0.5",
					Port: 8080,
				},
				Redirect: &config.RedirectConfig{
					Enabled: true,
					Type:    "full",
				},
			},
			shouldNotExist: []string{"Targets:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run function
			showConfigurationSummary(tt.cfg)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Verify strings that should NOT be present
			for _, notExpected := range tt.shouldNotExist {
				if strings.Contains(output, notExpected) {
					t.Errorf("Expected output NOT to contain %q, but it did.\nFull output:\n%s", notExpected, output)
				}
			}
		})
	}
}

func TestDetectSSHConnectionIP(t *testing.T) {
	tests := []struct {
		name          string
		sshConnection string
		expectedIP    string
		expectError   bool
	}{
		{
			name:          "valid SSH connection",
			sshConnection: "203.0.113.50 54321 10.16.0.5 22",
			expectedIP:    "203.0.113.50",
			expectError:   false,
		},
		{
			name:          "no SSH connection",
			sshConnection: "",
			expectedIP:    "",
			expectError:   false,
		},
		{
			name:          "malformed SSH connection (too few parts)",
			sshConnection: "203.0.113.50 54321",
			expectedIP:    "",
			expectError:   true,
		},
		{
			name:          "IPv6 SSH connection",
			sshConnection: "2001:db8::1 54321 2001:db8::2 22",
			expectedIP:    "2001:db8::1",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.sshConnection != "" {
				os.Setenv("SSH_CONNECTION", tt.sshConnection)
				defer os.Unsetenv("SSH_CONNECTION")
			}

			// Run function
			ip, err := detectSSHConnectionIP()

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check IP
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %q, got %q", tt.expectedIP, ip)
			}
		})
	}
}

func TestCheckSSHLockout(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.FirewallConfig
		sshIP       string
		expectError bool
	}{
		{
			name:        "firewall disabled",
			cfg:         &config.FirewallConfig{Enabled: false},
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name:        "nil firewall config",
			cfg:         nil,
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name: "no SSH rules configured",
			cfg: &config.FirewallConfig{
				Enabled:     true,
				InputPolicy: "drop",
			},
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name: "SSH IP in exact match",
			cfg: &config.FirewallConfig{
				Enabled:      true,
				InputPolicy:  "drop",
				AllowSSHFrom: []string{"203.0.113.50", "10.0.1.0/24"},
			},
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name: "SSH IP in CIDR range",
			cfg: &config.FirewallConfig{
				Enabled:      true,
				InputPolicy:  "drop",
				AllowSSHFrom: []string{"10.0.1.0/24"},
			},
			sshIP:       "10.0.1.100",
			expectError: false,
		},
		{
			name: "SSH IP in 0.0.0.0/0 (allow all)",
			cfg: &config.FirewallConfig{
				Enabled:      true,
				InputPolicy:  "drop",
				AllowSSHFrom: []string{"0.0.0.0/0"},
			},
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name: "SSH IP NOT in allow list - lockout risk",
			cfg: &config.FirewallConfig{
				Enabled:      true,
				InputPolicy:  "drop",
				AllowSSHFrom: []string{"10.0.1.0/24", "192.168.1.0/24"},
			},
			sshIP:       "203.0.113.50",
			expectError: true,
		},
		{
			name: "SSH IP outside CIDR range - lockout risk",
			cfg: &config.FirewallConfig{
				Enabled:      true,
				InputPolicy:  "drop",
				AllowSSHFrom: []string{"10.0.1.0/24"},
			},
			sshIP:       "10.0.2.100",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSSHLockout(tt.cfg, tt.sshIP)

			if tt.expectError && err == nil {
				t.Errorf("Expected lockout error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected lockout error: %v", err)
			}

			// If we expect an error, verify the error message contains the SSH IP
			if tt.expectError && err != nil {
				if !strings.Contains(err.Error(), tt.sshIP) {
					t.Errorf("Expected error message to contain SSH IP %q, got: %v", tt.sshIP, err)
				}
			}
		})
	}
}

func TestCheckSSHLockout_InvalidCIDR(t *testing.T) {
	// Test that invalid CIDR blocks are handled gracefully
	cfg := &config.FirewallConfig{
		Enabled:      true,
		InputPolicy:  "drop",
		AllowSSHFrom: []string{"not-a-valid-cidr", "10.0.1.0/24"},
	}

	// SSH IP is in the valid CIDR range, should not error
	err := checkSSHLockout(cfg, "10.0.1.100")
	if err != nil {
		t.Errorf("Expected no error when SSH IP is in valid CIDR range, got: %v", err)
	}

	// SSH IP not in any valid range, should error
	err = checkSSHLockout(cfg, "203.0.113.50")
	if err == nil {
		t.Errorf("Expected lockout error when SSH IP not in any valid range")
	}
}
