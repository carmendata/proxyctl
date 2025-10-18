package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

func TestShowConfigurationSummary_Basic(t *testing.T) {
	// Basic smoke test for showConfigurationSummary with V2 config
	cfg := &config.Config{
		Admin: config.AdminConfig{
			Sources: []string{"0.0.0.0/0"},
		},
		Interfaces: config.InterfacesConfig{
			"public": "eth0",
		},
		Firewall: &config.FirewallConfig{
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
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run function
	showConfigurationSummary(cfg)

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify expected strings are present
	expectedStrings := []string{
		"Configuration Summary:",
		"INPUT Filtering: ENABLED",
		"Default Policy: drop",
		"Rules: 1 configured",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain %q, got:\n%s", expected, output)
		}
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

func TestCheckSSHLockout_V2(t *testing.T) {
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
			name: "SSH IP in allow rule (exact match)",
			cfg: &config.FirewallConfig{
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
			},
			sshIP:       "203.0.113.50",
			expectError: false,
		},
		{
			name: "SSH IP in CIDR range",
			cfg: &config.FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "drop",
				Rules: []config.FirewallRule{
					{
						Name:      "allow-ssh",
						Interface: "public",
						Sources:   []string{"10.0.1.0/24"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
				},
			},
			sshIP:       "10.0.1.100",
			expectError: false,
		},
		{
			name: "SSH IP NOT in allow list - lockout risk",
			cfg: &config.FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "drop",
				Rules: []config.FirewallRule{
					{
						Name:      "allow-ssh",
						Interface: "public",
						Sources:   []string{"10.0.1.0/24"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
				},
			},
			sshIP:       "203.0.113.50",
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
