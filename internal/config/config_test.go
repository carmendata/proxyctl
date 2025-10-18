package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAdminConfig_Validate tests admin configuration validation
func TestAdminConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		admin   AdminConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid admin config",
			admin: AdminConfig{
				Sources: []string{"203.0.113.50", "203.0.113.0/24"},
				Ports:   []int{22},
			},
			wantErr: false,
		},
		{
			name: "valid admin config with multiple ports",
			admin: AdminConfig{
				Sources: []string{"203.0.113.50"},
				Ports:   []int{22, 2222, 8022},
			},
			wantErr: false,
		},
		{
			name: "valid admin config without ports (will use defaults)",
			admin: AdminConfig{
				Sources: []string{"203.0.113.50"},
			},
			wantErr: false,
		},
		{
			name: "empty sources",
			admin: AdminConfig{
				Sources: []string{},
			},
			wantErr: true,
			errMsg:  "admin.sources must contain at least one IP or CIDR",
		},
		{
			name: "invalid IP in sources",
			admin: AdminConfig{
				Sources: []string{"not-an-ip"},
			},
			wantErr: true,
			errMsg:  "invalid IP or CIDR in admin.sources",
		},
		{
			name: "invalid CIDR in sources",
			admin: AdminConfig{
				Sources: []string{"203.0.113.0/33"},
			},
			wantErr: true,
			errMsg:  "invalid IP or CIDR in admin.sources",
		},
		{
			name: "invalid port too low",
			admin: AdminConfig{
				Sources: []string{"203.0.113.50"},
				Ports:   []int{0},
			},
			wantErr: true,
			errMsg:  "invalid port in admin.ports: 0",
		},
		{
			name: "invalid port too high",
			admin: AdminConfig{
				Sources: []string{"203.0.113.50"},
				Ports:   []int{65536},
			},
			wantErr: true,
			errMsg:  "invalid port in admin.ports: 65536",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.admin.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("AdminConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("AdminConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestInterfacesConfig_Validate tests interfaces configuration validation
func TestInterfacesConfig_Validate(t *testing.T) {
	tests := []struct {
		name       string
		interfaces InterfacesConfig
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid interfaces",
			interfaces: InterfacesConfig{
				"public":  "eth0",
				"private": "eth1",
			},
			wantErr: false,
		},
		{
			name: "valid single interface",
			interfaces: InterfacesConfig{
				"public": "eth0",
			},
			wantErr: false,
		},
		{
			name: "valid loopback interface",
			interfaces: InterfacesConfig{
				"loopback": "lo",
			},
			wantErr: false,
		},
		{
			name:       "empty interfaces",
			interfaces: InterfacesConfig{},
			wantErr:    true,
			errMsg:     "at least one interface must be defined",
		},
		{
			name: "empty logical name",
			interfaces: InterfacesConfig{
				"": "eth0",
			},
			wantErr: true,
			errMsg:  "interface logical name cannot be empty",
		},
		{
			name: "empty physical name",
			interfaces: InterfacesConfig{
				"public": "",
			},
			wantErr: true,
			errMsg:  "interface physical name cannot be empty for 'public'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.interfaces.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("InterfacesConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("InterfacesConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestFirewallRule_Validate tests firewall rule validation
func TestFirewallRule_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":  "eth0",
		"private": "eth1",
	}

	tests := []struct {
		name    string
		rule    FirewallRule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid tcp rule with ports",
			rule: FirewallRule{
				Name:      "allow-ssh",
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "tcp",
				Ports:     []int{22},
				Action:    "accept",
			},
			wantErr: false,
		},
		{
			name: "valid icmp rule without ports",
			rule: FirewallRule{
				Name:      "allow-icmp",
				Interface: "public",
				Sources:   []string{"0.0.0.0/0"},
				Protocol:  "icmp",
				Action:    "accept",
			},
			wantErr: false,
		},
		{
			name: "valid rule with destinations",
			rule: FirewallRule{
				Name:         "allow-web",
				Interface:    "public",
				Sources:      []string{"10.0.0.0/8"},
				Destinations: []string{"192.168.1.100"},
				Protocol:     "tcp",
				Ports:        []int{80, 443},
				Action:       "accept",
			},
			wantErr: false,
		},
		{
			name: "empty rule name",
			rule: FirewallRule{
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "tcp",
				Ports:     []int{22},
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule name cannot be empty",
		},
		{
			name: "undefined interface",
			rule: FirewallRule{
				Name:      "test",
				Interface: "nonexistent",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "tcp",
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' references undefined interface: nonexistent",
		},
		{
			name: "empty sources",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{},
				Protocol:  "tcp",
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' must have at least one source",
		},
		{
			name: "invalid source IP",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{"not-an-ip"},
				Protocol:  "tcp",
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' has invalid source IP or CIDR: not-an-ip",
		},
		{
			name: "invalid destination IP",
			rule: FirewallRule{
				Name:         "test",
				Interface:    "public",
				Sources:      []string{"203.0.113.0/24"},
				Destinations: []string{"invalid"},
				Protocol:     "tcp",
				Action:       "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' has invalid destination IP or CIDR: invalid",
		},
		{
			name: "invalid protocol",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "invalid",
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' has invalid protocol: invalid",
		},
		{
			name: "ports with icmp protocol",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "icmp",
				Ports:     []int{22},
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' cannot specify ports for protocol 'icmp'",
		},
		{
			name: "invalid port number",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "tcp",
				Ports:     []int{99999},
				Action:    "accept",
			},
			wantErr: true,
			errMsg:  "rule 'test' has invalid port: 99999",
		},
		{
			name: "invalid action",
			rule: FirewallRule{
				Name:      "test",
				Interface: "public",
				Sources:   []string{"203.0.113.0/24"},
				Protocol:  "tcp",
				Action:    "invalid",
			},
			wantErr: true,
			errMsg:  "rule 'test' has invalid action: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("FirewallRule.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("FirewallRule.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestFirewallConfig_Validate tests firewall configuration validation
func TestFirewallConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":  "eth0",
		"private": "eth1",
	}

	tests := []struct {
		name     string
		firewall FirewallConfig
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid firewall config",
			firewall: FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "drop",
				Rules: []FirewallRule{
					{
						Name:      "allow-ssh",
						Interface: "public",
						Sources:   []string{"203.0.113.0/24"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid firewall with multiple rules",
			firewall: FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "block",
				Rules: []FirewallRule{
					{
						Name:      "allow-ssh",
						Interface: "public",
						Sources:   []string{"203.0.113.0/24"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
					{
						Name:      "allow-web",
						Interface: "public",
						Sources:   []string{"0.0.0.0/0"},
						Protocol:  "tcp",
						Ports:     []int{80, 443},
						Action:    "accept",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid default policy",
			firewall: FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "invalid",
			},
			wantErr: true,
			errMsg:  "default_policy must be 'drop', 'block', or 'accept', got: invalid",
		},
		{
			name: "duplicate rule names",
			firewall: FirewallConfig{
				Enabled:       true,
				DefaultPolicy: "drop",
				Rules: []FirewallRule{
					{
						Name:      "allow-ssh",
						Interface: "public",
						Sources:   []string{"203.0.113.0/24"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
					{
						Name:      "allow-ssh",
						Interface: "private",
						Sources:   []string{"10.0.0.0/8"},
						Protocol:  "tcp",
						Ports:     []int{22},
						Action:    "accept",
					},
				},
			},
			wantErr: true,
			errMsg:  "duplicate rule name: allow-ssh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.firewall.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("FirewallConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("FirewallConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestMasqueradeConfig_Validate tests masquerade configuration validation
func TestMasqueradeConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":   "eth0",
		"loopback": "lo",
	}

	tests := []struct {
		name       string
		masquerade MasqueradeConfig
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid masquerade config",
			masquerade: MasqueradeConfig{
				Enabled:   true,
				Interface: "public",
			},
			wantErr: false,
		},
		{
			name: "masquerade disabled (no validation)",
			masquerade: MasqueradeConfig{
				Enabled:   false,
				Interface: "",
			},
			wantErr: false,
		},
		{
			name: "undefined interface",
			masquerade: MasqueradeConfig{
				Enabled:   true,
				Interface: "nonexistent",
			},
			wantErr: true,
			errMsg:  "masquerade references undefined interface: nonexistent",
		},
		{
			name: "loopback interface not allowed",
			masquerade: MasqueradeConfig{
				Enabled:   true,
				Interface: "loopback",
			},
			wantErr: true,
			errMsg:  "masquerade cannot use loopback interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.masquerade.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("MasqueradeConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("MasqueradeConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestRoutingConfig_Validate tests routing configuration validation
func TestRoutingConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public": "eth0",
	}

	tests := []struct {
		name    string
		routing RoutingConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid routing config",
			routing: RoutingConfig{
				Enabled:   true,
				IPForward: true,
				Masquerade: MasqueradeConfig{
					Enabled:   true,
					Interface: "public",
				},
			},
			wantErr: false,
		},
		{
			name: "ip_forward disabled",
			routing: RoutingConfig{
				Enabled:   true,
				IPForward: false,
				Masquerade: MasqueradeConfig{
					Enabled:   true,
					Interface: "public",
				},
			},
			wantErr: true,
			errMsg:  "routing.ip_forward must be true when routing is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.routing.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("RoutingConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("RoutingConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestBindConfig_Validate tests bind configuration validation
func TestBindConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":   "eth0",
		"loopback": "lo",
	}

	tests := []struct {
		name    string
		bind    BindConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid bind config",
			bind: BindConfig{
				Interface: "public",
				Port:      8080,
			},
			wantErr: false,
		},
		{
			name: "valid bind on loopback",
			bind: BindConfig{
				Interface: "loopback",
				Port:      8080,
			},
			wantErr: false,
		},
		{
			name: "undefined interface",
			bind: BindConfig{
				Interface: "nonexistent",
				Port:      8080,
			},
			wantErr: true,
			errMsg:  "bind references undefined interface: nonexistent",
		},
		{
			name: "invalid port too low",
			bind: BindConfig{
				Interface: "public",
				Port:      0,
			},
			wantErr: true,
			errMsg:  "bind port must be between 1 and 65535, got: 0",
		},
		{
			name: "invalid port too high",
			bind: BindConfig{
				Interface: "public",
				Port:      65536,
			},
			wantErr: true,
			errMsg:  "bind port must be between 1 and 65535, got: 65536",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.bind.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("BindConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("BindConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestInterceptConfig_Validate tests intercept configuration validation
func TestInterceptConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":  "eth0",
		"private": "eth1",
	}

	tests := []struct {
		name      string
		intercept InterceptConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name: "valid intercept config",
			intercept: InterceptConfig{
				Ports:         []int{80, 443},
				FromInterface: "private",
			},
			wantErr: false,
		},
		{
			name: "empty ports",
			intercept: InterceptConfig{
				Ports:         []int{},
				FromInterface: "private",
			},
			wantErr: true,
			errMsg:  "intercept.ports must contain at least one port",
		},
		{
			name: "invalid port",
			intercept: InterceptConfig{
				Ports:         []int{80, 99999},
				FromInterface: "private",
			},
			wantErr: true,
			errMsg:  "invalid intercept port: 99999",
		},
		{
			name: "undefined interface",
			intercept: InterceptConfig{
				Ports:         []int{80, 443},
				FromInterface: "nonexistent",
			},
			wantErr: true,
			errMsg:  "intercept references undefined interface: nonexistent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.intercept.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("InterceptConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("InterceptConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestBackendServer_Validate tests backend server validation
func TestBackendServer_Validate(t *testing.T) {
	tests := []struct {
		name    string
		server  BackendServer
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid server",
			server: BackendServer{
				IP:   "192.168.1.100",
				Port: 8080,
			},
			wantErr: false,
		},
		{
			name: "valid server with weight",
			server: BackendServer{
				IP:     "192.168.1.100",
				Port:   8080,
				Weight: 100,
			},
			wantErr: false,
		},
		{
			name: "valid server with weight 0 (means omitted/default)",
			server: BackendServer{
				IP:     "192.168.1.100",
				Port:   8080,
				Weight: 0, // Weight 0 means "use HAProxy default" (omitempty in JSON)
			},
			wantErr: false,
		},
		{
			name: "empty IP",
			server: BackendServer{
				IP:   "",
				Port: 8080,
			},
			wantErr: true,
			errMsg:  "backend server IP cannot be empty",
		},
		{
			name: "invalid IP",
			server: BackendServer{
				IP:   "not-an-ip",
				Port: 8080,
			},
			wantErr: true,
			errMsg:  "invalid backend server IP: not-an-ip",
		},
		{
			name: "invalid port",
			server: BackendServer{
				IP:   "192.168.1.100",
				Port: 0,
			},
			wantErr: true,
			errMsg:  "invalid backend server port: 0",
		},
		{
			name: "invalid weight too high",
			server: BackendServer{
				IP:     "192.168.1.100",
				Port:   8080,
				Weight: 257,
			},
			wantErr: true,
			errMsg:  "backend server weight must be between 1 and 256, got: 257",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.server.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("BackendServer.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("BackendServer.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestBackendsConfig_Validate tests backends configuration validation
func TestBackendsConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"private": "eth1",
	}

	tests := []struct {
		name     string
		backends BackendsConfig
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid backends config",
			backends: BackendsConfig{
				Interface: "private",
				Servers: []BackendServer{
					{IP: "192.168.1.100", Port: 8080},
					{IP: "192.168.1.101", Port: 8080},
				},
				LoadBalance: "roundrobin",
			},
			wantErr: false,
		},
		{
			name: "undefined interface",
			backends: BackendsConfig{
				Interface: "nonexistent",
				Servers: []BackendServer{
					{IP: "192.168.1.100", Port: 8080},
				},
			},
			wantErr: true,
			errMsg:  "backends references undefined interface: nonexistent",
		},
		{
			name: "empty servers",
			backends: BackendsConfig{
				Interface: "private",
				Servers:   []BackendServer{},
			},
			wantErr: true,
			errMsg:  "backends must have at least one server",
		},
		{
			name: "invalid load balance algorithm",
			backends: BackendsConfig{
				Interface: "private",
				Servers: []BackendServer{
					{IP: "192.168.1.100", Port: 8080},
				},
				LoadBalance: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid load_balance algorithm: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.backends.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("BackendsConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("BackendsConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestSSLConfig_Validate tests SSL configuration validation
func TestSSLConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ssl     SSLConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid ssl config",
			ssl: SSLConfig{
				Enabled: true,
				CertDir: "/etc/haproxy/certs",
			},
			wantErr: false,
		},
		{
			name: "empty cert_dir",
			ssl: SSLConfig{
				Enabled: true,
				CertDir: "",
			},
			wantErr: true,
			errMsg:  "ssl.cert_dir cannot be empty when SSL is enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ssl.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSLConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("SSLConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestProxyConfig_Validate tests proxy configuration validation
func TestProxyConfig_Validate(t *testing.T) {
	interfaces := InterfacesConfig{
		"public":   "eth0",
		"private":  "eth1",
		"loopback": "lo",
	}

	tests := []struct {
		name    string
		proxy   ProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid egress transparent proxy",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "egress",
				Type:    "transparent",
				Bind: BindConfig{
					Interface: "loopback",
					Port:      3128,
				},
				Intercept: &InterceptConfig{
					Ports:         []int{80, 443},
					FromInterface: "private",
				},
			},
			wantErr: false,
		},
		{
			name: "valid ingress reverse proxy",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "ingress",
				Type:    "reverse",
				Bind: BindConfig{
					Interface: "public",
					Port:      80,
				},
				Backends: &BackendsConfig{
					Interface: "private",
					Servers: []BackendServer{
						{IP: "192.168.1.100", Port: 8080},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "invalid",
				Type:    "transparent",
				Bind: BindConfig{
					Interface: "loopback",
					Port:      3128,
				},
			},
			wantErr: true,
			errMsg:  "proxy.mode must be 'egress' or 'ingress', got: invalid",
		},
		{
			name: "invalid type",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "egress",
				Type:    "invalid",
				Bind: BindConfig{
					Interface: "loopback",
					Port:      3128,
				},
			},
			wantErr: true,
			errMsg:  "proxy.type must be 'transparent' or 'reverse', got: invalid",
		},
		{
			name: "egress mode requires transparent type",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "egress",
				Type:    "reverse",
				Bind: BindConfig{
					Interface: "loopback",
					Port:      3128,
				},
			},
			wantErr: true,
			errMsg:  "egress mode requires type 'transparent'",
		},
		{
			name: "egress transparent requires intercept config",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "egress",
				Type:    "transparent",
				Bind: BindConfig{
					Interface: "loopback",
					Port:      3128,
				},
			},
			wantErr: true,
			errMsg:  "egress transparent proxy requires 'intercept' configuration",
		},
		{
			name: "ingress mode requires reverse type",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "ingress",
				Type:    "transparent",
				Bind: BindConfig{
					Interface: "public",
					Port:      80,
				},
			},
			wantErr: true,
			errMsg:  "ingress mode requires type 'reverse'",
		},
		{
			name: "ingress reverse requires backends config",
			proxy: ProxyConfig{
				Enabled: true,
				Mode:    "ingress",
				Type:    "reverse",
				Bind: BindConfig{
					Interface: "public",
					Port:      80,
				},
			},
			wantErr: true,
			errMsg:  "ingress reverse proxy requires 'backends' configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.proxy.Validate(interfaces)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProxyConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("ProxyConfig.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestConfig_Validate tests overall configuration validation
func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid egress config",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public":   "eth0",
					"private":  "eth1",
					"loopback": "lo",
				},
				Firewall: &FirewallConfig{
					Enabled:       true,
					DefaultPolicy: "drop",
					Rules: []FirewallRule{
						{
							Name:      "allow-proxy",
							Interface: "public",
							Sources:   []string{"178.62.33.58"},
							Protocol:  "tcp",
							Ports:     []int{3128},
							Action:    "accept",
						},
					},
				},
				Routing: &RoutingConfig{
					Enabled:   true,
					IPForward: true,
					Masquerade: MasqueradeConfig{
						Enabled:   true,
						Interface: "public",
					},
				},
				Proxy: &ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "transparent",
					Bind: BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
					Intercept: &InterceptConfig{
						Ports:         []int{80, 443},
						FromInterface: "private",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid firewall-only config",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
				Firewall: &FirewallConfig{
					Enabled:       true,
					DefaultPolicy: "drop",
					Rules: []FirewallRule{
						{
							Name:      "allow-ssh",
							Interface: "public",
							Sources:   []string{"203.0.113.0/24"},
							Protocol:  "tcp",
							Ports:     []int{22},
							Action:    "accept",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no modes enabled",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
			},
			wantErr: true,
			errMsg:  "at least one of firewall, routing, or proxy must be enabled",
		},
		{
			name: "invalid admin config",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
				Firewall: &FirewallConfig{
					Enabled:       true,
					DefaultPolicy: "drop",
				},
			},
			wantErr: true,
			errMsg:  "admin validation failed",
		},
		{
			name: "invalid interfaces config",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{},
				Firewall: &FirewallConfig{
					Enabled:       true,
					DefaultPolicy: "drop",
				},
			},
			wantErr: true,
			errMsg:  "interfaces validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
				t.Errorf("Config.Validate() error = %v, want error containing %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// TestLoad tests loading configuration from file
func TestLoad(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid config file",
			configJSON: `{
				"admin": {
					"sources": ["203.0.113.50"]
				},
				"interfaces": {
					"public": "eth0",
					"loopback": "lo"
				},
				"firewall": {
					"enabled": true,
					"default_policy": "drop",
					"rules": [
						{
							"name": "allow-ssh",
							"interface": "public",
							"sources": ["203.0.113.0/24"],
							"protocol": "tcp",
							"ports": [22],
							"action": "accept"
						}
					]
				}
			}`,
			wantErr: false,
		},
		{
			name: "invalid json",
			configJSON: `{
				"admin": {
					"sources": ["203.0.113.50"]
				}
				"interfaces": {}
			}`,
			wantErr: true,
			errMsg:  "error parsing config file",
		},
		{
			name: "config fails validation",
			configJSON: `{
				"admin": {
					"sources": []
				},
				"interfaces": {
					"public": "eth0"
				},
				"firewall": {
					"enabled": true,
					"default_policy": "drop"
				}
			}`,
			wantErr: true,
			errMsg:  "invalid configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			cfgFile := filepath.Join(tmpDir, "config.json")

			// Write config
			err := os.WriteFile(cfgFile, []byte(tt.configJSON), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			// Load config (skip runtime interface validation for unit tests)
			data, err := os.ReadFile(cfgFile)
			if err != nil {
				t.Fatalf("Failed to read config: %v", err)
			}

			var cfg Config
			err = json.Unmarshal(data, &cfg)
			if tt.wantErr && err != nil {
				// JSON parse error expected
				return
			}
			if err != nil {
				t.Fatalf("Unexpected JSON parse error: %v", err)
			}

			// Validate (but don't do runtime interface check)
			err = cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config validation error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

// TestApplyDefaults tests default value application
func TestApplyDefaults(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		expectedPorts  []int
		expectedFormat string
		expectedLB     string
	}{
		{
			name: "admin ports default to 22",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
			},
			expectedPorts: []int{22},
		},
		{
			name: "proxy logging format defaults to combined",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
				Proxy: &ProxyConfig{
					Logging: &ProxyLoggingConfig{
						Enabled: true,
						Path:    "/var/log/haproxy.log",
					},
				},
			},
			expectedFormat: "combined",
		},
		{
			name: "backend load balance defaults to roundrobin",
			config: Config{
				Admin: AdminConfig{
					Sources: []string{"203.0.113.50"},
				},
				Interfaces: InterfacesConfig{
					"public": "eth0",
				},
				Proxy: &ProxyConfig{
					Backends: &BackendsConfig{
						Interface: "public",
						Servers: []BackendServer{
							{IP: "192.168.1.100", Port: 8080},
						},
					},
				},
			},
			expectedLB: "roundrobin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.applyDefaults()

			if tt.expectedPorts != nil && len(tt.config.Admin.Ports) != len(tt.expectedPorts) {
				t.Errorf("Admin.Ports = %v, want %v", tt.config.Admin.Ports, tt.expectedPorts)
			}

			if tt.expectedFormat != "" && tt.config.Proxy != nil && tt.config.Proxy.Logging != nil {
				if tt.config.Proxy.Logging.Format != tt.expectedFormat {
					t.Errorf("Proxy.Logging.Format = %v, want %v", tt.config.Proxy.Logging.Format, tt.expectedFormat)
				}
			}

			if tt.expectedLB != "" && tt.config.Proxy != nil && tt.config.Proxy.Backends != nil {
				if tt.config.Proxy.Backends.LoadBalance != tt.expectedLB {
					t.Errorf("Proxy.Backends.LoadBalance = %v, want %v", tt.config.Proxy.Backends.LoadBalance, tt.expectedLB)
				}
			}
		})
	}
}

// TestIsValidIPOrCIDR tests IP and CIDR validation helper
func TestIsValidIPOrCIDR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "valid ipv4", input: "192.168.1.1", want: true},
		{name: "valid ipv4 cidr", input: "192.168.1.0/24", want: true},
		{name: "valid ipv6", input: "2001:db8::1", want: true},
		{name: "valid ipv6 cidr", input: "2001:db8::/32", want: true},
		{name: "invalid ip", input: "not-an-ip", want: false},
		{name: "invalid cidr", input: "192.168.1.0/33", want: false},
		{name: "empty string", input: "", want: false},
		{name: "partial ip", input: "192.168", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIPOrCIDR(tt.input)
			if got != tt.want {
				t.Errorf("isValidIPOrCIDR(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// contains checks if a string contains a substring (helper for tests)
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
