package haproxy

import (
	"os"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
)

// TestNewManager tests manager creation
func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	expectedPath := "/etc/haproxy/haproxy.cfg"
	if mgr.ConfigPath != expectedPath {
		t.Errorf("ConfigPath = %s, want %s", mgr.ConfigPath, expectedPath)
	}
}

// TestGenerateEgressConfig tests egress transparent proxy config generation
func TestGenerateEgressConfig(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		wantContains   []string
		wantNotContain []string
		wantErr        bool
	}{
		{
			name: "basic egress transparent proxy",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "transparent",
					Bind: config.BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
					Intercept: &config.InterceptConfig{
						FromInterface: "external",
						Ports:         []int{80, 443},
					},
				},
			},
			wantContains: []string{
				"Transparent Egress Proxy",
				"bind 127.0.0.1:3128 transparent",
				"mode tcp",
				"source 0.0.0.0 usesrc clientip",
				"listen stats",
				"bind *:9000",
			},
			wantErr: false,
		},
		{
			name: "egress with custom logging",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "transparent",
					Bind: config.BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
					Intercept: &config.InterceptConfig{
						FromInterface: "loopback",
						Ports:         []int{80, 443},
					},
					Logging: &config.ProxyLoggingConfig{
						Enabled: true,
						Format:  "json",
					},
				},
			},
			wantContains: []string{
				"log-format",
				`"time":"%t"`,
				`"client":"%ci"`,
			},
			wantErr: false,
		},
		{
			name: "egress requires transparent type",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "reverse", // Wrong type
					Bind: config.BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "egress requires intercept config",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "transparent",
					Bind: config.BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
					Intercept: nil, // Missing
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager()
			haproxyConfig, err := mgr.generateEgressConfig(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateEgressConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(haproxyConfig, want) {
					t.Errorf("Config does not contain %q\nConfig:\n%s", want, haproxyConfig)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(haproxyConfig, notWant) {
					t.Errorf("Config should not contain %q\nConfig:\n%s", notWant, haproxyConfig)
				}
			}
		})
	}
}

// TestGenerateIngressConfig tests ingress reverse proxy config generation
func TestGenerateIngressConfig(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.Config
		wantContains   []string
		wantNotContain []string
		wantErr        bool
	}{
		{
			name: "basic ingress reverse proxy",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
					Backends: &config.BackendsConfig{
						Interface:   "external",
						LoadBalance: "roundrobin",
						Servers: []config.BackendServer{
							{IP: "10.0.1.10", Port: 8080, Weight: 1},
							{IP: "10.0.1.11", Port: 8080, Weight: 1},
						},
					},
				},
			},
			wantContains: []string{
				"Reverse Ingress Proxy",
				"mode http",
				"balance roundrobin",
				"server backend1 10.0.1.10:8080",
				"server backend2 10.0.1.11:8080",
			},
			wantErr: false,
		},
		{
			name: "ingress with health checks",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
					Backends: &config.BackendsConfig{
						Interface:   "external",
						LoadBalance: "leastconn",
						Servers: []config.BackendServer{
							{IP: "10.0.1.10", Port: 8080, Weight: 2},
						},
						HealthCheck: &config.HealthCheckConfig{
							Enabled:  true,
							Interval: "5s",
							Timeout:  "2s",
							Path:     "/health",
							Method:   "GET",
						},
					},
				},
			},
			wantContains: []string{
				"balance leastconn",
				"option httpchk GET /health",
				"timeout check 2s",
				"check inter 5s",
				"weight 2",
			},
			wantErr: false,
		},
		{
			name: "ingress with SSL",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      443,
					},
					SSL: &config.SSLConfig{
						Enabled: true,
						CertDir: "/etc/ssl/certs",
					},
					Backends: &config.BackendsConfig{
						Interface:   "external",
						LoadBalance: "roundrobin",
						Servers: []config.BackendServer{
							{IP: "10.0.1.10", Port: 8080},
						},
					},
				},
			},
			wantContains: []string{
				"ssl-default-bind-ciphers",
				"ssl-default-bind-options ssl-min-ver TLSv1.2",
				"bind",
				"ssl crt /etc/ssl/certs",
			},
			wantErr: false,
		},
		{
			name: "ingress with custom logging",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
					Logging: &config.ProxyLoggingConfig{
						Enabled: true,
						Format:  "combined",
					},
					Backends: &config.BackendsConfig{
						Interface:   "external",
						LoadBalance: "roundrobin",
						Servers: []config.BackendServer{
							{IP: "10.0.1.10", Port: 8080},
						},
					},
				},
			},
			wantContains: []string{
				"log-format",
				"%ci:%cp",
			},
			wantErr: false,
		},
		{
			name: "ingress requires reverse type",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "transparent", // Wrong type
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ingress requires backends config",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
					Backends: nil, // Missing
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager()
			haproxyConfig, err := mgr.generateIngressConfig(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("generateIngressConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(haproxyConfig, want) {
					t.Errorf("Config does not contain %q\nConfig:\n%s", want, haproxyConfig)
				}
			}

			for _, notWant := range tt.wantNotContain {
				if strings.Contains(haproxyConfig, notWant) {
					t.Errorf("Config should not contain %q\nConfig:\n%s", notWant, haproxyConfig)
				}
			}
		})
	}
}

// TestResolveInterfaceIP tests interface IP resolution
func TestResolveInterfaceIP(t *testing.T) {
	tests := []struct {
		name        string
		interfaces  config.InterfacesConfig
		logicalName string
		wantIP      string
		wantErr     bool
	}{
		{
			name: "loopback interface",
			interfaces: config.InterfacesConfig{
				"loopback": "lo",
			},
			logicalName: "loopback",
			wantIP:      "127.0.0.1",
			wantErr:     false,
		},
		{
			name: "interface not found in config",
			interfaces: config.InterfacesConfig{
				"external": "eth0",
			},
			logicalName: "internal",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager()
			ip, err := mgr.resolveInterfaceIP(tt.interfaces, tt.logicalName)

			if (err != nil) != tt.wantErr {
				t.Errorf("resolveInterfaceIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if ip != tt.wantIP {
				t.Errorf("resolveInterfaceIP() = %v, want %v", ip, tt.wantIP)
			}
		})
	}
}

// TestGetLogFormat tests log format generation
func TestGetLogFormat(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		wantContains []string
	}{
		{
			name:   "json format",
			format: "json",
			wantContains: []string{
				`"time":"%t"`,
				`"client":"%ci"`,
				`"frontend":"%f"`,
				`"backend":"%b"`,
			},
		},
		{
			name:   "combined format",
			format: "combined",
			wantContains: []string{
				"%ci:%cp",
				"%Tw/%Tc/%Tt",
				"%ac/%fc/%bc/%sc/%rc",
			},
		},
		{
			name:   "default format (empty)",
			format: "",
			wantContains: []string{
				"%ci:%cp",
				"%Tw/%Tc/%Tt",
			},
		},
		{
			name:   "unknown format defaults to combined",
			format: "unknown",
			wantContains: []string{
				"%ci:%cp",
				"%Tw/%Tc/%Tt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager()
			logFormat := mgr.getLogFormat(tt.format)

			for _, want := range tt.wantContains {
				if !strings.Contains(logFormat, want) {
					t.Errorf("Log format does not contain %q\nFormat: %s", want, logFormat)
				}
			}
		})
	}
}

// TestValidateConfig tests config validation (requires haproxy binary)
func TestValidateConfig(t *testing.T) {
	t.Skip("Skipping - requires haproxy binary (integration test needed)")

	mgr := NewManager()

	// Valid config
	validConfig := `global
    log /dev/log local0
    daemon

defaults
    log     global
    mode    tcp
    timeout connect 5000
    timeout client  50000
    timeout server  50000
`

	err := mgr.validateConfig(validConfig)
	if err != nil {
		t.Errorf("validateConfig() failed for valid config: %v", err)
	}

	// Invalid config
	invalidConfig := `this is not valid haproxy config`
	err = mgr.validateConfig(invalidConfig)
	if err == nil {
		t.Error("validateConfig() should fail for invalid config")
	}
}

// TestGenerateConfig tests full config generation and writing
func TestGenerateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "egress mode",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "egress",
					Type:    "transparent",
					Bind: config.BindConfig{
						Interface: "loopback",
						Port:      3128,
					},
					Intercept: &config.InterceptConfig{
						FromInterface: "external",
						Ports:         []int{80, 443},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ingress mode",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"external": "eth0",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "ingress",
					Type:    "reverse",
					Bind: config.BindConfig{
						Interface: "external",
						Port:      80,
					},
					Backends: &config.BackendsConfig{
						Interface:   "external",
						LoadBalance: "roundrobin",
						Servers: []config.BackendServer{
							{IP: "10.0.1.10", Port: 8080},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "proxy not enabled",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
				},
				Proxy: &config.ProxyConfig{
					Enabled: false,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid mode",
			cfg: &config.Config{
				Interfaces: config.InterfacesConfig{
					"loopback": "lo",
				},
				Proxy: &config.ProxyConfig{
					Enabled: true,
					Mode:    "invalid",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip validation for this test
			t.Skip("Skipping - requires haproxy binary for validation (integration test needed)")

			tmpDir := t.TempDir()
			configPath := tmpDir + "/haproxy.cfg"

			mgr := &Manager{
				ConfigPath: configPath,
			}

			err := mgr.GenerateConfig(tt.cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check that file was written
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				t.Errorf("Config file was not written to %s", configPath)
			}

			// Read and verify content
			content, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("Failed to read generated config: %v", err)
			}

			configStr := string(content)
			if !strings.Contains(configStr, "HAProxy Configuration") {
				t.Error("Generated config does not contain expected header")
			}
		})
	}
}

// TestServiceManagement tests service management functions
func TestServiceManagement(t *testing.T) {
	t.Skip("Skipping - requires systemctl and haproxy service (integration test needed)")

	mgr := NewManager()

	// Test Reload
	err := mgr.Reload()
	if err != nil {
		t.Logf("Reload() returned error (expected if haproxy not installed): %v", err)
	}

	// Test Restart
	err = mgr.Restart()
	if err != nil {
		t.Logf("Restart() returned error (expected if haproxy not installed): %v", err)
	}

	// Test Enable
	err = mgr.Enable()
	if err != nil {
		t.Logf("Enable() returned error (expected if haproxy not installed): %v", err)
	}

	// Test GetStatus
	status, err := mgr.GetStatus()
	if err != nil {
		t.Logf("GetStatus() returned error (expected if haproxy not installed): %v", err)
	}
	_ = status
}

// TestConfigPathCustomization tests custom config path
func TestConfigPathCustomization(t *testing.T) {
	customPath := "/custom/path/haproxy.cfg"
	mgr := &Manager{
		ConfigPath: customPath,
	}

	if mgr.ConfigPath != customPath {
		t.Errorf("ConfigPath = %s, want %s", mgr.ConfigPath, customPath)
	}
}

// TestEgressConfigStructure tests the structure of generated egress config
func TestEgressConfigStructure(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			"loopback": "lo",
		},
		Proxy: &config.ProxyConfig{
			Enabled: true,
			Mode:    "egress",
			Type:    "transparent",
			Bind: config.BindConfig{
				Interface: "loopback",
				Port:      3128,
			},
			Intercept: &config.InterceptConfig{
				FromInterface: "loopback",
				Ports:         []int{80, 443},
			},
		},
	}

	mgr := NewManager()
	haproxyConfig, err := mgr.generateEgressConfig(cfg)
	if err != nil {
		t.Fatalf("generateEgressConfig() failed: %v", err)
	}

	// Check config structure
	requiredSections := []string{
		"global",
		"defaults",
		"frontend transparent_proxy",
		"backend transparent_backend",
		"listen stats",
	}

	for _, section := range requiredSections {
		if !strings.Contains(haproxyConfig, section) {
			t.Errorf("Config missing required section: %s", section)
		}
	}

	// Check global section settings
	globalSettings := []string{
		"log /dev/log",
		"chroot /var/lib/haproxy",
		"stats socket /run/haproxy/admin.sock",
		"user haproxy",
		"group haproxy",
		"daemon",
	}

	for _, setting := range globalSettings {
		if !strings.Contains(haproxyConfig, setting) {
			t.Errorf("Config missing global setting: %s", setting)
		}
	}
}

// TestIngressConfigStructure tests the structure of generated ingress config
func TestIngressConfigStructure(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			"external": "eth0",
		},
		Proxy: &config.ProxyConfig{
			Enabled: true,
			Mode:    "ingress",
			Type:    "reverse",
			Bind: config.BindConfig{
				Interface: "external",
				Port:      80,
			},
			Backends: &config.BackendsConfig{
				Interface:   "external",
				LoadBalance: "roundrobin",
				Servers: []config.BackendServer{
					{IP: "10.0.1.10", Port: 8080, Weight: 1},
					{IP: "10.0.1.11", Port: 8080, Weight: 2},
				},
			},
		},
	}

	mgr := NewManager()
	haproxyConfig, err := mgr.generateIngressConfig(cfg)
	if err != nil {
		t.Fatalf("generateIngressConfig() failed: %v", err)
	}

	// Check config structure
	requiredSections := []string{
		"global",
		"defaults",
		"frontend http_front",
		"backend app_backend",
		"listen stats",
	}

	for _, section := range requiredSections {
		if !strings.Contains(haproxyConfig, section) {
			t.Errorf("Config missing required section: %s", section)
		}
	}

	// Check HTTP-specific settings
	httpSettings := []string{
		"mode    http",
		"option  httplog",
		"option  forwardfor",
	}

	for _, setting := range httpSettings {
		if !strings.Contains(haproxyConfig, setting) {
			t.Errorf("Config missing HTTP setting: %s", setting)
		}
	}

	// Check that both backend servers are present
	if !strings.Contains(haproxyConfig, "server backend1 10.0.1.10:8080") {
		t.Error("Config missing backend1 server")
	}
	if !strings.Contains(haproxyConfig, "server backend2 10.0.1.11:8080") {
		t.Error("Config missing backend2 server")
	}

	// Check weights
	if !strings.Contains(haproxyConfig, "weight 1") {
		t.Error("Config missing weight 1")
	}
	if !strings.Contains(haproxyConfig, "weight 2") {
		t.Error("Config missing weight 2")
	}
}
