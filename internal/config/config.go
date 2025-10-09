package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Config represents the unified configuration for both egress and ingress modes
type Config struct {
	Mode string `json:"mode"` // "egress" or "ingress"

	// Egress-specific configuration
	Egress *EgressConfig `json:"egress,omitempty"`

	// Ingress-specific configuration
	Ingress *IngressConfig `json:"ingress,omitempty"`

	// Shared HAProxy configuration
	HAProxy HAProxyConfig `json:"haproxy"`

	// Daemon configuration (for scheduled checks/monitoring)
	Daemon DaemonConfig `json:"daemon"`

	// Logging configuration
	Logging LoggingConfig `json:"logging"`

	// Alert configuration
	Alerts []AlertConfig `json:"alerts"`
}

// EgressConfig contains egress-specific settings
type EgressConfig struct {
	// Private IP of the egress proxy server
	PrivateIP string `json:"private_ip"`

	// Public IP of the egress proxy server
	PublicIP string `json:"public_ip"`

	// HAProxy port for transparent proxy
	Port int `json:"port"`

	// ACL file path
	ACLFile string `json:"acl_file"`

	// Auto-reload HAProxy when ACL changes
	AutoReload bool `json:"auto_reload"`

	// Server check configuration
	Checks ServerCheckConfig `json:"checks"`
}

// IngressConfig contains ingress-specific settings
type IngressConfig struct {
	// Reserved IPs (DigitalOcean floating IPs)
	ReservedIPs []string `json:"reserved_ips"`

	// Backends directory or config source
	BackendsSource BackendSource `json:"backends"`

	// SSL certificate directory or config source
	SSLSource SSLSource `json:"ssl"`

	// Health check configuration
	HealthChecks HealthCheckConfig `json:"health_checks"`

	// Load balancing algorithm
	Algorithm string `json:"algorithm"` // roundrobin, leastconn, source
}

// BackendSource defines where backend configuration comes from
type BackendSource struct {
	// Type: "file", "consul", "etcd", "api"
	Type string `json:"type"`

	// Path for file-based config
	Path string `json:"path,omitempty"`

	// URL for remote config (consul, etcd, API)
	URL string `json:"url,omitempty"`

	// Refresh interval for remote config
	RefreshInterval string `json:"refresh_interval,omitempty"`
}

// SSLSource defines where SSL certificates come from
type SSLSource struct {
	// Type: "file", "vault", "certbot"
	Type string `json:"type"`

	// Directory for file-based certs
	Directory string `json:"directory,omitempty"`

	// Vault configuration
	VaultURL  string `json:"vault_url,omitempty"`
	VaultPath string `json:"vault_path,omitempty"`
}

// ServerCheckConfig for egress server health checks
type ServerCheckConfig struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"` // "1h", "30m"
	Parallel bool   `json:"parallel"`
	SSHUser  string `json:"ssh_user"`
	SSHKey   string `json:"ssh_key"`
	Timeout  string `json:"timeout"`
}

// HealthCheckConfig for ingress backend health checks
type HealthCheckConfig struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
	Path     string `json:"path"`   // HTTP path to check
	Method   string `json:"method"` // GET, HEAD
}

// HAProxyConfig contains HAProxy-specific settings (shared)
type HAProxyConfig struct {
	ConfigFile string `json:"config_file"`
	Binary     string `json:"binary"`
	SocketFile string `json:"socket_file"`
	StatsPort  int    `json:"stats_port"`
	StatsUser  string `json:"stats_user"`
	StatsPass  string `json:"stats_pass"`
}

// DaemonConfig for background monitoring/automation
type DaemonConfig struct {
	Enabled    bool   `json:"enabled"`
	PIDFile    string `json:"pid_file"`
	LogFile    string `json:"log_file"`
	Interval   string `json:"interval"`
	WorkerPool int    `json:"worker_pool"`
}

// LoggingConfig for structured logging
type LoggingConfig struct {
	Level  string `json:"level"`  // debug, info, warn, error
	Format string `json:"format"` // json, text
	Output string `json:"output"` // stdout, file path
}

// AlertConfig for alert integrations
type AlertConfig struct {
	Type         string            `json:"type"` // slack, email, pagerduty, webhook
	Enabled      bool              `json:"enabled"`
	FailuresOnly bool              `json:"failures_only"`
	Config       map[string]string `json:"config"`
}

// Load reads configuration from file, environment, or defaults
func Load(mode string, cfgFile string) (*Config, error) {
	// Start with defaults
	cfg := defaultConfig(mode)

	// Find and load config file
	configPath := cfgFile
	if configPath == "" {
		configPath = findConfigFile(mode)
	}

	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("error reading config file %s: %w", configPath, err)
		}

		// Parse JSON
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("error parsing config file %s: %w", configPath, err)
		}
	}

	// Apply environment variable overrides
	applyEnvOverrides(&cfg)

	// Set mode if not specified in config
	if cfg.Mode == "" {
		cfg.Mode = mode
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// defaultConfig returns a Config with sensible defaults
func defaultConfig(mode string) Config {
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/root"
	}

	return Config{
		Mode: mode,
		Egress: &EgressConfig{
			Port:       8080,
			ACLFile:    "/etc/haproxy/acl.lst",
			AutoReload: true,
			Checks: ServerCheckConfig{
				Enabled:  true,
				Interval: "1h",
				Parallel: true,
				SSHUser:  "root",
				SSHKey:   filepath.Join(homeDir, ".ssh/id_rsa"),
				Timeout:  "30s",
			},
		},
		Ingress: &IngressConfig{
			BackendsSource: BackendSource{
				Type: "file",
				Path: "/etc/haproxy/backends.d",
			},
			SSLSource: SSLSource{
				Type:      "file",
				Directory: "/etc/ssl/haproxy",
			},
			HealthChecks: HealthCheckConfig{
				Enabled:  true,
				Interval: "10s",
				Timeout:  "5s",
				Path:     "/health",
				Method:   "GET",
			},
			Algorithm: "roundrobin",
		},
		HAProxy: HAProxyConfig{
			ConfigFile: "/etc/haproxy/haproxy.cfg",
			Binary:     "/usr/sbin/haproxy",
			SocketFile: "/run/haproxy/admin.sock",
			StatsPort:  9000,
		},
		Daemon: DaemonConfig{
			Enabled:    false,
			PIDFile:    "/var/run/proxyctl.pid",
			LogFile:    "/var/log/proxyctl.log",
			Interval:   "5m",
			WorkerPool: 10,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
	}
}

// findConfigFile searches for config file in standard paths
func findConfigFile(mode string) string {
	filename := mode + ".json"
	homeDir := os.Getenv("HOME")

	searchPaths := []string{
		filename, // Current directory
		filepath.Join(homeDir, ".config", "proxyctl", filename), // User config
		filepath.Join("/etc", "proxyctl", filename),             // System config
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "" // No config file found (will use defaults)
}

// applyEnvOverrides applies environment variable overrides to config
// Supports PROXYCTL_* prefix for all config values
func applyEnvOverrides(cfg *Config) {
	// Mode
	if val := os.Getenv("PROXYCTL_MODE"); val != "" {
		cfg.Mode = val
	}

	// Egress overrides
	if cfg.Egress != nil {
		if val := os.Getenv("PROXYCTL_EGRESS_PRIVATE_IP"); val != "" {
			cfg.Egress.PrivateIP = val
		}
		if val := os.Getenv("PROXYCTL_EGRESS_PUBLIC_IP"); val != "" {
			cfg.Egress.PublicIP = val
		}
		if val := os.Getenv("PROXYCTL_EGRESS_PORT"); val != "" {
			if port, err := strconv.Atoi(val); err == nil {
				cfg.Egress.Port = port
			}
		}
		if val := os.Getenv("PROXYCTL_EGRESS_ACL_FILE"); val != "" {
			cfg.Egress.ACLFile = val
		}
		if val := os.Getenv("PROXYCTL_EGRESS_AUTO_RELOAD"); val != "" {
			cfg.Egress.AutoReload = val == "true" || val == "1"
		}
	}

	// HAProxy overrides
	if val := os.Getenv("PROXYCTL_HAPROXY_CONFIG_FILE"); val != "" {
		cfg.HAProxy.ConfigFile = val
	}
	if val := os.Getenv("PROXYCTL_HAPROXY_BINARY"); val != "" {
		cfg.HAProxy.Binary = val
	}
	if val := os.Getenv("PROXYCTL_HAPROXY_SOCKET_FILE"); val != "" {
		cfg.HAProxy.SocketFile = val
	}
	if val := os.Getenv("PROXYCTL_HAPROXY_STATS_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			cfg.HAProxy.StatsPort = port
		}
	}

	// Logging overrides
	if val := os.Getenv("PROXYCTL_LOGGING_LEVEL"); val != "" {
		cfg.Logging.Level = val
	}
	if val := os.Getenv("PROXYCTL_LOGGING_FORMAT"); val != "" {
		cfg.Logging.Format = val
	}
	if val := os.Getenv("PROXYCTL_LOGGING_OUTPUT"); val != "" {
		cfg.Logging.Output = val
	}

	// Daemon overrides
	if val := os.Getenv("PROXYCTL_DAEMON_ENABLED"); val != "" {
		cfg.Daemon.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv("PROXYCTL_DAEMON_INTERVAL"); val != "" {
		cfg.Daemon.Interval = val
	}
}

// Validate checks configuration for errors
func (c *Config) Validate() error {
	if c.Mode != "egress" && c.Mode != "ingress" && c.Mode != "proxyctl" {
		return fmt.Errorf("invalid mode: %s (must be egress, ingress, or proxyctl)", c.Mode)
	}

	// Mode-specific validation
	if c.Mode == "egress" && c.Egress == nil {
		return fmt.Errorf("egress configuration required when mode is egress")
	}
	if c.Mode == "ingress" && c.Ingress == nil {
		return fmt.Errorf("ingress configuration required when mode is ingress")
	}

	return nil
}

// IsEphemeral returns true if this is an ephemeral deployment
// (ingress mode with remote config sources)
func (c *Config) IsEphemeral() bool {
	if c.Mode != "ingress" || c.Ingress == nil {
		return false
	}

	// Check if using remote config sources (indicates ephemeral)
	return c.Ingress.BackendsSource.Type != "file" || c.Ingress.SSLSource.Type != "file"
}
