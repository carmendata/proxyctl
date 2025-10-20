package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Logger constants
const (
	DefaultLogPath      = "/var/log/proxyctl/"
	MaxLoggerNameLength = 32
)

// Config represents the unified configuration for both egress and ingress modes
type Config struct {
	Mode string `json:"mode"` // "egress" or "ingress"

	// Shared HAProxy configuration
	HAProxy HAProxyConfig `json:"haproxy"`

	// Daemon configuration (for scheduled checks/monitoring)
	Daemon DaemonConfig `json:"daemon"`

	// Logging configuration
	Logging LoggingConfig `json:"logging"`

	// Alert configuration
	Alerts []AlertConfig `json:"alerts"`

	// V2 configuration format (v0.8.0+)
	// Simple, flatter config structure
	Proxy    *ProxyConfig    `json:"proxy,omitempty"`
	ACL      *ACLConfig      `json:"acl,omitempty"`
	Firewall *FirewallConfig `json:"firewall,omitempty"`
	Redirect *RedirectConfig `json:"redirect,omitempty"`
	Logger   *LoggerConfig   `json:"logger,omitempty"`
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

// ProxyConfig defines proxy server settings (v0.8.0+)
// Supports multiple formats for flexibility:
// - String: "10.16.0.5" or "10.16.0.5:8080"
// - Object: {"ip": "10.16.0.5", "port": 8080}
type ProxyConfig struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	StatsPort int    `json:"stats_port,omitempty"`
}

// ACLConfig defines ACL file location (v0.8.0+)
type ACLConfig struct {
	File string `json:"file"`
}

// FirewallConfig defines INPUT filtering and FORWARD rules (v0.8.0+)
type FirewallConfig struct {
	Enabled          bool                 `json:"enabled"`
	InputPolicy      string               `json:"input_policy"` // Required: "drop", "block", or "ignore"
	AllowSSHFrom     []string             `json:"allow_ssh_from,omitempty"`
	AllowProxyFrom   []AllowProxyFromRule `json:"allow_proxy_from,omitempty"`
	ForwardPolicy    string               `json:"forward_policy,omitempty"`     // Optional: "drop" or "accept" (default: "drop")
	AllowForwardFrom []ForwardRule        `json:"allow_forward_from,omitempty"` // FORWARD chain rules (v0.10.0+)
}

// AllowProxyFromRule defines source IPs and optional ports
type AllowProxyFromRule struct {
	Sources []string `json:"sources"`         // IPs or CIDR blocks
	Ports   []int    `json:"ports,omitempty"` // Optional: specific ports
}

// ForwardRule defines FORWARD chain rules (v0.10.0+)
// Used for gateway/forwarding scenarios where traffic is routed through the server
type ForwardRule struct {
	Sources      []string `json:"sources"`                // Source IPs/CIDRs that can be forwarded
	Destinations []string `json:"destinations,omitempty"` // Destination IPs/CIDRs (default: ["0.0.0.0/0"])
	Protocols    []string `json:"protocols,omitempty"`    // Protocol filter: "tcp", "udp", "icmp" (default: all)
	Ports        []int    `json:"ports,omitempty"`        // Optional destination port filter
	Masquerade   bool     `json:"masquerade,omitempty"`   // Enable MASQUERADE/SNAT for this rule
	Comment      string   `json:"comment,omitempty"`      // Optional comment for documentation
}

// RedirectConfig defines OUTPUT redirect rules (v0.8.0+)
type RedirectConfig struct {
	Enabled bool     `json:"enabled"`
	Type    string   `json:"type"`              // "partial" or "full"
	Targets []string `json:"targets,omitempty"` // Required for "partial", ignored for "full"
}

// LoggerConfig defines connection logging settings (v0.8.0+)
// Supports comprehensive traffic monitoring with flexible filtering
type LoggerConfig struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`               // REQUIRED: Logger name (used for log files, prefixes, etc.)
	LogPath string `json:"log_path,omitempty"` // Optional: Log directory (default: /var/log/proxyctl/)

	// DEPRECATED: Use Name + LogPath instead
	Output string `json:"output,omitempty"` // Old field, will be migrated automatically

	// Chain selection (which netfilter chains to hook)
	// Default: ["OUTPUT"] for egress monitoring
	// Options: "OUTPUT", "INPUT", "FORWARD"
	Chains []string `json:"chains,omitempty"`

	// Protocol filtering (which protocols to monitor)
	// Default: ["tcp", "udp"]
	// Options: "tcp", "udp", "icmp", "all"
	Protocols []string `json:"protocols,omitempty"`

	// Category inclusion (add special IP ranges to monitoring)
	// These flags ADD to the base set (public IPs)
	IncludePrivate   bool `json:"include_private,omitempty"`   // RFC1918 + link-local (10.x, 172.16.x, 192.168.x, 169.254.x)
	IncludeLoopback  bool `json:"include_loopback,omitempty"`  // 127.0.0.0/8
	IncludeMulticast bool `json:"include_multicast,omitempty"` // 224.0.0.0/4, 240.0.0.0/4

	// Range filtering (fine-grained control)
	// include_ranges: If non-empty, acts as WHITELIST (intersection with base set)
	// exclude_ranges: Acts as BLACKLIST (subtraction from result)
	// Processing order: Categories → IncludeRanges (whitelist) → ExcludeRanges (blacklist)
	IncludeRanges []string `json:"include_ranges,omitempty"` // Whitelist specific IPs/CIDRs
	ExcludeRanges []string `json:"exclude_ranges,omitempty"` // Blacklist specific IPs/CIDRs
}

// UnmarshalJSON implements custom unmarshaling for Config
// Handles the special case where "proxy" can be either a string or an object
func (c *Config) UnmarshalJSON(data []byte) error {
	// First, unmarshal into a temporary map to inspect the proxy field
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Handle proxy field specially if it exists
	if proxyRaw, ok := raw["proxy"]; ok {
		// Try to unmarshal as string first
		var proxyStr string
		if err := json.Unmarshal(proxyRaw, &proxyStr); err == nil {
			// String format: parse it
			c.Proxy = parseProxyString(proxyStr)
			// Remove proxy from raw map so we don't unmarshal it again
			delete(raw, "proxy")
		} else {
			// Object format: unmarshal normally
			var proxyObj ProxyConfig
			if err := json.Unmarshal(proxyRaw, &proxyObj); err != nil {
				return fmt.Errorf("invalid proxy format: %w", err)
			}
			c.Proxy = &proxyObj
			delete(raw, "proxy")
		}
	}

	// Reconstruct the JSON without the proxy field
	modifiedData, err := json.Marshal(raw)
	if err != nil {
		return err
	}

	// Unmarshal the rest of the fields using a type alias to avoid recursion
	type ConfigAlias Config
	var alias ConfigAlias
	if err := json.Unmarshal(modifiedData, &alias); err != nil {
		return err
	}

	// Copy fields from alias to c (except Proxy which we already set)
	c.Mode = alias.Mode
	c.HAProxy = alias.HAProxy
	c.Daemon = alias.Daemon
	c.Logging = alias.Logging
	c.Alerts = alias.Alerts
	c.ACL = alias.ACL
	c.Firewall = alias.Firewall
	c.Redirect = alias.Redirect
	c.Logger = alias.Logger

	return nil
}

// parseProxyString parses a proxy string into ProxyConfig
// Supports formats: "10.16.0.5" or "10.16.0.5:8080"
func parseProxyString(s string) *ProxyConfig {
	parts := splitHostPort(s)
	ip := parts[0]
	port := 8080 // Default port

	if len(parts) > 1 {
		if p, err := strconv.Atoi(parts[1]); err == nil {
			port = p
		}
	}

	return &ProxyConfig{
		IP:   ip,
		Port: port,
	}
}

// splitHostPort splits a string like "10.16.0.5:8080" into ["10.16.0.5", "8080"]
// Handles IPv6 addresses and plain IPs without ports
func splitHostPort(s string) []string {
	// Simple case: no colon
	if idx := findLastColon(s); idx == -1 {
		return []string{s}
	} else {
		return []string{s[:idx], s[idx+1:]}
	}
}

// findLastColon finds the last colon in a string (for port separation)
func findLastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
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

		// Migrate logger config if needed (old 'output' field → new 'name' + 'log_path')
		if err := migrateLoggerConfig(&cfg, configPath); err != nil {
			return nil, fmt.Errorf("error migrating logger config: %w", err)
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

// migrateLoggerConfig migrates old logger config format to new format
// Old format: {"output": "/var/log/proxyctl/egress.log"}
// New format: {"name": "egress", "log_path": "/var/log/proxyctl/"}
func migrateLoggerConfig(cfg *Config, configPath string) error {
	if cfg.Logger == nil {
		return nil // No logger config
	}

	// Check if migration needed
	if cfg.Logger.Output != "" && cfg.Logger.Name == "" {
		fmt.Println("Migrating old logger config format...")

		// Step 1: Backup original config file
		backupPath := configPath + ".pre-v0.3.backup"
		if err := copyFile(configPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup config: %w", err)
		}
		fmt.Printf("Config backup saved: %s\n", backupPath)

		// Step 2: Set name to "egress" (will be normalized to lowercase in validation)
		cfg.Logger.Name = "egress"

		// Step 3: Remove output field by creating a new LoggerConfig without it
		// We need to explicitly create a new struct to ensure output is not marshaled
		oldLogger := cfg.Logger
		cfg.Logger = &LoggerConfig{
			Enabled:          oldLogger.Enabled,
			Name:             "egress",
			LogPath:          "", // Use default
			Chains:           oldLogger.Chains,
			Protocols:        oldLogger.Protocols,
			IncludePrivate:   oldLogger.IncludePrivate,
			IncludeLoopback:  oldLogger.IncludeLoopback,
			IncludeMulticast: oldLogger.IncludeMulticast,
			IncludeRanges:    oldLogger.IncludeRanges,
			ExcludeRanges:    oldLogger.ExcludeRanges,
		}

		// Step 4: Write updated config to disk
		updatedData, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal migrated config: %w", err)
		}

		if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
			// Restore from backup on failure
			if restoreErr := copyFile(backupPath, configPath); restoreErr != nil {
				return fmt.Errorf("failed to write migrated config AND restore backup: %w (restore error: %v)", err, restoreErr)
			}
			return fmt.Errorf("failed to write migrated config: %w", err)
		}

		fmt.Printf("✓ Config migrated: 'output' removed, 'name' set to 'egress'\n")
		fmt.Printf("✓ Original config backed up to: %s\n", backupPath)
	}

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// defaultConfig returns a Config with sensible defaults
func defaultConfig(mode string) Config {
	return Config{
		Mode: mode,
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

	// Proxy overrides (V2)
	if val := os.Getenv("PROXYCTL_PROXY_IP"); val != "" {
		if cfg.Proxy == nil {
			cfg.Proxy = &ProxyConfig{}
		}
		cfg.Proxy.IP = val
	}
	if val := os.Getenv("PROXYCTL_PROXY_PORT"); val != "" {
		if port, err := strconv.Atoi(val); err == nil {
			if cfg.Proxy == nil {
				cfg.Proxy = &ProxyConfig{}
			}
			cfg.Proxy.Port = port
		}
	}

	// ACL overrides (V2)
	if val := os.Getenv("PROXYCTL_ACL_FILE"); val != "" {
		if cfg.ACL == nil {
			cfg.ACL = &ACLConfig{}
		}
		cfg.ACL.File = val
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

	// Check for V1 config usage (removed in v0.9.0)
	if err := c.checkForV1Config(); err != nil {
		return err
	}

	// Validate firewall configuration (v0.8.0+)
	if c.Firewall != nil {
		if err := c.validateFirewall(); err != nil {
			return fmt.Errorf("firewall validation error: %w", err)
		}
	}

	// Validate redirect configuration (v0.8.0+)
	if c.Redirect != nil {
		if err := c.validateRedirect(); err != nil {
			return fmt.Errorf("redirect validation error: %w", err)
		}
	}

	// Validate proxy configuration (v0.8.0+)
	if c.Proxy != nil {
		if err := c.validateProxy(); err != nil {
			return fmt.Errorf("proxy validation error: %w", err)
		}
	}

	// Validate logger configuration (v0.8.0+)
	if c.Logger != nil {
		if err := c.validateLogger(); err != nil {
			return fmt.Errorf("logger validation error: %w", err)
		}
	}

	return nil
}

// checkForV1Config detects and rejects V1 configuration format
func (c *Config) checkForV1Config() error {
	// Parse raw JSON to detect V1 fields
	// Note: This is a simple check - if users have V1 fields, they'll be in the JSON
	// but won't be unmarshaled into the struct (since we removed those fields)

	// We can detect V1 usage by checking if certain V2 fields are missing when mode is egress
	// This is a reasonable heuristic since V1 users won't have migrated yet

	// For now, we provide a helpful error in command files when Proxy or ACL is nil
	// But we can also check the raw JSON here if needed

	return nil
}

// validateFirewall validates firewall configuration
func (c *Config) validateFirewall() error {
	fw := c.Firewall

	// If firewall is enabled, input_policy is required
	if fw.Enabled {
		if fw.InputPolicy == "" {
			return fmt.Errorf("input_policy is required when firewall.enabled is true")
		}

		// Validate input_policy value
		validPolicies := map[string]bool{"drop": true, "block": true, "ignore": true}
		if !validPolicies[fw.InputPolicy] {
			return fmt.Errorf("input_policy must be 'drop', 'block', or 'ignore', got: %s", fw.InputPolicy)
		}

		// Require at least one allow rule (INPUT, FORWARD, or both)
		// Allow FORWARD-only configurations for gateway scenarios
		if len(fw.AllowSSHFrom) == 0 && len(fw.AllowProxyFrom) == 0 && len(fw.AllowForwardFrom) == 0 {
			return fmt.Errorf("at least one of allow_ssh_from, allow_proxy_from, or allow_forward_from must be specified when firewall is enabled")
		}

		// Validate allow_proxy_from rules
		for i, rule := range fw.AllowProxyFrom {
			if len(rule.Sources) == 0 {
				return fmt.Errorf("allow_proxy_from[%d]: sources cannot be empty", i)
			}
			// Ports are optional, so no validation needed
		}
	}

	// Validate FORWARD policy if specified
	if fw.ForwardPolicy != "" {
		validForwardPolicies := map[string]bool{"drop": true, "accept": true}
		if !validForwardPolicies[fw.ForwardPolicy] {
			return fmt.Errorf("forward_policy must be 'drop' or 'accept', got: %s", fw.ForwardPolicy)
		}
	}

	// Validate allow_forward_from rules
	for i, rule := range fw.AllowForwardFrom {
		// Sources are required
		if len(rule.Sources) == 0 {
			return fmt.Errorf("allow_forward_from[%d]: sources cannot be empty", i)
		}

		// Validate IP/CIDR format for sources
		for j, source := range rule.Sources {
			if err := validateIPOrCIDR(source); err != nil {
				return fmt.Errorf("allow_forward_from[%d].sources[%d]: invalid IP/CIDR '%s': %w", i, j, source, err)
			}
		}

		// Validate destinations if specified
		for j, dest := range rule.Destinations {
			if err := validateIPOrCIDR(dest); err != nil {
				return fmt.Errorf("allow_forward_from[%d].destinations[%d]: invalid IP/CIDR '%s': %w", i, j, dest, err)
			}
		}

		// Validate protocols if specified
		validProtocols := map[string]bool{"tcp": true, "udp": true, "icmp": true}
		for j, proto := range rule.Protocols {
			protoLower := strings.ToLower(proto)
			if !validProtocols[protoLower] {
				return fmt.Errorf("allow_forward_from[%d].protocols[%d]: invalid protocol '%s' (must be tcp, udp, or icmp)", i, j, proto)
			}
		}

		// Validate ports if specified
		for j, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("allow_forward_from[%d].ports[%d]: invalid port %d (must be 1-65535)", i, j, port)
			}
		}
	}

	return nil
}

// validateRedirect validates redirect configuration
func (c *Config) validateRedirect() error {
	rd := c.Redirect

	if rd.Enabled {
		// Validate type
		if rd.Type != "partial" && rd.Type != "full" {
			return fmt.Errorf("redirect.type must be 'partial' or 'full', got: %s", rd.Type)
		}

		// For partial redirect, targets are required
		if rd.Type == "partial" && len(rd.Targets) == 0 {
			return fmt.Errorf("redirect.targets must contain at least one IP when type is 'partial'")
		}

		// Proxy must be configured when redirect is enabled
		if c.Proxy == nil {
			return fmt.Errorf("proxy configuration required when redirect is enabled")
		}
	}

	return nil
}

// validateProxy validates proxy configuration
func (c *Config) validateProxy() error {
	p := c.Proxy

	if p.IP == "" {
		return fmt.Errorf("proxy.ip cannot be empty")
	}

	// Validate port (defaults to 8080 if not set, but must be valid if set)
	if p.Port == 0 {
		p.Port = 8080 // Set default
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("proxy.port must be between 1 and 65535, got: %d", p.Port)
	}

	// Stats port is optional, but if set must be valid
	if p.StatsPort != 0 && (p.StatsPort < 1 || p.StatsPort > 65535) {
		return fmt.Errorf("proxy.stats_port must be between 1 and 65535, got: %d", p.StatsPort)
	}

	return nil
}

// validateLogger validates logger configuration
func (c *Config) validateLogger() error {
	l := c.Logger

	// BACKWARD COMPATIBILITY: Handle migration from old 'output' field format
	// Old format: {"logger": {"enabled": true, "output": "/var/log/proxyctl/egress.log"}}
	// New format: {"logger": {"enabled": true, "name": "egress", "log_path": "/var/log/proxyctl/"}}
	//
	// If 'output' field is present (old format), set default name for migration.
	// Migration will be handled by migrateLoggerConfig() during config load.
	if l.Output != "" && l.Name == "" {
		l.Name = "egress"
	}

	// REQUIRED FIELD: 'name' must be explicitly specified in new configurations
	//
	// DO NOT make this field optional by applying a default for all configs!
	// The 'name' field is intentionally required to:
	//   1. Support multiple named loggers (e.g., "egress", "db-primary", "api-gateway")
	//   2. Ensure users consciously choose logger names
	//   3. Prevent accidental conflicts when multiple loggers are deployed
	//
	// Only configs with the old 'output' field (see above) should get a default name.
	// All new configs must explicitly specify: "name": "egress" (or other name)
	//
	// If integration tests fail here, fix the TESTS to include "name" field,
	// not this validation logic!
	if l.Name == "" {
		return fmt.Errorf("logger 'name' is required")
	}

	// Validate name
	if err := validateLoggerName(l.Name); err != nil {
		return err
	}

	// Normalize name to lowercase
	l.Name = strings.ToLower(l.Name)

	// Validate log_path if specified
	if l.LogPath != "" {
		if !filepath.IsAbs(l.LogPath) {
			return fmt.Errorf("logger 'log_path' must be absolute path: %s", l.LogPath)
		}
	}

	// Warn if old 'output' field present alongside new fields
	if l.Output != "" && l.Name != "" {
		// This warning will be shown during migration
		l.Output = "" // Clear deprecated field after migration
	}

	// Validate chains
	if len(l.Chains) > 0 {
		validChains := map[string]bool{"OUTPUT": true, "INPUT": true, "FORWARD": true}
		for _, chain := range l.Chains {
			chainUpper := strings.ToUpper(chain)
			if !validChains[chainUpper] {
				return fmt.Errorf("invalid chain: %s (must be OUTPUT, INPUT, or FORWARD)", chain)
			}
		}
	}

	// Validate protocols
	if len(l.Protocols) > 0 {
		validProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
		for _, proto := range l.Protocols {
			protoLower := strings.ToLower(proto)
			if !validProtos[protoLower] {
				return fmt.Errorf("invalid protocol: %s (must be tcp, udp, icmp, or all)", proto)
			}
		}
	}

	// Validate include_ranges (whitelist)
	for i, ipRange := range l.IncludeRanges {
		if err := validateIPOrCIDR(ipRange); err != nil {
			return fmt.Errorf("invalid include_ranges[%d]: %s - %w", i, ipRange, err)
		}
	}

	// Validate exclude_ranges (blacklist)
	for i, ipRange := range l.ExcludeRanges {
		if err := validateIPOrCIDR(ipRange); err != nil {
			return fmt.Errorf("invalid exclude_ranges[%d]: %s - %w", i, ipRange, err)
		}
	}

	return nil
}

// validateLoggerName validates a logger name
func validateLoggerName(name string) error {
	// Length check
	if len(name) == 0 {
		return fmt.Errorf("logger name cannot be empty")
	}
	if len(name) > MaxLoggerNameLength {
		return fmt.Errorf("logger name too long (max %d chars): %s", MaxLoggerNameLength, name)
	}

	// Character validation (before normalization)
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validName.MatchString(name) {
		return fmt.Errorf("logger name contains invalid characters (allowed: a-z, A-Z, 0-9, _, -): %s", name)
	}

	// Reserved names (check after lowercase conversion)
	reserved := map[string]bool{
		"all": true, "test": true, "tmp": true, "temp": true,
		"con": true, "prn": true, "aux": true, "nul": true,
	}
	lowerName := strings.ToLower(name)
	if reserved[lowerName] {
		return fmt.Errorf("logger name '%s' is reserved", name)
	}

	// Leading character checks
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("logger name cannot start with hyphen: %s", name)
	}
	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("logger name cannot start with dot: %s", name)
	}

	return nil
}

// validateIPOrCIDR validates that a string is either a valid IP address or CIDR notation
func validateIPOrCIDR(ipRange string) error {
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(ipRange); err == nil {
		return nil
	}

	// Try parsing as plain IP
	if net.ParseIP(ipRange) != nil {
		return nil
	}

	return fmt.Errorf("not a valid IP address or CIDR notation")
}

// IsEphemeral returns true if this is an ephemeral deployment
// (ingress mode with remote config sources)
// Note: Ingress mode is not yet implemented
func (c *Config) IsEphemeral() bool {
	return false
}
