package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// Config is the configuration schema
type Config struct {
	Admin      AdminConfig      `json:"admin"`
	Interfaces InterfacesConfig `json:"interfaces"`
	Firewall   *FirewallConfig  `json:"firewall,omitempty"`
	Routing    *RoutingConfig   `json:"routing,omitempty"`
	Proxy      *ProxyConfig     `json:"proxy,omitempty"`
	Redirect   *RedirectConfig  `json:"redirect,omitempty"` // OUTPUT redirect for worker servers
}

// AdminConfig defines global admin access (SSH lockout prevention)
type AdminConfig struct {
	Sources []string `json:"sources"`         // IP addresses or CIDR blocks
	Ports   []int    `json:"ports,omitempty"` // Defaults to [22]
}

// InterfacesConfig maps logical names to physical interfaces
type InterfacesConfig map[string]string // logical_name -> interface_name (e.g., "public" -> "eth0")

// FirewallConfig defines INPUT filtering rules
type FirewallConfig struct {
	Enabled       bool           `json:"enabled"`
	DefaultPolicy string         `json:"default_policy"` // "drop", "block", "accept"
	Rules         []FirewallRule `json:"rules,omitempty"`
}

// FirewallRule defines a single firewall rule
type FirewallRule struct {
	Name         string   `json:"name"`                   // Human-readable identifier
	Interface    string   `json:"interface"`              // References InterfacesConfig key
	Sources      []string `json:"sources"`                // IP addresses or CIDR blocks
	Destinations []string `json:"destinations,omitempty"` // Optional
	Protocol     string   `json:"protocol"`               // "tcp", "udp", "icmp", "all"
	Ports        []int    `json:"ports,omitempty"`        // Only for tcp/udp
	Action       string   `json:"action"`                 // "accept", "drop", "reject"
}

// RoutingConfig defines IP forwarding and MASQUERADE
type RoutingConfig struct {
	Enabled    bool             `json:"enabled"`
	IPForward  bool             `json:"ip_forward"`
	Masquerade MasqueradeConfig `json:"masquerade"`
}

// MasqueradeConfig defines MASQUERADE settings
type MasqueradeConfig struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"` // References InterfacesConfig key
}

// RedirectConfig defines OUTPUT redirect for worker servers
type RedirectConfig struct {
	Enabled bool     `json:"enabled"`
	Type    string   `json:"type"`              // "partial" or "full"
	Targets []string `json:"targets,omitempty"` // Only for partial redirect
}

// ProxyConfig defines HAProxy configuration
type ProxyConfig struct {
	Enabled   bool                `json:"enabled"`
	Mode      string              `json:"mode"`           // "egress", "ingress"
	Type      string              `json:"type"`           // "transparent", "reverse"
	IP        string              `json:"ip,omitempty"`   // Proxy IP (for redirect target on worker servers)
	Port      int                 `json:"port,omitempty"` // Proxy port (for redirect target on worker servers)
	Bind      BindConfig          `json:"bind,omitempty"`
	Intercept *InterceptConfig    `json:"intercept,omitempty"` // For egress transparent
	ACL       *ACLConfig          `json:"acl,omitempty"`       // For egress mode
	Backends  *BackendsConfig     `json:"backends,omitempty"`  // For ingress reverse
	SSL       *SSLConfig          `json:"ssl,omitempty"`       // For ingress
	Logging   *ProxyLoggingConfig `json:"logging,omitempty"`
}

// BindConfig defines where HAProxy binds
type BindConfig struct {
	Interface string `json:"interface"` // References InterfacesConfig key ("loopback" for transparent)
	Port      int    `json:"port"`
}

// InterceptConfig defines port interception for transparent proxy
type InterceptConfig struct {
	Ports         []int  `json:"ports"`          // Ports to intercept (e.g., [80, 443])
	FromInterface string `json:"from_interface"` // References InterfacesConfig key
}

// ACLConfig defines ACL (Access Control List) settings for egress proxy
type ACLConfig struct {
	Enabled    bool   `json:"enabled"`
	FilePath   string `json:"file_path"`   // Path to ACL file (e.g., "/etc/haproxy/acl.lst")
	AutoReload bool   `json:"auto_reload"` // Auto-reload HAProxy on ACL changes
}

// BackendsConfig defines backend servers for reverse proxy
type BackendsConfig struct {
	Interface   string             `json:"interface"` // References InterfacesConfig key
	Servers     []BackendServer    `json:"servers"`
	HealthCheck *HealthCheckConfig `json:"health_check,omitempty"`
	LoadBalance string             `json:"load_balance,omitempty"` // "roundrobin", "leastconn", "source"
}

// BackendServer defines a single backend server
type BackendServer struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Weight int    `json:"weight,omitempty"` // Optional, 1-256
}

// HealthCheckConfig defines backend health check settings
type HealthCheckConfig struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval"` // e.g., "5s", "10s"
	Timeout  string `json:"timeout"`
	Path     string `json:"path"`   // HTTP path for health check
	Method   string `json:"method"` // GET, HEAD, POST
}

// SSLConfig defines SSL/TLS configuration for ingress
type SSLConfig struct {
	Enabled bool   `json:"enabled"`
	CertDir string `json:"cert_dir"` // Directory containing SSL certificates
}

// ProxyLoggingConfig defines HAProxy logging settings
type ProxyLoggingConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`             // Log file path
	Format  string `json:"format,omitempty"` // "combined", "json"
}

// Validate validates the entire configuration
func (c *Config) Validate() error {
	// Validate admin section
	if err := c.Admin.Validate(); err != nil {
		return fmt.Errorf("admin validation failed: %w", err)
	}

	// Validate interfaces
	if err := c.Interfaces.Validate(); err != nil {
		return fmt.Errorf("interfaces validation failed: %w", err)
	}

	// At least one mode must be enabled
	if (c.Firewall == nil || !c.Firewall.Enabled) &&
		(c.Routing == nil || !c.Routing.Enabled) &&
		(c.Proxy == nil || !c.Proxy.Enabled) {
		return fmt.Errorf("at least one of firewall, routing, or proxy must be enabled")
	}

	// Validate each enabled section
	if c.Firewall != nil && c.Firewall.Enabled {
		if err := c.Firewall.Validate(c.Interfaces); err != nil {
			return fmt.Errorf("firewall validation failed: %w", err)
		}
	}

	if c.Routing != nil && c.Routing.Enabled {
		if err := c.Routing.Validate(c.Interfaces); err != nil {
			return fmt.Errorf("routing validation failed: %w", err)
		}
	}

	if c.Proxy != nil && c.Proxy.Enabled {
		if err := c.Proxy.Validate(c.Interfaces); err != nil {
			return fmt.Errorf("proxy validation failed: %w", err)
		}
	}

	if c.Redirect != nil && c.Redirect.Enabled {
		if err := c.Redirect.Validate(); err != nil {
			return fmt.Errorf("redirect validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates admin configuration
func (a *AdminConfig) Validate() error {
	if len(a.Sources) == 0 {
		return fmt.Errorf("admin.sources must contain at least one IP or CIDR")
	}

	for _, source := range a.Sources {
		if !isValidIPOrCIDR(source) {
			return fmt.Errorf("invalid IP or CIDR in admin.sources: %s", source)
		}
	}

	// Validate ports if specified
	if len(a.Ports) > 0 {
		for _, port := range a.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid port in admin.ports: %d", port)
			}
		}
	}

	return nil
}

// Validate validates interfaces configuration
func (i InterfacesConfig) Validate() error {
	if len(i) == 0 {
		return fmt.Errorf("at least one interface must be defined")
	}

	// Validate interface names (basic check, runtime validation happens later)
	for logical, physical := range i {
		if logical == "" {
			return fmt.Errorf("interface logical name cannot be empty")
		}
		if physical == "" {
			return fmt.Errorf("interface physical name cannot be empty for '%s'", logical)
		}
	}

	return nil
}

// ValidateAtRuntime checks if interfaces actually exist on the system
func (i InterfacesConfig) ValidateAtRuntime() error {
	for logical, physical := range i {
		// Skip loopback special case
		if logical == "loopback" && physical == "lo" {
			continue
		}

		// Check if interface exists
		if _, err := net.InterfaceByName(physical); err != nil {
			return fmt.Errorf("interface '%s' (mapped from '%s') does not exist on system: %w",
				physical, logical, err)
		}
	}
	return nil
}

// Validate validates firewall configuration
func (f *FirewallConfig) Validate(interfaces InterfacesConfig) error {
	// Validate default_policy
	validPolicies := map[string]bool{"drop": true, "block": true, "accept": true}
	if !validPolicies[f.DefaultPolicy] {
		return fmt.Errorf("default_policy must be 'drop', 'block', or 'accept', got: %s", f.DefaultPolicy)
	}

	// Validate rules
	ruleNames := make(map[string]bool)
	for i, rule := range f.Rules {
		if err := rule.Validate(interfaces); err != nil {
			return fmt.Errorf("rule[%d] validation failed: %w", i, err)
		}

		// Check for duplicate rule names
		if ruleNames[rule.Name] {
			return fmt.Errorf("duplicate rule name: %s", rule.Name)
		}
		ruleNames[rule.Name] = true
	}

	return nil
}

// Validate validates a single firewall rule
func (r *FirewallRule) Validate(interfaces InterfacesConfig) error {
	if r.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	// Validate interface reference
	if _, ok := interfaces[r.Interface]; !ok {
		return fmt.Errorf("rule '%s' references undefined interface: %s", r.Name, r.Interface)
	}

	// Validate sources
	if len(r.Sources) == 0 {
		return fmt.Errorf("rule '%s' must have at least one source", r.Name)
	}
	for _, source := range r.Sources {
		if !isValidIPOrCIDR(source) {
			return fmt.Errorf("rule '%s' has invalid source IP or CIDR: %s", r.Name, source)
		}
	}

	// Validate destinations if specified
	for _, dest := range r.Destinations {
		if !isValidIPOrCIDR(dest) {
			return fmt.Errorf("rule '%s' has invalid destination IP or CIDR: %s", r.Name, dest)
		}
	}

	// Validate protocol
	validProtocols := map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
	if !validProtocols[r.Protocol] {
		return fmt.Errorf("rule '%s' has invalid protocol: %s", r.Name, r.Protocol)
	}

	// Validate ports (only valid for tcp/udp)
	if len(r.Ports) > 0 {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("rule '%s' cannot specify ports for protocol '%s'", r.Name, r.Protocol)
		}
		for _, port := range r.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("rule '%s' has invalid port: %d", r.Name, port)
			}
		}
	}

	// Validate action
	validActions := map[string]bool{"accept": true, "drop": true, "reject": true}
	if !validActions[r.Action] {
		return fmt.Errorf("rule '%s' has invalid action: %s", r.Name, r.Action)
	}

	return nil
}

// Validate validates routing configuration
func (r *RoutingConfig) Validate(interfaces InterfacesConfig) error {
	if !r.IPForward {
		return fmt.Errorf("routing.ip_forward must be true when routing is enabled")
	}

	if err := r.Masquerade.Validate(interfaces); err != nil {
		return fmt.Errorf("masquerade validation failed: %w", err)
	}

	return nil
}

// Validate validates masquerade configuration
func (m *MasqueradeConfig) Validate(interfaces InterfacesConfig) error {
	if !m.Enabled {
		return nil // Not enabled, nothing to validate
	}

	// Validate interface reference
	physicalIface, ok := interfaces[m.Interface]
	if !ok {
		return fmt.Errorf("masquerade references undefined interface: %s", m.Interface)
	}

	// Ensure it's not loopback
	if m.Interface == "loopback" || physicalIface == "lo" {
		return fmt.Errorf("masquerade cannot use loopback interface")
	}

	return nil
}

// Validate validates redirect configuration
func (r *RedirectConfig) Validate() error {
	// Validate type
	validTypes := map[string]bool{"partial": true, "full": true}
	if !validTypes[r.Type] {
		return fmt.Errorf("redirect.type must be 'partial' or 'full', got: %s", r.Type)
	}

	// Partial redirect requires targets
	if r.Type == "partial" {
		if len(r.Targets) == 0 {
			return fmt.Errorf("partial redirect requires at least one target")
		}
		// Validate targets are valid IPs or CIDRs
		for _, target := range r.Targets {
			if !isValidIPOrCIDR(target) {
				return fmt.Errorf("invalid redirect target IP or CIDR: %s", target)
			}
		}
	}

	// Full redirect should not have targets
	if r.Type == "full" && len(r.Targets) > 0 {
		return fmt.Errorf("full redirect should not specify targets")
	}

	return nil
}

// Validate validates proxy configuration
func (p *ProxyConfig) Validate(interfaces InterfacesConfig) error {
	// Validate mode
	validModes := map[string]bool{"egress": true, "ingress": true}
	if !validModes[p.Mode] {
		return fmt.Errorf("proxy.mode must be 'egress' or 'ingress', got: %s", p.Mode)
	}

	// Validate type
	validTypes := map[string]bool{"transparent": true, "reverse": true}
	if !validTypes[p.Type] {
		return fmt.Errorf("proxy.type must be 'transparent' or 'reverse', got: %s", p.Type)
	}

	// Mode-specific validation
	if p.Mode == "egress" {
		if p.Type != "transparent" {
			return fmt.Errorf("egress mode requires type 'transparent'")
		}
		if p.Intercept == nil {
			return fmt.Errorf("egress transparent proxy requires 'intercept' configuration")
		}
		if err := p.Intercept.Validate(interfaces); err != nil {
			return fmt.Errorf("intercept validation failed: %w", err)
		}
	}

	if p.Mode == "ingress" {
		if p.Type != "reverse" {
			return fmt.Errorf("ingress mode requires type 'reverse'")
		}
		if p.Backends == nil {
			return fmt.Errorf("ingress reverse proxy requires 'backends' configuration")
		}
		if err := p.Backends.Validate(interfaces); err != nil {
			return fmt.Errorf("backends validation failed: %w", err)
		}
	}

	// Validate IP/Port if specified (for redirect target)
	if p.IP != "" {
		if net.ParseIP(p.IP) == nil {
			return fmt.Errorf("invalid proxy IP: %s", p.IP)
		}
	}
	if p.Port != 0 {
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("proxy port must be between 1 and 65535, got: %d", p.Port)
		}
	}

	// Validate bind if present (optional for worker servers with redirect)
	if p.Bind.Interface != "" || p.Bind.Port != 0 {
		if err := p.Bind.Validate(interfaces); err != nil {
			return fmt.Errorf("bind validation failed: %w", err)
		}
	}

	// Validate SSL if present
	if p.SSL != nil && p.SSL.Enabled {
		if err := p.SSL.Validate(); err != nil {
			return fmt.Errorf("ssl validation failed: %w", err)
		}
	}

	return nil
}

// Validate validates bind configuration
func (b *BindConfig) Validate(interfaces InterfacesConfig) error {
	// Validate interface reference
	if _, ok := interfaces[b.Interface]; !ok {
		return fmt.Errorf("bind references undefined interface: %s", b.Interface)
	}

	// Validate port
	if b.Port < 1 || b.Port > 65535 {
		return fmt.Errorf("bind port must be between 1 and 65535, got: %d", b.Port)
	}

	return nil
}

// Validate validates intercept configuration
func (i *InterceptConfig) Validate(interfaces InterfacesConfig) error {
	if len(i.Ports) == 0 {
		return fmt.Errorf("intercept.ports must contain at least one port")
	}

	for _, port := range i.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid intercept port: %d", port)
		}
	}

	// Validate interface reference
	if _, ok := interfaces[i.FromInterface]; !ok {
		return fmt.Errorf("intercept references undefined interface: %s", i.FromInterface)
	}

	return nil
}

// Validate validates ACL configuration
func (a *ACLConfig) Validate() error {
	if a.FilePath == "" {
		return fmt.Errorf("acl.file_path cannot be empty when ACL is enabled")
	}
	return nil
}

// Validate validates backends configuration
func (b *BackendsConfig) Validate(interfaces InterfacesConfig) error {
	// Validate interface reference
	if _, ok := interfaces[b.Interface]; !ok {
		return fmt.Errorf("backends references undefined interface: %s", b.Interface)
	}

	// Validate servers
	if len(b.Servers) == 0 {
		return fmt.Errorf("backends must have at least one server")
	}

	for i, server := range b.Servers {
		if err := server.Validate(); err != nil {
			return fmt.Errorf("backend server[%d] validation failed: %w", i, err)
		}
	}

	// Validate load balance algorithm
	if b.LoadBalance != "" {
		validAlgos := map[string]bool{"roundrobin": true, "leastconn": true, "source": true}
		if !validAlgos[b.LoadBalance] {
			return fmt.Errorf("invalid load_balance algorithm: %s", b.LoadBalance)
		}
	}

	return nil
}

// Validate validates a backend server
func (s *BackendServer) Validate() error {
	if s.IP == "" {
		return fmt.Errorf("backend server IP cannot be empty")
	}
	if net.ParseIP(s.IP) == nil {
		return fmt.Errorf("invalid backend server IP: %s", s.IP)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("invalid backend server port: %d", s.Port)
	}
	if s.Weight != 0 && (s.Weight < 1 || s.Weight > 256) {
		return fmt.Errorf("backend server weight must be between 1 and 256, got: %d", s.Weight)
	}
	return nil
}

// Validate validates SSL configuration
func (s *SSLConfig) Validate() error {
	if s.CertDir == "" {
		return fmt.Errorf("ssl.cert_dir cannot be empty when SSL is enabled")
	}
	return nil
}

// isValidIPOrCIDR validates if string is a valid IP address or CIDR block
func isValidIPOrCIDR(s string) bool {
	// Try parsing as IP first
	if net.ParseIP(s) != nil {
		return true
	}
	// Try parsing as CIDR
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// applyDefaults applies default values to the configuration
func (c *Config) applyDefaults() {
	// Default admin ports to [22] if not specified
	if len(c.Admin.Ports) == 0 {
		c.Admin.Ports = []int{22}
	}

	// Apply proxy defaults if proxy is configured
	if c.Proxy != nil {
		// Default logging format to "combined"
		if c.Proxy.Logging != nil && c.Proxy.Logging.Enabled && c.Proxy.Logging.Format == "" {
			c.Proxy.Logging.Format = "combined"
		}

		// Default load balance to "roundrobin"
		if c.Proxy.Backends != nil && c.Proxy.Backends.LoadBalance == "" {
			c.Proxy.Backends.LoadBalance = "roundrobin"
		}
	}
}

// Load loads and validates configuration from a JSON file
func Load(configPath string) (*Config, error) {
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	// Apply defaults
	cfg.applyDefaults()

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}
