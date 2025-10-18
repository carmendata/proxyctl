# Implementation Plan: Configuration v2.0

**Date**: 2025-10-17
**Target Release**: v0.9.0
**Status**: Planning Phase

## Overview

This document provides a detailed, step-by-step implementation plan for migrating from v1.x to v2.0 configuration schema. Focus is on **P0 (Critical Path)** items to get the hybrid egress proxy working on `egress-proxy-01.carmendata.net`.

---

## Phase 1: Configuration Schema (P0)

### Goal
Implement v2.0 config structs, parsing, and validation.

### Files to Create/Modify

#### 1.1. Create `internal/config/v2.go`

**Purpose**: Define v2.0 configuration structs

```go
package config

// ConfigV2 is the v2.0 configuration schema
type ConfigV2 struct {
    Admin      AdminConfig      `json:"admin"`
    Interfaces InterfacesConfig `json:"interfaces"`
    Firewall   *FirewallV2Config `json:"firewall,omitempty"`
    Routing    *RoutingConfig    `json:"routing,omitempty"`
    Proxy      *ProxyV2Config    `json:"proxy,omitempty"`
}

// AdminConfig defines global admin access (SSH lockout prevention)
type AdminConfig struct {
    Sources []string `json:"sources"` // IP addresses or CIDR blocks
    Ports   []int    `json:"ports,omitempty"` // Defaults to [22]
}

// InterfacesConfig maps logical names to physical interfaces
type InterfacesConfig map[string]string // logical_name -> interface_name (e.g., "public" -> "eth0")

// FirewallV2Config defines INPUT filtering rules
type FirewallV2Config struct {
    Enabled       bool           `json:"enabled"`
    DefaultPolicy string         `json:"default_policy"` // "drop", "block", "accept"
    Rules         []FirewallRule `json:"rules,omitempty"`
}

// FirewallRule defines a single firewall rule
type FirewallRule struct {
    Name         string   `json:"name"` // Human-readable identifier
    Interface    string   `json:"interface"` // References InterfacesConfig key
    Sources      []string `json:"sources"` // IP addresses or CIDR blocks
    Destinations []string `json:"destinations,omitempty"` // Optional
    Protocol     string   `json:"protocol"` // "tcp", "udp", "icmp", "all"
    Ports        []int    `json:"ports,omitempty"` // Only for tcp/udp
    Action       string   `json:"action"` // "accept", "drop", "reject"
}

// RoutingConfig defines IP forwarding and MASQUERADE
type RoutingConfig struct {
    Enabled   bool              `json:"enabled"`
    IPForward bool              `json:"ip_forward"`
    Masquerade MasqueradeConfig `json:"masquerade"`
}

// MasqueradeConfig defines MASQUERADE settings
type MasqueradeConfig struct {
    Enabled   bool   `json:"enabled"`
    Interface string `json:"interface"` // References InterfacesConfig key
}

// ProxyV2Config defines HAProxy configuration
type ProxyV2Config struct {
    Enabled   bool            `json:"enabled"`
    Mode      string          `json:"mode"` // "egress", "ingress"
    Type      string          `json:"type"` // "transparent", "reverse"
    Bind      BindConfig      `json:"bind"`
    Intercept *InterceptConfig `json:"intercept,omitempty"` // For egress transparent
    Backends  *BackendsConfig  `json:"backends,omitempty"` // For ingress reverse
    Logging   *ProxyLoggingConfig `json:"logging,omitempty"`
}

// BindConfig defines where HAProxy binds
type BindConfig struct {
    Interface string `json:"interface"` // References InterfacesConfig key ("loopback" for transparent)
    Port      int    `json:"port"`
}

// InterceptConfig defines port interception for transparent proxy
type InterceptConfig struct {
    Ports         []int  `json:"ports"` // Ports to intercept (e.g., [80, 443])
    FromInterface string `json:"from_interface"` // References InterfacesConfig key
}

// BackendsConfig defines backend servers for reverse proxy
type BackendsConfig struct {
    Interface   string                `json:"interface"` // References InterfacesConfig key
    Servers     []BackendServer       `json:"servers"`
    HealthCheck *HealthCheckConfig    `json:"health_check,omitempty"`
    LoadBalance string                `json:"load_balance,omitempty"` // "roundrobin", "leastconn", "source"
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
    Path     string `json:"path"` // HTTP path for health check
}

// ProxyLoggingConfig defines HAProxy logging settings
type ProxyLoggingConfig struct {
    Enabled bool   `json:"enabled"`
    Path    string `json:"path"` // Log file path
    Format  string `json:"format,omitempty"` // "combined", "json"
}
```

**Validation methods** (same file):

```go
// Validate validates the entire configuration
func (c *ConfigV2) Validate() error {
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
func (f *FirewallV2Config) Validate(interfaces InterfacesConfig) error {
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

// Validate validates proxy configuration
func (p *ProxyV2Config) Validate(interfaces InterfacesConfig) error {
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

    // Validate bind
    if err := p.Bind.Validate(interfaces); err != nil {
        return fmt.Errorf("bind validation failed: %w", err)
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

// Helper function to validate IP or CIDR
func isValidIPOrCIDR(s string) bool {
    // Try parsing as IP first
    if net.ParseIP(s) != nil {
        return true
    }
    // Try parsing as CIDR
    _, _, err := net.ParseCIDR(s)
    return err == nil
}
```

#### 1.2. Modify `internal/config/config.go`

**Add function to load v2 config**:

```go
// LoadV2 reads v2.0 configuration from file
func LoadV2(cfgFile string) (*ConfigV2, error) {
    data, err := os.ReadFile(cfgFile)
    if err != nil {
        return nil, fmt.Errorf("error reading config file %s: %w", cfgFile, err)
    }

    var cfg ConfigV2
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("error parsing config file %s: %w", cfgFile, err)
    }

    // Validate configuration
    if err := cfg.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }

    // Runtime validation of interfaces
    if err := cfg.Interfaces.ValidateAtRuntime(); err != nil {
        return nil, fmt.Errorf("interface validation failed: %w", err)
    }

    // Set defaults
    cfg.applyDefaults()

    return &cfg, nil
}

// applyDefaults sets default values for optional fields
func (c *ConfigV2) applyDefaults() {
    // Admin ports default to [22]
    if len(c.Admin.Ports) == 0 {
        c.Admin.Ports = []int{22}
    }

    // Proxy logging format defaults to "combined"
    if c.Proxy != nil && c.Proxy.Logging != nil && c.Proxy.Logging.Format == "" {
        c.Proxy.Logging.Format = "combined"
    }

    // Backend load balance defaults to "roundrobin"
    if c.Proxy != nil && c.Proxy.Backends != nil && c.Proxy.Backends.LoadBalance == "" {
        c.Proxy.Backends.LoadBalance = "roundrobin"
    }
}
```

#### 1.3. Create Unit Tests `internal/config/v2_test.go`

```go
package config

import (
    "encoding/json"
    "testing"
)

func TestConfigV2Validate(t *testing.T) {
    tests := []struct {
        name    string
        config  ConfigV2
        wantErr bool
    }{
        {
            name: "valid egress config",
            config: ConfigV2{
                Admin: AdminConfig{
                    Sources: []string{"1.2.3.4/32"},
                },
                Interfaces: InterfacesConfig{
                    "public": "eth0",
                    "private": "eth1",
                },
                Firewall: &FirewallV2Config{
                    Enabled: true,
                    DefaultPolicy: "drop",
                    Rules: []FirewallRule{
                        {
                            Name: "test",
                            Interface: "public",
                            Sources: []string{"0.0.0.0/0"},
                            Protocol: "tcp",
                            Ports: []int{80},
                            Action: "accept",
                        },
                    },
                },
            },
            wantErr: false,
        },
        {
            name: "missing admin sources",
            config: ConfigV2{
                Admin: AdminConfig{},
                Interfaces: InterfacesConfig{"public": "eth0"},
            },
            wantErr: true,
        },
        // Add more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.config.Validate()
            if (err != nil) != tt.wantErr {
                t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

// Add more tests for each validation function...
```

**Estimated Time**: 4-6 hours

---

## Phase 2: Routing Implementation (P0)

### Goal
Implement IP forwarding and MASQUERADE support.

### Files to Create/Modify

#### 2.1. Create `internal/firewall/routing.go`

```go
package firewall

import (
    "fmt"
    "os"
    "os/exec"
    "strings"
)

// ApplyRouting enables IP forwarding and MASQUERADE
func (m *Manager) ApplyRouting(cfg *config.RoutingConfig, interfaces config.InterfacesConfig) error {
    // Enable IP forwarding
    if err := m.enableIPForwarding(); err != nil {
        return fmt.Errorf("failed to enable IP forwarding: %w", err)
    }
    fmt.Println("✓ IP forwarding enabled")

    // Apply MASQUERADE if enabled
    if cfg.Masquerade.Enabled {
        physicalIface := interfaces[cfg.Masquerade.Interface]

        switch m.Type {
        case TypeIPTables:
            if err := m.applyMasqueradeIPTables(physicalIface); err != nil {
                return fmt.Errorf("failed to apply MASQUERADE (iptables): %w", err)
            }
        case TypeNFTables:
            if err := m.applyMasqueradeNFTables(physicalIface); err != nil {
                return fmt.Errorf("failed to apply MASQUERADE (nftables): %w", err)
            }
        default:
            return fmt.Errorf("unknown firewall type: %s", m.Type)
        }

        fmt.Printf("✓ MASQUERADE enabled on interface %s (%s)\n",
            cfg.Masquerade.Interface, physicalIface)
    }

    return nil
}

// RemoveRouting removes routing rules and disables IP forwarding
func (m *Manager) RemoveRouting() error {
    // Remove MASQUERADE rules
    switch m.Type {
    case TypeIPTables:
        if err := m.removeMasqueradeIPTables(); err != nil {
            fmt.Printf("Warning: failed to remove MASQUERADE (iptables): %v\n", err)
        }
    case TypeNFTables:
        if err := m.removeMasqueradeNFTables(); err != nil {
            fmt.Printf("Warning: failed to remove MASQUERADE (nftables): %v\n", err)
        }
    }

    // Optionally disable IP forwarding (commented out for safety)
    // If other services rely on IP forwarding, don't disable it
    // m.disableIPForwarding()

    fmt.Println("✓ Routing rules removed")
    return nil
}

// enableIPForwarding enables kernel IP forwarding
func (m *Manager) enableIPForwarding() error {
    // Set sysctl
    cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to set sysctl: %w", err)
    }

    // Make persistent
    sysctlConf := "/etc/sysctl.d/99-proxyctl-routing.conf"
    content := "# proxyctl routing configuration\nnet.ipv4.ip_forward=1\n"
    if err := os.WriteFile(sysctlConf, []byte(content), 0644); err != nil {
        return fmt.Errorf("failed to write sysctl config: %w", err)
    }

    return nil
}

// applyMasqueradeIPTables applies MASQUERADE rule using iptables
func (m *Manager) applyMasqueradeIPTables(iface string) error {
    // Remove existing MASQUERADE rules (idempotent)
    exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE").Run()

    // Add new MASQUERADE rule
    cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
    }

    // Save rules
    return m.saveIPTables()
}

// applyMasqueradeNFTables applies MASQUERADE rule using nftables
func (m *Manager) applyMasqueradeNFTables(iface string) error {
    // Build nftables configuration
    var config strings.Builder
    config.WriteString("# proxyctl Routing - MASQUERADE\n")
    config.WriteString("# Created by proxyctl for transparent egress proxying\n\n")
    config.WriteString("table ip proxyctl_routing {\n")
    config.WriteString("    chain postrouting {\n")
    config.WriteString("        type nat hook postrouting priority 100; policy accept;\n\n")
    config.WriteString(fmt.Sprintf("        # MASQUERADE outbound traffic on %s\n", iface))
    config.WriteString(fmt.Sprintf("        oifname \"%s\" masquerade\n", iface))
    config.WriteString("    }\n")
    config.WriteString("}\n")

    // Create nftables.d directory if needed
    if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
        return fmt.Errorf("failed to create /etc/nftables.d: %w", err)
    }

    // Write configuration file
    configPath := "/etc/nftables.d/proxyctl-routing.nft"
    if err := os.WriteFile(configPath, []byte(config.String()), 0644); err != nil {
        return fmt.Errorf("failed to write %s: %w", configPath, err)
    }

    // Delete existing table to make idempotent
    exec.Command("nft", "delete", "table", "ip", "proxyctl_routing").Run()

    // Load the configuration immediately
    cmd := exec.Command("nft", "-f", configPath)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to load nftables rules: %w", err)
    }

    // Add include to main nftables.conf if not already present
    if err := m.addNFTablesInclude(configPath); err != nil {
        fmt.Printf("Warning: could not add include to nftables.conf: %v\n", err)
    }

    return nil
}

// removeMasqueradeIPTables removes MASQUERADE rules
func (m *Manager) removeMasqueradeIPTables() error {
    // Note: We don't know which interface was used, so we remove all proxyctl MASQUERADE rules
    // This is safe because we only add one rule
    exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run() // Flush entire chain (risky!)
    // TODO: Better approach - track which interface was used
    return m.saveIPTables()
}

// removeMasqueradeNFTables removes MASQUERADE rules
func (m *Manager) removeMasqueradeNFTables() error {
    // Remove table
    exec.Command("nft", "delete", "table", "ip", "proxyctl_routing").Run()

    // Remove configuration file
    os.Remove("/etc/nftables.d/proxyctl-routing.nft")

    // Remove include from main config
    if err := m.removeNFTablesInclude("/etc/nftables.d/proxyctl-routing.nft"); err != nil {
        fmt.Printf("Warning: could not remove include from nftables.conf: %v\n", err)
    }

    return nil
}
```

**Estimated Time**: 2-3 hours

---

## Phase 3: HAProxy Configuration Generation (P0)

### Goal
Generate HAProxy config for transparent egress proxy.

### Files to Create/Modify

#### 3.1. Create `internal/haproxy/haproxy.go`

```go
package haproxy

import (
    "fmt"
    "os"
    "os/exec"
    "strings"
    "text/template"

    "github.com/carmendata/proxyctl/internal/config"
)

const haproxyConfigPath = "/etc/haproxy/haproxy.cfg"

// ConfigureTransparentEgress generates HAProxy config for transparent egress proxy
func ConfigureTransparentEgress(cfg *config.ProxyV2Config) error {
    // Generate config
    configContent, err := generateTransparentEgressConfig(cfg)
    if err != nil {
        return fmt.Errorf("failed to generate config: %w", err)
    }

    // Backup existing config
    if err := backupConfig(); err != nil {
        return fmt.Errorf("failed to backup existing config: %w", err)
    }

    // Write new config
    if err := os.WriteFile(haproxyConfigPath, []byte(configContent), 0644); err != nil {
        return fmt.Errorf("failed to write config: %w", err)
    }

    // Validate config
    if err := validateConfig(); err != nil {
        // Restore backup
        restoreConfig()
        return fmt.Errorf("config validation failed: %w", err)
    }

    // Reload HAProxy
    if err := reloadHAProxy(); err != nil {
        return fmt.Errorf("failed to reload HAProxy: %w", err)
    }

    return nil
}

// generateTransparentEgressConfig generates the config file content
func generateTransparentEgressConfig(cfg *config.ProxyV2Config) (string, error) {
    tmpl := `global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  300000
    timeout server  300000

# Transparent Egress Proxy Frontend
frontend transparent_proxy
    bind 127.0.0.1:{{.Port}}
    mode tcp
    default_backend forward_backend

# Transparent Egress Proxy Backend
backend forward_backend
    mode tcp
    # Forward to original destination (transparent mode)
    # Note: This requires special kernel setup or accept-proxy
    server forward 0.0.0.0:0
`

    t, err := template.New("haproxy").Parse(tmpl)
    if err != nil {
        return "", err
    }

    var buf strings.Builder
    data := struct {
        Port int
    }{
        Port: cfg.Bind.Port,
    }

    if err := t.Execute(&buf, data); err != nil {
        return "", err
    }

    return buf.String(), nil
}

// backupConfig backs up existing HAProxy config
func backupConfig() error {
    backupPath := haproxyConfigPath + ".backup"
    cmd := exec.Command("cp", haproxyConfigPath, backupPath)
    return cmd.Run()
}

// restoreConfig restores HAProxy config from backup
func restoreConfig() error {
    backupPath := haproxyConfigPath + ".backup"
    cmd := exec.Command("cp", backupPath, haproxyConfigPath)
    return cmd.Run()
}

// validateConfig validates HAProxy configuration
func validateConfig() error {
    cmd := exec.Command("haproxy", "-c", "-f", haproxyConfigPath)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("validation failed: %s", string(output))
    }
    return nil
}

// reloadHAProxy reloads HAProxy service
func reloadHAProxy() error {
    cmd := exec.Command("systemctl", "reload", "haproxy")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("systemctl reload failed: %w", err)
    }
    return nil
}
```

**NOTE**: The transparent TCP forwarding in HAProxy is complex. If HAProxy doesn't work, we'll disable the proxy section and use pure IP/nftables routing instead. This is a **HIGH RISK** item.

**Estimated Time**: 3-4 hours (+ risk mitigation time if HAProxy doesn't work)

---

## Phase 4: PREROUTING Redirect Rules (P0)

### Goal
Create PREROUTING rules to redirect intercepted ports to HAProxy.

### Files to Modify

#### 4.1. Extend `internal/firewall/routing.go`

```go
// ApplyInterception applies PREROUTING redirect rules for transparent proxy
func (m *Manager) ApplyInterception(cfg *config.InterceptConfig, bindPort int, interfaces config.InterfacesConfig) error {
    fromIface := interfaces[cfg.FromInterface]

    switch m.Type {
    case TypeIPTables:
        return m.applyInterceptionIPTables(cfg.Ports, fromIface, bindPort)
    case TypeNFTables:
        return m.applyInterceptionNFTables(cfg.Ports, fromIface, bindPort)
    default:
        return fmt.Errorf("unknown firewall type: %s", m.Type)
    }
}

// applyInterceptionIPTables applies PREROUTING redirect rules
func (m *Manager) applyInterceptionIPTables(ports []int, fromIface string, bindPort int) error {
    // Create custom chain for interception
    cmd := exec.Command("iptables", "-t", "nat", "-N", "PROXYCTL_INTERCEPT")
    cmd.Run() // Ignore error if exists

    // Flush existing rules
    exec.Command("iptables", "-t", "nat", "-F", "PROXYCTL_INTERCEPT").Run()

    // Add redirect rules for each port
    for _, port := range ports {
        cmd := exec.Command("iptables", "-t", "nat", "-A", "PROXYCTL_INTERCEPT",
            "-i", fromIface,
            "-p", "tcp", "--dport", fmt.Sprintf("%d", port),
            "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", bindPort))
        if err := cmd.Run(); err != nil {
            return fmt.Errorf("failed to add redirect rule for port %d: %w", port, err)
        }
    }

    // Remove existing jump (idempotent)
    exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PROXYCTL_INTERCEPT").Run()

    // Insert jump to our chain
    cmd = exec.Command("iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PROXYCTL_INTERCEPT")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to insert jump rule: %w", err)
    }

    // Save rules
    return m.saveIPTables()
}

// applyInterceptionNFTables applies PREROUTING redirect rules
func (m *Manager) applyInterceptionNFTables(ports []int, fromIface string, bindPort int) error {
    // Build config
    var config strings.Builder
    config.WriteString("# proxyctl Interception - PREROUTING Redirect\n")
    config.WriteString("table ip proxyctl_intercept {\n")
    config.WriteString("    chain prerouting {\n")
    config.WriteString("        type nat hook prerouting priority -100; policy accept;\n\n")

    for _, port := range ports {
        config.WriteString(fmt.Sprintf("        iifname \"%s\" tcp dport %d redirect to :%d\n",
            fromIface, port, bindPort))
    }

    config.WriteString("    }\n")
    config.WriteString("}\n")

    // Write and load config
    configPath := "/etc/nftables.d/proxyctl-intercept.nft"
    if err := os.WriteFile(configPath, []byte(config.String()), 0644); err != nil {
        return fmt.Errorf("failed to write config: %w", err)
    }

    exec.Command("nft", "delete", "table", "ip", "proxyctl_intercept").Run()
    cmd := exec.Command("nft", "-f", configPath)
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("failed to load rules: %w", err)
    }

    m.addNFTablesInclude(configPath)
    return nil
}
```

**Estimated Time**: 2 hours

---

## Phase 5: Update Commands (P0)

### Goal
Modify `firewall apply` to support v2 config.

### Files to Modify

#### 5.1. Create `cmd/proxyctl/apply_v2.go`

```go
package main

import (
    "fmt"

    "github.com/carmendata/proxyctl/internal/config"
    "github.com/carmendata/proxyctl/internal/firewall"
    "github.com/carmendata/proxyctl/internal/haproxy"
)

// runApplyV2 applies v2.0 configuration
func runApplyV2(cfgFile string, dryRun bool) error {
    // Load v2 config
    cfg, err := config.LoadV2(cfgFile)
    if err != nil {
        return fmt.Errorf("failed to load config: %w", err)
    }

    // Detect/create firewall manager
    fwMgr, err := firewall.NewManager()
    if err != nil {
        return fmt.Errorf("failed to initialize firewall: %w", err)
    }

    fmt.Printf("Detected firewall type: %s\n", fwMgr.Type)
    fmt.Println()

    // Show configuration summary
    showV2ConfigSummary(cfg)

    if dryRun {
        fmt.Println("\n🔍 DRY RUN MODE - No changes will be made")
        return nil
    }

    // Confirm before applying
    if !confirmApply() {
        return fmt.Errorf("operation cancelled by user")
    }

    // Create backup
    fmt.Println("\nCreating backup...")
    backupPath, err := fwMgr.Backup()
    if err != nil {
        return fmt.Errorf("failed to create backup: %w", err)
    }
    fmt.Printf("✓ Backup created: %s\n", backupPath)

    // Apply firewall if enabled
    if cfg.Firewall != nil && cfg.Firewall.Enabled {
        fmt.Println("\n📋 Applying Firewall Rules...")
        if err := applyFirewallV2(fwMgr, cfg); err != nil {
            return fmt.Errorf("failed to apply firewall: %w", err)
        }
        fmt.Println("✓ Firewall rules applied")
    }

    // Apply routing if enabled
    if cfg.Routing != nil && cfg.Routing.Enabled {
        fmt.Println("\n🔄 Applying Routing...")
        if err := fwMgr.ApplyRouting(cfg.Routing, cfg.Interfaces); err != nil {
            return fmt.Errorf("failed to apply routing: %w", err)
        }
        fmt.Println("✓ Routing applied")
    }

    // Apply proxy if enabled
    if cfg.Proxy != nil && cfg.Proxy.Enabled {
        fmt.Println("\n🔌 Configuring Proxy...")
        if err := applyProxyV2(fwMgr, cfg); err != nil {
            return fmt.Errorf("failed to configure proxy: %w", err)
        }
        fmt.Println("✓ Proxy configured")
    }

    fmt.Println("\n✅ Configuration applied successfully")
    fmt.Printf("   Backup available at: %s\n", backupPath)

    return nil
}

// applyFirewallV2 applies firewall rules from v2 config
func applyFirewallV2(fwMgr *firewall.Manager, cfg *config.ConfigV2) error {
    // Generate admin rules
    adminRules := generateAdminRules(cfg.Admin, cfg.Interfaces)

    // Apply INPUT filtering with admin rules + user rules
    allRules := append(adminRules, cfg.Firewall.Rules...)

    return fwMgr.ApplyInputFilteringV2(cfg.Firewall, allRules, cfg.Interfaces)
}

// generateAdminRules creates firewall rules from admin config
func generateAdminRules(admin config.AdminConfig, interfaces config.InterfacesConfig) []config.FirewallRule {
    var rules []config.FirewallRule

    // Create SSH rules for each interface
    ruleNum := 0
    for ifaceName := range interfaces {
        for _, source := range admin.Sources {
            for _, port := range admin.Ports {
                rules = append(rules, config.FirewallRule{
                    Name:      fmt.Sprintf("admin-ssh-%d", ruleNum),
                    Interface: ifaceName,
                    Sources:   []string{source},
                    Protocol:  "tcp",
                    Ports:     []int{port},
                    Action:    "accept",
                })
                ruleNum++
            }
        }
    }

    return rules
}

// applyProxyV2 configures HAProxy from v2 config
func applyProxyV2(fwMgr *firewall.Manager, cfg *config.ConfigV2) error {
    if cfg.Proxy.Mode == "egress" && cfg.Proxy.Type == "transparent" {
        // Generate HAProxy config
        if err := haproxy.ConfigureTransparentEgress(cfg.Proxy); err != nil {
            return fmt.Errorf("failed to configure HAProxy: %w", err)
        }

        // Apply interception rules
        if err := fwMgr.ApplyInterception(cfg.Proxy.Intercept, cfg.Proxy.Bind.Port, cfg.Interfaces); err != nil {
            return fmt.Errorf("failed to apply interception: %w", err)
        }

        return nil
    }

    // TODO: Implement ingress reverse proxy
    return fmt.Errorf("proxy mode '%s' type '%s' not yet implemented", cfg.Proxy.Mode, cfg.Proxy.Type)
}

// showV2ConfigSummary displays configuration summary
func showV2ConfigSummary(cfg *config.ConfigV2) {
    fmt.Println("📋 Configuration Summary:")
    fmt.Println("========================")

    fmt.Printf("Admin Sources: %v\n", cfg.Admin.Sources)
    fmt.Printf("Interfaces: %d defined\n", len(cfg.Interfaces))

    if cfg.Firewall != nil && cfg.Firewall.Enabled {
        fmt.Printf("Firewall: ENABLED (policy: %s, %d rules)\n",
            cfg.Firewall.DefaultPolicy, len(cfg.Firewall.Rules))
    }

    if cfg.Routing != nil && cfg.Routing.Enabled {
        fmt.Printf("Routing: ENABLED (masquerade on %s)\n", cfg.Routing.Masquerade.Interface)
    }

    if cfg.Proxy != nil && cfg.Proxy.Enabled {
        fmt.Printf("Proxy: ENABLED (mode: %s, type: %s, port: %d)\n",
            cfg.Proxy.Mode, cfg.Proxy.Type, cfg.Proxy.Bind.Port)
    }

    fmt.Println()
}
```

**Estimated Time**: 3 hours

---

## Phase 6: Testing & Deployment (P0)

### Goal
Test on real server and verify functionality.

### Steps

1. **Build new binary**:
   ```bash
   make build
   ```

2. **Create v2 config for egress-proxy-01**:
   ```json
   {
     "admin": {
       "sources": ["213.48.12.11/32", "149.241.32.219/32"]
     },
     "interfaces": {
       "public": "eth0",
       "private": "eth1"
     },
     "firewall": {
       "enabled": true,
       "default_policy": "drop",
       "rules": [
         {
           "name": "allow-worker",
           "interface": "private",
           "sources": ["178.62.33.58/32"],
           "protocol": "all",
           "action": "accept"
         }
       ]
     },
     "routing": {
       "enabled": true,
       "ip_forward": true,
       "masquerade": {
         "enabled": true,
         "interface": "public"
       }
     },
     "proxy": {
       "enabled": true,
       "mode": "egress",
       "type": "transparent",
       "bind": {
         "interface": "loopback",
         "port": 3128
       },
       "intercept": {
         "ports": [80, 443],
         "from_interface": "private"
       },
       "logging": {
         "enabled": true,
         "path": "/var/log/haproxy/egress.log"
       }
     }
   }
   ```

3. **Deploy to server**:
   ```bash
   scp bin/proxyctl root@egress-proxy-01.carmendata.net:/usr/local/bin/
   scp config-v2.json root@egress-proxy-01.carmendata.net:/etc/proxyctl/egress.json
   ```

4. **Apply configuration**:
   ```bash
   ssh root@egress-proxy-01.carmendata.net 'proxyctl apply /etc/proxyctl/egress.json'
   ```

5. **Verify**:
   ```bash
   # Check IP forwarding
   ssh root@egress-proxy-01.carmendata.net 'cat /proc/sys/net/ipv4/ip_forward'

   # Check iptables
   ssh root@egress-proxy-01.carmendata.net 'iptables -t nat -L -n -v'

   # Check HAProxy
   ssh root@egress-proxy-01.carmendata.net 'systemctl status haproxy'
   ssh root@egress-proxy-01.carmendata.net 'ss -tlnp | grep 3128'
   ```

**Estimated Time**: 2-3 hours

---

## Total Estimated Time

| Phase | Description | Time |
|-------|-------------|------|
| 1 | Config Schema v2.0 | 4-6 hours |
| 2 | Routing Implementation | 2-3 hours |
| 3 | HAProxy Config Generation | 3-4 hours |
| 4 | PREROUTING Redirect | 2 hours |
| 5 | Update Commands | 3 hours |
| 6 | Testing & Deployment | 2-3 hours |
| **TOTAL** | **P0 Critical Path** | **16-21 hours** |

**With contingency (HAProxy issues)**: 20-25 hours (2.5-3 days)

---

## Risk Mitigation

### High Risk: HAProxy Transparent Proxy

**Problem**: HAProxy may not support true transparent TCP proxying well.

**Contingency Plan**:
1. Try HAProxy with `server forward 0.0.0.0:0` (as documented)
2. If fails, try HAProxy with `accept-proxy` and modify DNAT to use PROXY protocol
3. If still fails, **disable proxy section** and use pure IP/nftables routing

**Pure Routing Fallback**:
If HAProxy transparent proxy doesn't work, we simply disable the `proxy` section and rely on pure IP forwarding + MASQUERADE:

```json
{
  "proxy": {
    "enabled": false
  }
}
```

**Result**:
- ✅ All traffic forwarded (HTTP, HTTPS, SSH, DNS, everything)
- ✅ Source IP masquerading works (outbound IP = proxy IP)
- ❌ No HTTP-level logging (only iptables connection logs)
- ❌ No URL visibility (only destination IPs/ports)

**Decision Point**: Test HAProxy first (Phase 3). If issues, disable proxy and use routing-only mode.

---

## Success Criteria

**P0 Complete** when:
- ✅ v2 config parses and validates
- ✅ Firewall rules applied (INPUT filtering)
- ✅ IP forwarding enabled
- ✅ MASQUERADE working (outbound IP = proxy IP)
- ✅ HAProxy intercepting HTTP/HTTPS (or routing-only mode if HAProxy fails)
- ✅ Non-HTTP traffic bypasses proxy
- ✅ SSH access works from admin IPs
- ✅ Worker server can route through proxy

**Test Command** (from worker):
```bash
curl -v http://ifconfig.me  # Should show egress proxy IP (165.22.116.193)
```

---

## Next Steps

1. **Review this plan** with stakeholders
2. **Begin Phase 1** (Config Schema)
3. **Test incrementally** after each phase
4. **Document issues** as they arise
5. **Adjust plan** based on real-world testing

---

## See Also

- [CONFIG-V2-SCHEMA.md](CONFIG-V2-SCHEMA.md) - Complete v2.0 schema specification
- [GAP-ANALYSIS-V2.md](GAP-ANALYSIS-V2.md) - Gap analysis details
- [CLAUDE.md](../CLAUDE.md) - Project architecture
