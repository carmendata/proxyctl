package logger

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
	"github.com/carmendata/proxyctl/internal/pkgmgr"
)

// DUAL FIREWALL SUPPORT: iptables + nftables
//
// This package supports both iptables and nftables for connection logging.
// See internal/firewall/firewall.go for the full MIGRATION PLAN.
//
// Functions to remove when dropping iptables support:
// - createIPTablesRules()
// - removeIPTablesRules()
// - setupIPTablesSystemdService()
// - removeIPTablesSystemdService()
//
// Functions to keep (nftables-only):
// - createNFTablesRules()
// - removeNFTablesRules()
// - addIncludeToNFTablesConf()
// - removeIncludeFromNFTablesConf()
// - findNFTablesMainConf()
// - verifyNFTablesRulesLoaded()

const (
	LogPrefix     = "EGRESS_MONITOR"
	LogFile       = "/var/log/proxyctl/egress.log"
	LogDir        = "/var/log/proxyctl"
	RsyslogConf   = "/etc/rsyslog.d/10-egress-monitor.conf" // 10- runs before 50-default.conf
	LogrotateConf = "/etc/logrotate.d/egress-monitor"
	NFTablesConf  = "/etc/nftables.d/egress-monitor.nft"
)

// Possible nftables config file locations (distro-specific)
var nftablesMainConfPaths = []string{
	"/etc/sysconfig/nftables.conf", // CentOS/RHEL/Fedora
	"/etc/nftables.conf",           // Debian/Ubuntu
}

// Manager handles connection logger operations
type Manager struct {
	LogFile       string
	RsyslogConf   string
	LogrotateConf string

	// Configuration-driven monitoring (new fields)
	Chains           []string // Netfilter chains to monitor (OUTPUT, INPUT, FORWARD)
	Protocols        []string // Protocols to monitor (tcp, udp, icmp, all)
	IncludePrivate   bool     // Include RFC1918 + link-local ranges
	IncludeLoopback  bool     // Include 127.0.0.0/8
	IncludeMulticast bool     // Include 224.0.0.0/4, 240.0.0.0/4
	IncludeRanges    []string // Whitelist (if non-empty, only monitor these)
	ExcludeRanges    []string // Blacklist (remove from monitoring)
}

// NewManager creates a new logger manager with default settings
// For backward compatibility - uses current behavior (public IPs only)
func NewManager() *Manager {
	return &Manager{
		LogFile:       LogFile,
		RsyslogConf:   RsyslogConf,
		LogrotateConf: LogrotateConf,
		Chains:        []string{"OUTPUT"}, // Default: egress monitoring
		Protocols:     []string{"tcp", "udp"}, // Default: TCP and UDP
		// All include flags default to false (backward compatible)
	}
}

// NewManagerFromConfig creates a new logger manager from LoggerConfig
// Applies user-specified monitoring settings
func NewManagerFromConfig(cfg *config.LoggerConfig) *Manager {
	m := &Manager{
		LogFile:          cfg.Output,
		RsyslogConf:      RsyslogConf,
		LogrotateConf:    LogrotateConf,
		IncludePrivate:   cfg.IncludePrivate,
		IncludeLoopback:  cfg.IncludeLoopback,
		IncludeMulticast: cfg.IncludeMulticast,
		IncludeRanges:    cfg.IncludeRanges,
		ExcludeRanges:    cfg.ExcludeRanges,
	}

	// Set chains (default to OUTPUT if not specified)
	if len(cfg.Chains) > 0 {
		m.Chains = cfg.Chains
	} else {
		m.Chains = []string{"OUTPUT"}
	}

	// Set protocols (default to TCP+UDP if not specified)
	if len(cfg.Protocols) > 0 {
		m.Protocols = cfg.Protocols
	} else {
		m.Protocols = []string{"tcp", "udp"}
	}

	// If output not specified, use default
	if m.LogFile == "" {
		m.LogFile = LogFile
	}

	return m
}

// getMonitoredRanges computes which IP ranges to monitor based on config
// Implements two-tier filtering: Categories → Include Filter → Exclude Filter
//
// Logic:
//  1. Build base set (public IPs + enabled categories)
//  2. Apply include_ranges as whitelist (intersection) if non-empty
//  3. Apply exclude_ranges as blacklist (subtraction)
//
// Returns: List of IP ranges that should NOT be monitored (for firewall exclusion rules)
func (m *Manager) getMonitoredRanges() []string {
	// Define special IP categories
	privateRanges := []string{
		"10.0.0.0/8",      // RFC1918 private
		"172.16.0.0/12",   // RFC1918 private
		"192.168.0.0/16",  // RFC1918 private
		"169.254.0.0/16",  // Link-local (included with private)
	}
	loopbackRanges := []string{
		"127.0.0.0/8", // Loopback
	}
	multicastRanges := []string{
		"224.0.0.0/4", // Multicast
		"240.0.0.0/4", // Reserved/multicast
	}

	// Step 1: Build base exclusion set (what NOT to monitor by default)
	// Start by excluding private, loopback, and multicast
	baseExclusions := []string{}

	if !m.IncludePrivate {
		baseExclusions = append(baseExclusions, privateRanges...)
	}
	if !m.IncludeLoopback {
		baseExclusions = append(baseExclusions, loopbackRanges...)
	}
	if !m.IncludeMulticast {
		baseExclusions = append(baseExclusions, multicastRanges...)
	}

	// Step 2: If include_ranges is set, it acts as a whitelist
	// We can't easily implement intersection in firewall rules, so we handle this differently:
	// If include_ranges is non-empty, we ONLY add those ranges to monitoring
	// This means: return ALL ranges EXCEPT include_ranges as exclusions
	if len(m.IncludeRanges) > 0 {
		// Whitelist mode: Only monitor include_ranges
		// Return: everything else as exclusions
		// Note: This is a simplified implementation. For full correctness, we'd need
		// to compute the inverse of include_ranges, which is complex.
		// Instead, we return the standard exclusions + custom exclude_ranges
		// The firewall rules will be built to ONLY match include_ranges
		return m.ExcludeRanges // Let caller handle whitelist logic
	}

	// Step 3: No whitelist - use base exclusions + custom excludes
	finalExclusions := baseExclusions
	finalExclusions = append(finalExclusions, m.ExcludeRanges...)

	return finalExclusions
}

// hasWhitelist returns true if include_ranges is configured (whitelist mode)
func (m *Manager) hasWhitelist() bool {
	return len(m.IncludeRanges) > 0
}

// Remove removes the connection logger
func (m *Manager) Remove() error {
	// Detect firewall type
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to detect firewall: %w", err)
	}

	// Remove firewall rules based on type
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		if err := m.removeIPTablesRules(); err != nil {
			return err
		}
	case firewall.TypeNFTables:
		if err := m.removeNFTablesRules(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported firewall type: %s", fwMgr.Type)
	}

	// Remove rsyslog configuration
	if err := m.removeRsyslogConfig(); err != nil {
		return err
	}

	// Remove logrotate configuration
	if err := m.removeLogrotateConfig(); err != nil {
		return err
	}

	return nil
}

// removeIPTablesRules removes EGRESS_LOG chain
func (m *Manager) removeIPTablesRules() error {
	// Remove ALL jumps to EGRESS_LOG chain (handle duplicates from failed idempotent installs)
	// Keep trying until the command fails (no more rules to delete)
	for {
		cmd := exec.Command("iptables", "-D", "OUTPUT", "-j", "EGRESS_LOG")
		if err := cmd.Run(); err != nil {
			// No more rules to delete
			break
		}
	}

	// Flush and delete EGRESS_LOG chain
	exec.Command("iptables", "-F", "EGRESS_LOG").Run()
	exec.Command("iptables", "-X", "EGRESS_LOG").Run()

	// Remove systemd service if it exists
	m.removeIPTablesSystemdService()

	return nil
}

// deleteRsyslogConfig removes the rsyslog configuration file (unit testable)
func (m *Manager) deleteRsyslogConfig() error {
	if _, err := os.Stat(m.RsyslogConf); err == nil {
		if err := os.Remove(m.RsyslogConf); err != nil {
			return fmt.Errorf("failed to remove rsyslog config: %w", err)
		}
	}
	return nil
}

// removeRsyslogConfig removes rsyslog configuration (public API - deletes config and restarts service)
func (m *Manager) removeRsyslogConfig() error {
	if err := m.deleteRsyslogConfig(); err != nil {
		return err
	}
	// Only restart if the file existed (was deleted)
	if _, err := os.Stat(m.RsyslogConf); os.IsNotExist(err) {
		return m.restartRsyslog()
	}
	return nil
}

// removeLogrotateConfig removes logrotate configuration
func (m *Manager) removeLogrotateConfig() error {
	if _, err := os.Stat(m.LogrotateConf); err == nil {
		if err := os.Remove(m.LogrotateConf); err != nil {
			return fmt.Errorf("failed to remove logrotate config: %w", err)
		}
	}

	return nil
}

// Install installs the connection logger
func (m *Manager) Install() error {
	// Ensure a firewall is available (install if necessary)
	fwType, err := firewall.EnsureFirewall()
	if err != nil {
		return fmt.Errorf("failed to ensure firewall is available: %w", err)
	}

	// Create firewall manager with the ensured firewall type
	fwMgr := &firewall.Manager{Type: fwType}

	// Check if already installed - if so, reinstall (idempotent)
	if err := m.checkNotInstalled(fwMgr.Type); err != nil {
		// Already installed - clean up firewall rules only (preserve configs and logs)
		fmt.Println("Logger already installed - reinstalling (idempotent)...")

		// Rotate logs before upgrade to preserve old logs separately
		// This moves egress.log -> egress.log.1, egress.log.1 -> egress.log.2, etc.
		m.rotateLogs()

		// Only remove firewall rules, not rsyslog/logrotate configs
		// This preserves log file content during upgrades
		switch fwMgr.Type {
		case firewall.TypeIPTables:
			m.removeIPTablesRules() // Ignore errors, we'll recreate anyway
		case firewall.TypeNFTables:
			m.removeNFTablesRules() // Ignore errors, we'll recreate anyway
		}
	}

	// Create firewall rules based on type
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		if err := m.createIPTablesRules(); err != nil {
			return err
		}
	case firewall.TypeNFTables:
		if err := m.createNFTablesRules(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported firewall type: %s", fwMgr.Type)
	}

	// Create log directory
	if err := os.MkdirAll(LogDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Fix permissions for rsyslog compatibility
	// On Ubuntu/Debian, rsyslog may run as 'syslog' user (unprivileged)
	// Standard practice: root:syslog with 0775 (group-writable)
	if err := m.fixLogDirectoryPermissions(); err != nil {
		return fmt.Errorf("failed to set log directory permissions: %w", err)
	}

	// Ensure rsyslog is installed (connection logging requires it)
	fmt.Println("Checking rsyslog installation (required for connection logging)...")
	if err := EnsureRsyslog(); err != nil {
		return fmt.Errorf("cannot install connection logger: rsyslog is required for logging\n\n"+
			"Failed to install rsyslog: %w\n\n"+
			"SOLUTION:\n"+
			"  Install rsyslog manually:\n"+
			"    Ubuntu/Debian: sudo apt-get install -y rsyslog\n"+
			"    RHEL/CentOS:   sudo dnf install -y rsyslog\n\n"+
			"  Then run this command again.", err)
	}
	fmt.Println("✓ rsyslog is installed")

	// Ensure logrotate is installed (recommended for log rotation)
	fmt.Println("Checking logrotate installation (recommended for log rotation)...")
	if err := EnsureLogrotate(); err != nil {
		// logrotate is recommended but not critical - warn but don't fail
		fmt.Printf("Warning: Failed to install logrotate: %v\n", err)
		fmt.Println("Log rotation will not work automatically.")
		fmt.Println("Consider installing manually: apt-get install logrotate (or yum/dnf)")
	} else {
		fmt.Println("✓ logrotate is installed")
	}

	// Configure rsyslog (same for both)
	if err := m.configureRsyslog(); err != nil {
		return err
	}

	// Configure logrotate (same for both)
	if err := m.configureLogrotate(); err != nil {
		return err
	}

	return nil
}

// createIPTablesRules creates logging rules
func (m *Manager) createIPTablesRules() error {
	// Create custom chain
	cmd := exec.Command("iptables", "-N", "EGRESS_LOG")
	cmd.Run() // Ignore error if exists

	// Flush existing rules
	exec.Command("iptables", "-F", "EGRESS_LOG").Run()

	// Get IP ranges to exclude based on configuration
	if m.hasWhitelist() {
		// Whitelist mode: Only log include_ranges
		// Add all include_ranges with explicit match rules
		for _, ipRange := range m.IncludeRanges {
			// For each protocol, add a match rule for this IP range
			for _, proto := range m.Protocols {
				protoLower := strings.ToLower(proto)
				if protoLower == "all" {
					// Log all protocols for this IP
					cmd := exec.Command("iptables", "-A", "EGRESS_LOG",
						"-d", ipRange,
						"-m", "state", "--state", "NEW",
						"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to add whitelist rule for %s: %w", ipRange, err)
					}
				} else {
					// Log specific protocol for this IP
					cmd := exec.Command("iptables", "-A", "EGRESS_LOG",
						"-p", protoLower,
						"-d", ipRange,
						"-m", "state", "--state", "NEW",
						"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to add %s whitelist rule for %s: %w", protoLower, ipRange, err)
					}
				}
			}
		}
		// Add exclude_ranges as additional exclusions (if any)
		for _, ipRange := range m.ExcludeRanges {
			cmd := exec.Command("iptables", "-A", "EGRESS_LOG", "-d", ipRange, "-j", "RETURN")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add exclusion for %s: %w", ipRange, err)
			}
		}
	} else {
		// Normal mode: Exclude specified ranges
		excludedRanges := m.getMonitoredRanges()
		for _, ipRange := range excludedRanges {
			cmd := exec.Command("iptables", "-A", "EGRESS_LOG", "-d", ipRange, "-j", "RETURN")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to add exclusion for %s: %w", ipRange, err)
			}
		}

		// Add logging rules for configured protocols
		for _, proto := range m.Protocols {
			protoLower := strings.ToLower(proto)
			if protoLower == "all" {
				// Log all protocols
				cmd = exec.Command("iptables", "-A", "EGRESS_LOG",
					"-m", "state", "--state", "NEW",
					"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to add logging rule for all protocols: %w", err)
				}
			} else {
				// Log specific protocol
				cmd = exec.Command("iptables", "-A", "EGRESS_LOG",
					"-p", protoLower,
					"-m", "state", "--state", "NEW",
					"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to add %s logging rule: %w", protoLower, err)
				}
			}
		}
	}

	// Accept all traffic (monitoring only, no blocking)
	cmd = exec.Command("iptables", "-A", "EGRESS_LOG", "-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add return rule: %w", err)
	}

	// Insert jump to logging chain
	cmd = exec.Command("iptables", "-I", "OUTPUT", "1", "-j", "EGRESS_LOG")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to insert jump rule: %w", err)
	}

	// Set up systemd service for persistence across reboots
	if err := m.setupIPTablesSystemdService(); err != nil {
		// Log warning but don't fail - rules are still active
		fmt.Printf("Warning: Failed to set up systemd service for persistence: %v\n", err)
		fmt.Println("Rules are active but will not persist across reboots.")
		fmt.Println("You may need to reinstall after reboot.")
	}

	return nil
}

// createRsyslogConfig creates the rsyslog configuration file (unit testable)
func (m *Manager) createRsyslogConfig() error {
	// Use modern RainerScript format (rsyslog v8+)
	content := fmt.Sprintf(`# Egress Connection Monitoring
# Separate kernel logs with %s prefix to dedicated log file

if $msg contains "%s" then {
    action(type="omfile" file="%s")
    stop
}
`, LogPrefix, LogPrefix, m.LogFile)

	if err := os.WriteFile(m.RsyslogConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write rsyslog config: %w", err)
	}

	return nil
}

// restartRsyslog restarts the rsyslog service (integration test only)
func (m *Manager) restartRsyslog() error {
	// Restart rsyslog to ensure config is loaded and log files are reopened
	// This is safe because we rotate logs before upgrades (old logs preserved in .1, .2, etc.)
	cmd := exec.Command("systemctl", "restart", "rsyslog")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart rsyslog: %w", err)
	}
	return nil
}

// configureRsyslog configures rsyslog (public API - creates config and restarts service)
func (m *Manager) configureRsyslog() error {
	if err := m.createRsyslogConfig(); err != nil {
		return err
	}
	return m.restartRsyslog()
}

// configureLogrotate configures logrotate
func (m *Manager) configureLogrotate() error {
	// Determine file ownership for rotated logs
	// Ubuntu: syslog:adm, Debian/others: root:root
	fileOwner := "root root"
	if m.hasSyslogUser() {
		fileOwner = "syslog adm"
	}

	content := fmt.Sprintf(`%s {
    daily
    rotate 14
    compress
    delaycompress
    dateext
    missingok
    notifempty
    create 0640 %s
    su %s
    sharedscripts
    postrotate
        systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
`, m.LogFile, fileOwner, fileOwner)

	if err := os.WriteFile(m.LogrotateConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write logrotate config: %w", err)
	}

	return nil
}

// checkNotInstalled checks if logger is already installed
func (m *Manager) checkNotInstalled(fwType firewall.Type) error {
	switch fwType {
	case firewall.TypeIPTables:
		cmd := exec.Command("iptables", "-L", "OUTPUT", "-n")
		output, _ := cmd.CombinedOutput()
		// Check for the chain name (EGRESS_LOG), not the log prefix
		if containsString(string(output), "EGRESS_LOG") {
			return fmt.Errorf("monitoring appears to already be installed (iptables)")
		}
	case firewall.TypeNFTables:
		cmd := exec.Command("nft", "list", "tables")
		output, _ := cmd.CombinedOutput()
		if strings.Contains(string(output), "egress_monitor") {
			return fmt.Errorf("monitoring appears to already be installed (nftables)")
		}
	}
	return nil
}

// createNFTablesRules creates logging rules using nftables
func (m *Manager) createNFTablesRules() error {
	// Build nftables config
	var config strings.Builder
	config.WriteString("# Connection Monitoring (proxyctl)\n")
	config.WriteString("# Generated by proxyctl - do not edit manually\n\n")
	config.WriteString("table ip egress_monitor {\n")
	config.WriteString("    chain output {\n")
	config.WriteString("        type filter hook output priority -1; policy accept;\n\n")

	// Handle whitelist vs normal mode
	if m.hasWhitelist() {
		// Whitelist mode: Only log include_ranges
		config.WriteString("        # Whitelist mode: Only monitor specified IPs\n")

		// Add exclusions first (highest priority)
		if len(m.ExcludeRanges) > 0 {
			config.WriteString("        # Excluded ranges\n")
			for _, ipRange := range m.ExcludeRanges {
				config.WriteString(fmt.Sprintf("        ip daddr %s return\n", ipRange))
			}
			config.WriteString("\n")
		}

		// Add include_ranges with logging
		config.WriteString("        # Whitelisted ranges\n")
		for _, ipRange := range m.IncludeRanges {
			for _, proto := range m.Protocols {
				protoLower := strings.ToLower(proto)
				switch protoLower {
				case "tcp":
					config.WriteString(fmt.Sprintf("        ip daddr %s meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new log prefix \"%s: \" level info\n", ipRange, LogPrefix))
				case "udp":
					config.WriteString(fmt.Sprintf("        ip daddr %s meta l4proto udp ct state new log prefix \"%s: \" level info\n", ipRange, LogPrefix))
				case "icmp":
					config.WriteString(fmt.Sprintf("        ip daddr %s meta l4proto icmp ct state new log prefix \"%s: \" level info\n", ipRange, LogPrefix))
				case "all":
					config.WriteString(fmt.Sprintf("        ip daddr %s ct state new log prefix \"%s: \" level info\n", ipRange, LogPrefix))
				}
			}
		}
	} else {
		// Normal mode: Exclude specified ranges
		excludedRanges := m.getMonitoredRanges()
		if len(excludedRanges) > 0 {
			config.WriteString("        # Excluded ranges\n")
			for _, ipRange := range excludedRanges {
				config.WriteString(fmt.Sprintf("        ip daddr %s return\n", ipRange))
			}
			config.WriteString("\n")
		}

		// Add logging rules for configured protocols
		config.WriteString("        # Monitored protocols\n")
		for _, proto := range m.Protocols {
			protoLower := strings.ToLower(proto)
			switch protoLower {
			case "tcp":
				config.WriteString(fmt.Sprintf("        meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new log prefix \"%s: \" level info\n", LogPrefix))
			case "udp":
				config.WriteString(fmt.Sprintf("        meta l4proto udp ct state new log prefix \"%s: \" level info\n", LogPrefix))
			case "icmp":
				config.WriteString(fmt.Sprintf("        meta l4proto icmp ct state new log prefix \"%s: \" level info\n", LogPrefix))
			case "all":
				config.WriteString(fmt.Sprintf("        ct state new log prefix \"%s: \" level info\n", LogPrefix))
			}
		}
	}

	config.WriteString("    }\n")
	config.WriteString("}\n")

	// Create nftables.d directory
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create nftables.d directory: %w", err)
	}

	// Write config file
	if err := os.WriteFile(NFTablesConf, []byte(config.String()), 0644); err != nil {
		return fmt.Errorf("failed to write nftables config: %w", err)
	}

	// Add include to main config
	if err := addIncludeToNFTablesConf(); err != nil {
		return fmt.Errorf("failed to add include to nftables.conf: %w", err)
	}

	// Ensure nftables service is enabled and started (required for Ubuntu 24.04+)
	// This prevents issues where rules are loaded but not persistent or functional
	enableNFTablesService()

	// Try multiple methods to load the rules (in order of preference)
	var loadErr error

	// Method 1: Reload nftables service (preserves existing rules)
	fmt.Println("Attempting to reload nftables service...")
	cmd := exec.Command("systemctl", "reload", "nftables")
	if err := cmd.Run(); err == nil {
		// Verify rules loaded
		if verifyNFTablesRulesLoaded() == nil {
			fmt.Println("✓ Rules loaded successfully via systemctl reload")
			return nil
		}
		fmt.Printf("Warning: systemctl reload succeeded but rules not active\n")
	} else {
		loadErr = err
		fmt.Printf("Warning: systemctl reload failed: %v\n", err)
	}

	// Method 2: Direct load of our config file
	fmt.Printf("Attempting direct load of %s...\n", NFTablesConf)
	cmd = exec.Command("nft", "-f", NFTablesConf)
	if output, err := cmd.CombinedOutput(); err == nil {
		// Verify rules loaded
		if verifyNFTablesRulesLoaded() == nil {
			fmt.Println("✓ Rules loaded successfully via direct nft -f")
			return nil
		}
		fmt.Printf("Warning: direct load succeeded but rules not active\n")
	} else {
		loadErr = err
		fmt.Printf("Warning: direct load failed: %v\nOutput: %s\n", err, string(output))
	}

	// Method 3: Load main config file
	mainConf := findNFTablesMainConf()
	fmt.Printf("Attempting to load main config %s...\n", mainConf)
	cmd = exec.Command("nft", "-f", mainConf)
	if output, err := cmd.CombinedOutput(); err == nil {
		// Verify rules loaded
		if verifyNFTablesRulesLoaded() == nil {
			fmt.Println("✓ Rules loaded successfully via main config")
			return nil
		}
		fmt.Printf("Warning: main config load succeeded but rules not active\n")
	} else {
		loadErr = err
		fmt.Printf("Warning: main config load failed: %v\nOutput: %s\n", err, string(output))
	}

	// All methods failed - return error with verification
	if verifyNFTablesRulesLoaded() != nil {
		return fmt.Errorf("failed to load nftables rules after trying all methods. Last error: %w.\n"+
			"Config file created at: %s\n"+
			"Main config: %s\n"+
			"Manual fix: nft -f %s", loadErr, NFTablesConf, mainConf, NFTablesConf)
	}

	// Rules are somehow loaded despite errors - success
	fmt.Println("✓ Rules are active (loaded by unknown method)")
	return nil
}

// removeNFTablesRules removes nftables logging rules
func (m *Manager) removeNFTablesRules() error {
	// Remove table
	exec.Command("nft", "delete", "table", "ip", "egress_monitor").Run()

	// Remove config file
	os.Remove(NFTablesConf)

	// Remove include from main config
	removeIncludeFromNFTablesConf()

	// Reload nftables
	exec.Command("systemctl", "reload", "nftables").Run()

	return nil
}

// addIncludeToNFTablesConf adds include directive to main nftables config
func addIncludeToNFTablesConf() error {
	mainConf := findNFTablesMainConf()
	fmt.Printf("Using nftables config file: %s\n", mainConf)

	content, err := os.ReadFile(mainConf)
	if err != nil {
		// If file doesn't exist, create it with just the include
		fmt.Printf("Creating new nftables config at %s\n", mainConf)
		return os.WriteFile(mainConf,
			[]byte(fmt.Sprintf(`include "%s"`+"\n", NFTablesConf)), 0644)
	}

	includeLine := fmt.Sprintf(`include "%s"`, NFTablesConf)
	if strings.Contains(string(content), includeLine) {
		fmt.Println("Include directive already present")
		return nil // Already included
	}

	// Append include line
	fmt.Printf("Adding include directive to %s\n", mainConf)
	f, err := os.OpenFile(mainConf, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s for writing: %w", mainConf, err)
	}
	defer f.Close()

	_, err = f.WriteString(includeLine + "\n")
	if err != nil {
		return fmt.Errorf("failed to write include directive: %w", err)
	}

	return nil
}

// removeIncludeFromNFTablesConf removes include directive from main nftables config
func removeIncludeFromNFTablesConf() error {
	// Try all possible locations
	for _, mainConf := range nftablesMainConfPaths {
		content, err := os.ReadFile(mainConf)
		if err != nil {
			continue // File doesn't exist, try next
		}

		includeLine := fmt.Sprintf(`include "%s"`, NFTablesConf)
		lines := strings.Split(string(content), "\n")
		var newLines []string

		for _, line := range lines {
			if !strings.Contains(line, includeLine) {
				newLines = append(newLines, line)
			}
		}

		// Only write if something changed
		if len(newLines) != len(lines) {
			return os.WriteFile(mainConf, []byte(strings.Join(newLines, "\n")), 0644)
		}
	}

	return nil
}

// findNFTablesMainConf finds the nftables main config file for this distro
func findNFTablesMainConf() string {
	// Try each possible location in order
	for _, path := range nftablesMainConfPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Default to Debian/Ubuntu path if none found
	return nftablesMainConfPaths[1]
}

// verifyNFTablesRulesLoaded verifies that the egress_monitor table is actually loaded
func verifyNFTablesRulesLoaded() error {
	cmd := exec.Command("nft", "list", "table", "ip", "egress_monitor")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rules not loaded: nft list table ip egress_monitor failed: %w", err)
	}
	return nil
}

// enableNFTablesService enables and starts the nftables service
// This is required on systems like Ubuntu 24.04 where nftables might be installed but not running
func enableNFTablesService() {
	// Try to enable the service (best effort, ignore errors)
	exec.Command("systemctl", "enable", "nftables").Run()

	// Try to start the service (best effort, ignore errors)
	// This might fail if no main config exists yet, which is OK
	exec.Command("systemctl", "start", "nftables").Run()
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr || containsInMiddle(s, substr)))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// setupIPTablesSystemdService creates a systemd service for iptables rule persistence
func (m *Manager) setupIPTablesSystemdService() error {
	serviceContent := `[Unit]
Description=ProxyCtl Connection Logger (iptables persistence)
After=network.target rsyslog.service
Before=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/egressctl logger install
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target
`

	servicePath := "/etc/systemd/system/egressctl-logger.service"

	// Write service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write systemd service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", "egressctl-logger").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	fmt.Println("✓ Systemd service installed for automatic persistence across reboots")

	return nil
}

// removeIPTablesSystemdService removes the systemd service for iptables persistence
func (m *Manager) removeIPTablesSystemdService() {
	servicePath := "/etc/systemd/system/egressctl-logger.service"

	// Stop and disable service
	exec.Command("systemctl", "stop", "egressctl-logger").Run()
	exec.Command("systemctl", "disable", "egressctl-logger").Run()

	// Remove service file
	os.Remove(servicePath)

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()
}

// rotateLogs manually rotates the log file before an upgrade
// This preserves old logs in .1, .2, etc. while creating a fresh log file
func (m *Manager) rotateLogs() {
	// Check if log file exists
	if _, err := os.Stat(m.LogFile); os.IsNotExist(err) {
		// No log file to rotate
		return
	}

	// Use logrotate to rotate the logs
	// The -f flag forces immediate rotation regardless of schedule
	cmd := exec.Command("logrotate", "-f", m.LogrotateConf)
	if err := cmd.Run(); err != nil {
		// Log rotation failed, but don't fail the upgrade
		// The reload-or-restart of rsyslog will still work
		fmt.Printf("Warning: Log rotation failed (non-critical): %v\n", err)
		return
	}

	fmt.Println("✓ Logs rotated (old logs preserved in .1, .2, etc.)")
}

// hasSyslogUser checks if the syslog user exists on this system
func (m *Manager) hasSyslogUser() bool {
	cmd := exec.Command("getent", "passwd", "syslog")
	return cmd.Run() == nil
}

// isRsyslogInstalled checks if rsyslog is installed on the system
func isRsyslogInstalled() bool {
	_, err := exec.LookPath("rsyslogd")
	return err == nil
}

// installRsyslog installs rsyslog package
func installRsyslog() error {
	// Check if rsyslogd binary is available
	if _, err := exec.LookPath("rsyslogd"); err != nil {
		fmt.Println("rsyslog not found. Installing...")
		// Try to install rsyslog package
		if err := pkgmgr.InstallPackage("rsyslog"); err != nil {
			return fmt.Errorf("failed to install rsyslog package: %w", err)
		}
	}

	// Verify installation
	if _, err := exec.LookPath("rsyslogd"); err != nil {
		return fmt.Errorf("rsyslogd binary not found after installation")
	}

	// Start and enable rsyslog service
	exec.Command("systemctl", "start", "rsyslog").Run()  // Best effort
	exec.Command("systemctl", "enable", "rsyslog").Run() // Best effort

	fmt.Println("✓ rsyslog installed successfully")
	return nil
}

// EnsureRsyslog ensures rsyslog is installed, installing it if necessary
// Returns error if installation fails
func EnsureRsyslog() error {
	// Check if already installed
	if isRsyslogInstalled() {
		return nil
	}

	// Try to install
	return installRsyslog()
}

// isLogrotateInstalled checks if logrotate is installed on the system
func isLogrotateInstalled() bool {
	_, err := exec.LookPath("logrotate")
	return err == nil
}

// installLogrotate installs logrotate package
func installLogrotate() error {
	// Check if logrotate binary is available
	if _, err := exec.LookPath("logrotate"); err != nil {
		fmt.Println("logrotate not found. Installing...")
		// Try to install logrotate package
		if err := pkgmgr.InstallPackage("logrotate"); err != nil {
			return fmt.Errorf("failed to install logrotate package: %w", err)
		}
	}

	// Verify installation
	if _, err := exec.LookPath("logrotate"); err != nil {
		return fmt.Errorf("logrotate binary not found after installation")
	}

	fmt.Println("✓ logrotate installed successfully")
	return nil
}

// EnsureLogrotate ensures logrotate is installed, installing it if necessary
// Returns error if installation fails
func EnsureLogrotate() error {
	// Check if already installed
	if isLogrotateInstalled() {
		return nil
	}

	// Try to install
	return installLogrotate()
}

// fixLogDirectoryPermissions sets proper ownership/permissions for rsyslog compatibility
// On Ubuntu: rsyslog runs as 'syslog' user, needs group-writable directory
// On Debian: rsyslog runs as 'root', standard permissions work fine
func (m *Manager) fixLogDirectoryPermissions() error {
	// Try to get syslog group ID
	cmd := exec.Command("getent", "group", "syslog")
	output, err := cmd.Output()
	if err != nil {
		// No syslog group - rsyslog likely runs as root (Debian/CentOS)
		// Keep default root:root 0755 permissions
		return nil
	}

	// Parse group ID from "syslog:x:102:" format
	parts := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(parts) < 3 {
		return nil // Invalid format, skip
	}

	var gid int
	if _, err := fmt.Sscanf(parts[2], "%d", &gid); err != nil {
		return nil // Can't parse GID, skip
	}

	// Change group to syslog
	if err := os.Chown(LogDir, 0, gid); err != nil {
		return fmt.Errorf("failed to chown to syslog group: %w", err)
	}

	// Make directory group-writable (root:syslog 0775)
	if err := os.Chmod(LogDir, 0775); err != nil {
		return fmt.Errorf("failed to chmod to 0775: %w", err)
	}

	return nil
}
