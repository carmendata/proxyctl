package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/carmendata/proxyctl/internal/acl"
	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
	"github.com/carmendata/proxyctl/internal/logger"
)

// runStatus shows comprehensive egress proxy status
func runStatus(args []string) error {
	fmt.Println("Egress Proxy Status")
	fmt.Println("===================")
	fmt.Println()

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("❌ Configuration: Failed to load (%v)\n", err)
		return err
	}

	// Show configuration status
	showConfigStatus(cfg)
	fmt.Println()

	// Show HAProxy status
	showHAProxyStatus()
	fmt.Println()

	// Show ACL status
	showACLStatus(cfg)
	fmt.Println()

	// Show logger status
	showLoggerStatus(cfg)
	fmt.Println()

	// Show firewall status (call existing function)
	showFirewallStatusSummary()

	return nil
}

// showConfigStatus displays configuration information
func showConfigStatus(cfg *config.Config) {
	fmt.Println("Configuration:")

	// Show which config file was loaded
	configPath := cfgFile
	if configPath == "" {
		// Try to determine which default config was used
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = "/root"
		}

		// Check standard config paths
		searchPaths := []string{
			"egress.json", // Current directory
			homeDir + "/.config/proxyctl/egress.json", // User config
			"/etc/proxyctl/egress.json",               // System config
		}

		for _, path := range searchPaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
	}

	if configPath != "" {
		fmt.Printf("  File: %s\n", configPath)
	} else {
		fmt.Println("  File: Using defaults")
	}

	// Show proxy configuration
	if cfg.Proxy != nil {
		fmt.Printf("  Proxy: %s:%d\n", cfg.Proxy.IP, cfg.Proxy.Port)
	}
}

// showHAProxyStatus displays HAProxy service status
func showHAProxyStatus() {
	fmt.Println("HAProxy Service:")

	// Check if HAProxy is running
	cmd := exec.Command("systemctl", "is-active", "haproxy")
	output, err := cmd.Output()
	status := strings.TrimSpace(string(output))

	if err != nil || status != "active" {
		fmt.Printf("  Status: ❌ Not running\n")
		return
	}

	fmt.Printf("  Status: ✓ Running\n")

	// Get PID
	cmd = exec.Command("systemctl", "show", "haproxy", "--property=MainPID", "--value")
	if output, err := cmd.Output(); err == nil {
		pid := strings.TrimSpace(string(output))
		if pid != "" && pid != "0" {
			fmt.Printf("  PID: %s\n", pid)
		}
	}

	// Get uptime
	cmd = exec.Command("systemctl", "show", "haproxy", "--property=ActiveEnterTimestamp", "--value")
	if output, err := cmd.Output(); err == nil {
		timestamp := strings.TrimSpace(string(output))
		if timestamp != "" {
			// Parse timestamp and calculate uptime
			if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", timestamp); err == nil {
				uptime := time.Since(t)
				fmt.Printf("  Uptime: %s\n", formatDuration(uptime))
			}
		}
	}
}

// showACLStatus displays ACL status
func showACLStatus(cfg *config.Config) {
	fmt.Println("ACL:")

	if cfg.ACL == nil || cfg.ACL.File == "" {
		fmt.Println("  Status: Not configured")
		return
	}

	aclPath := cfg.ACL.File
	fmt.Printf("  File: %s\n", aclPath)

	// Check if ACL file exists
	info, err := os.Stat(aclPath)
	if err != nil {
		fmt.Printf("  Status: ❌ File not found\n")
		return
	}

	// Get number of entries
	mgr := acl.NewManager(aclPath)
	entries, err := mgr.List()
	if err != nil {
		fmt.Printf("  Entries: Error reading (%v)\n", err)
	} else {
		fmt.Printf("  Entries: %d IP/CIDR blocks\n", len(entries))
	}

	// Show last modified time
	fmt.Printf("  Last modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
}

// showLoggerStatus displays connection logger status
func showLoggerStatus(cfg *config.Config) {
	fmt.Println("Logger:")

	// Detect firewall type (don't try to install)
	fwType, err := firewall.Detect()
	if err != nil {
		fmt.Println("  Status: Not installed (no firewall detected)")
		return
	}

	fwMgr := &firewall.Manager{Type: fwType}

	// Create logger manager to get correct table/chain names
	var mgr *logger.Manager
	if cfg.Logger != nil {
		mgr = logger.NewManagerFromConfig(cfg.Logger)
	} else {
		mgr = logger.NewManager() // Use default name "egress"
	}

	// Check if logger rules exist
	installed, err := checkLoggerInstalledWithName(fwMgr, mgr)
	if err != nil {
		fmt.Printf("  Status: ❌ Error checking (%v)\n", err)
		return
	}

	if !installed {
		fmt.Println("  Status: Not installed")
		return
	}

	// Show configuration (from config file or inferred defaults if logger is running)
	if cfg.Logger != nil && cfg.Logger.Enabled {
		showLoggerConfig(cfg.Logger)
	} else {
		// Logger is installed but no config - show defaults
		fmt.Println("  Configuration (inferred from deployment):")
		showLoggerConfigDefaults()
	}

	fmt.Println("  Status: ✓ Installed")

	// Check for configuration drift
	drift := checkLoggerDrift(fwMgr, cfg)
	if len(drift) > 0 {
		fmt.Println("  ⚠️  Configuration Drift Detected:")
		for _, issue := range drift {
			fmt.Printf("     - %s\n", issue)
		}
		fmt.Printf("  ℹ️  To fix: egressctl logger remove && egressctl logger install\n")
	}

	// Use configured log paths if available, otherwise defaults
	var logDir, logFile string
	if cfg.Logger != nil {
		mgr := logger.NewManagerFromConfig(cfg.Logger)
		logDir = mgr.LogPath
		logFile = mgr.LogFile
	} else {
		// Fallback to defaults
		logDir = "/var/log/proxyctl/"
		logFile = logDir + "egress.log"
	}

	fmt.Printf("  Log directory: %s\n", logDir)

	// Check current log file
	if info, err := os.Stat(logFile); err == nil {
		size := float64(info.Size()) / 1024 / 1024 // Convert to MB
		// Extract filename from path
		filename := filepath.Base(logFile)
		fmt.Printf("  Current log: %s (%.1f MB)\n", filename, size)
	}
}

// showFirewallStatusSummary displays a summary of firewall status
func showFirewallStatusSummary() {
	fmt.Println("Firewall:")

	// Load config for drift detection
	cfg, cfgErr := loadConfig()
	if cfgErr != nil {
		// Config failed to load - show error but continue
		fmt.Printf("  ⚠️  Config error: %v\n", cfgErr)
	}

	// Detect firewall type (don't try to install)
	fwType, err := firewall.Detect()
	if err != nil {
		fmt.Println("  Status: Not configured (no firewall detected)")

		// Still show configuration from config file if available
		if cfg != nil {
			if cfg.Firewall != nil && cfg.Firewall.Enabled {
				fmt.Println()
				showFirewallInputConfig(cfg.Firewall)
				fmt.Println("  Status: Not deployed")
			}
			if cfg.Redirect != nil && cfg.Redirect.Enabled {
				fmt.Println()
				showRedirectConfig(cfg.Redirect, cfg.Proxy)
				fmt.Println("  Status: Not deployed")
			}
		}
		return
	}

	fwMgr := &firewall.Manager{Type: fwType}
	fmt.Printf("  Type: %s\n", fwType)

	// Show INPUT filtering configuration if enabled
	if cfg != nil && cfg.Firewall != nil && cfg.Firewall.Enabled {
		showFirewallInputConfig(cfg.Firewall)
	}

	// Check if INPUT filtering is applied
	inputApplied, err := checkInputFilteringApplied(fwMgr)
	if err != nil {
		fmt.Printf("  INPUT filtering: ❌ Error checking (%v)\n", err)
	} else if inputApplied {
		fmt.Println("  Status: ✓ Applied")

		// Check for drift if config loaded successfully
		if cfg != nil {
			inputDrift := checkFirewallInputDrift(fwMgr, cfg)
			if len(inputDrift) > 0 {
				fmt.Println("     ⚠️  Configuration Drift:")
				for _, issue := range inputDrift {
					fmt.Printf("        - %s\n", issue)
				}
			}
		}
	} else {
		fmt.Println("  Status: Not configured")
	}

	// Show OUTPUT redirect configuration if enabled
	if cfg != nil && cfg.Redirect != nil && cfg.Redirect.Enabled {
		fmt.Println()
		showRedirectConfig(cfg.Redirect, cfg.Proxy)
	}

	// Check if OUTPUT redirect is applied
	outputApplied, err := checkOutputRedirectApplied(fwMgr)
	if err != nil {
		fmt.Printf("  OUTPUT redirect: ❌ Error checking (%v)\n", err)
	} else if outputApplied {
		fmt.Println("  Status: ✓ Applied")

		// Check for drift if config loaded successfully
		if cfg != nil {
			var driftIssues []string
			if cfg.Redirect != nil && cfg.Redirect.Type == "gateway" {
				driftIssues = checkGatewayRoutingDrift(fwMgr, cfg)
			} else {
				driftIssues = checkFirewallOutputDrift(fwMgr, cfg)
			}
			if len(driftIssues) > 0 {
				fmt.Println("     ⚠️  Configuration Drift:")
				for _, issue := range driftIssues {
					fmt.Printf("        - %s\n", issue)
				}
			}
		}
	} else {
		fmt.Println("  Status: Not configured")
	}

	// Show fix command if any drift detected
	if cfg != nil {
		inputDrift := checkFirewallInputDrift(fwMgr, cfg)
		var redirectDrift []string
		if cfg.Redirect != nil && cfg.Redirect.Type == "gateway" {
			redirectDrift = checkGatewayRoutingDrift(fwMgr, cfg)
		} else {
			redirectDrift = checkFirewallOutputDrift(fwMgr, cfg)
		}
		if len(inputDrift) > 0 || len(redirectDrift) > 0 {
			fmt.Printf("  ℹ️  To fix: %s firewall apply\n", os.Args[0])
		}
	}

	// Show number of backups
	backups, err := fwMgr.ListBackups()
	if err == nil && len(backups) > 0 {
		fmt.Printf("  Backups: %d available\n", len(backups))
	}

	fmt.Println()
	fmt.Printf("  ℹ️  For detailed firewall status, run: %s firewall status\n", os.Args[0])
}

// checkLoggerInstalledWithName checks if logger firewall rules are installed using logger manager names
func checkLoggerInstalledWithName(fwMgr *firewall.Manager, mgr *logger.Manager) (bool, error) {
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		// Check if logger chain exists in filter table (not nat)
		cmd := exec.Command("iptables", "-L", mgr.IPTablesChain, "-n")
		if err := cmd.Run(); err != nil {
			return false, nil // Chain doesn't exist
		}
		return true, nil

	case firewall.TypeNFTables:
		// Check if logger table exists
		cmd := exec.Command("nft", "list", "table", "ip", mgr.NFTableName)
		if err := cmd.Run(); err != nil {
			return false, nil // Table doesn't exist
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported firewall type: %s", fwMgr.Type)
	}
}

// checkInputFilteringApplied checks if INPUT filtering rules are applied
func checkInputFilteringApplied(fwMgr *firewall.Manager) (bool, error) {
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		// Check if PROXYCTL_INPUT chain exists
		cmd := exec.Command("iptables", "-L", "PROXYCTL_INPUT", "-n")
		if err := cmd.Run(); err != nil {
			return false, nil // Chain doesn't exist
		}
		return true, nil

	case firewall.TypeNFTables:
		// Check if proxyctl_filter table exists
		cmd := exec.Command("nft", "list", "table", "inet", "proxyctl_filter")
		if err := cmd.Run(); err != nil {
			return false, nil // Table doesn't exist
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported firewall type: %s", fwMgr.Type)
	}
}

// checkOutputRedirectApplied checks if OUTPUT redirect rules are applied
func checkOutputRedirectApplied(fwMgr *firewall.Manager) (bool, error) {
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		// Check if PROXYCTL_OUTPUT chain exists
		cmd := exec.Command("iptables", "-t", "nat", "-L", "PROXYCTL_OUTPUT", "-n")
		if err := cmd.Run(); err != nil {
			return false, nil // Chain doesn't exist
		}
		return true, nil

	case firewall.TypeNFTables:
		// Check if proxyctl_redirect table exists
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_redirect")
		if err := cmd.Run(); err != nil {
			return false, nil // Table doesn't exist
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported firewall type: %s", fwMgr.Type)
	}
}

// formatDuration formats a duration in a human-readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", days)
}

// showLoggerConfigDefaults displays all default logger configuration values
func showLoggerConfigDefaults() {
	fmt.Printf("    Name: egress (default)\n")
	fmt.Printf("    Protocols: [tcp udp] (default)\n")
	fmt.Printf("    Chains: [OUTPUT] (default)\n")
	fmt.Printf("    Log path: /var/log/proxyctl/ (default)\n")
	fmt.Printf("    IP categories: public only (default)\n")
}

// showLoggerConfig displays logger configuration with defaults highlighted
func showLoggerConfig(loggerCfg *config.LoggerConfig) {
	fmt.Println("  Configuration:")

	// Name (defaults to "egress")
	if loggerCfg.Name != "" {
		fmt.Printf("    Name: %s\n", loggerCfg.Name)
	} else {
		fmt.Printf("    Name: egress (default)\n")
	}

	// Protocols (defaults to ["tcp", "udp"])
	if len(loggerCfg.Protocols) > 0 {
		fmt.Printf("    Protocols: %v\n", loggerCfg.Protocols)
	} else {
		fmt.Printf("    Protocols: [tcp udp] (default)\n")
	}

	// Chains (defaults to ["OUTPUT"])
	if len(loggerCfg.Chains) > 0 {
		fmt.Printf("    Chains: %v\n", loggerCfg.Chains)
	} else {
		fmt.Printf("    Chains: [OUTPUT] (default)\n")
	}

	// Log path (defaults to /var/log/proxyctl/)
	if loggerCfg.LogPath != "" {
		fmt.Printf("    Log path: %s\n", loggerCfg.LogPath)
	} else {
		fmt.Printf("    Log path: /var/log/proxyctl/ (default)\n")
	}

	// Category flags (all default to false)
	hasNonDefaults := false
	if loggerCfg.IncludePrivate {
		fmt.Printf("    Include private IPs: true\n")
		hasNonDefaults = true
	}
	if loggerCfg.IncludeLoopback {
		fmt.Printf("    Include loopback: true\n")
		hasNonDefaults = true
	}
	if loggerCfg.IncludeMulticast {
		fmt.Printf("    Include multicast: true\n")
		hasNonDefaults = true
	}
	if !hasNonDefaults {
		fmt.Printf("    IP categories: public only (default)\n")
	}

	// Include/Exclude ranges
	if len(loggerCfg.IncludeRanges) > 0 {
		fmt.Printf("    Include ranges (whitelist): %v\n", loggerCfg.IncludeRanges)
	}
	if len(loggerCfg.ExcludeRanges) > 0 {
		fmt.Printf("    Exclude ranges: %v\n", loggerCfg.ExcludeRanges)
	}
}

// showFirewallInputConfig displays INPUT filtering configuration with defaults highlighted
func showFirewallInputConfig(fwCfg *config.FirewallConfig) {
	fmt.Println("  INPUT Filtering Configuration:")

	// Input policy (required, no default)
	fmt.Printf("    Policy: %s\n", fwCfg.InputPolicy)

	// SSH allow list
	if len(fwCfg.AllowSSHFrom) > 0 {
		fmt.Printf("    Allow SSH from: %v\n", fwCfg.AllowSSHFrom)
	} else {
		fmt.Printf("    Allow SSH from: [] (none - SSH will be blocked!)\n")
	}

	// Proxy allow list
	if len(fwCfg.AllowProxyFrom) > 0 {
		fmt.Printf("    Allow proxy from:\n")
		for _, rule := range fwCfg.AllowProxyFrom {
			if len(rule.Ports) > 0 {
				fmt.Printf("      - %v ports %v\n", rule.Sources, rule.Ports)
			} else {
				fmt.Printf("      - %v all ports\n", rule.Sources)
			}
		}
	} else {
		fmt.Printf("    Allow proxy from: [] (none)\n")
	}
}

// showRedirectConfig displays OUTPUT redirect or gateway routing configuration
func showRedirectConfig(redirectCfg *config.RedirectConfig, proxyCfg *config.ProxyConfig) {
	if redirectCfg.Type == "gateway" {
		fmt.Println("  Gateway Routing Configuration:")

		// Redirect type
		fmt.Printf("    Type: %s\n", redirectCfg.Type)

		// Gateway IP
		fmt.Printf("    Gateway: %s\n", redirectCfg.Gateway)

		// Routing table
		tableID := redirectCfg.RoutingTable
		if tableID == 0 {
			tableID = 200 // Default
		}
		fmt.Printf("    Routing Table: %d\n", tableID)

		// Targets
		if len(redirectCfg.Targets) > 0 {
			fmt.Printf("    Targets: %v\n", redirectCfg.Targets)
		} else {
			fmt.Printf("    Targets: [] (warning: gateway requires targets!)\n")
		}
	} else {
		fmt.Println("  OUTPUT Redirect Configuration:")

		// Redirect type (required, no default)
		fmt.Printf("    Type: %s\n", redirectCfg.Type)

		// Proxy destination
		if proxyCfg != nil {
			proxyPort := proxyCfg.Port
			if proxyPort == 0 {
				proxyPort = 8080 // Default from config validation
			}
			fmt.Printf("    Proxy: %s:%d\n", proxyCfg.IP, proxyPort)
		}

		// Targets (for partial redirect)
		if redirectCfg.Type == "partial" {
			if len(redirectCfg.Targets) > 0 {
				fmt.Printf("    Targets: %v\n", redirectCfg.Targets)
			} else {
				fmt.Printf("    Targets: [] (warning: partial redirect requires targets!)\n")
			}
		} else if redirectCfg.Type == "full" {
			fmt.Printf("    Targets: all HTTP/HTTPS traffic\n")
		}
	}
}

// checkLoggerDrift detects configuration drift for logger
func checkLoggerDrift(fwMgr *firewall.Manager, cfg *config.Config) []string {
	if cfg.Logger == nil || !cfg.Logger.Enabled {
		return nil // No logger configured
	}

	mgr := logger.NewManagerFromConfig(cfg.Logger)
	var drift []string

	switch fwMgr.Type {
	case firewall.TypeNFTables:
		// Read deployed nftables rules
		cmd := exec.Command("nft", "list", "table", "ip", mgr.NFTableName)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check protocols
		configProtocols := make(map[string]bool)
		for _, proto := range mgr.Protocols {
			configProtocols[strings.ToLower(proto)] = true
		}

		deployedProtocols := make(map[string]bool)
		// TCP can be matched with "tcp flags" or "meta l4proto tcp"
		if strings.Contains(rulesText, "tcp flags") || strings.Contains(rulesText, "meta l4proto tcp") {
			deployedProtocols["tcp"] = true
		}
		if strings.Contains(rulesText, "meta l4proto udp") {
			deployedProtocols["udp"] = true
		}
		if strings.Contains(rulesText, "meta l4proto icmp") {
			deployedProtocols["icmp"] = true
		}
		// Check for "all" protocol (rules without specific protocol filter)
		if strings.Contains(rulesText, "ct state new log") &&
			!strings.Contains(rulesText, "meta l4proto") &&
			!strings.Contains(rulesText, "tcp flags") {
			deployedProtocols["all"] = true
		}

		// Compare protocols
		for proto := range configProtocols {
			if !deployedProtocols[proto] && proto != "all" {
				drift = append(drift, fmt.Sprintf("Protocol %s configured but not deployed", proto))
			}
		}
		for proto := range deployedProtocols {
			if !configProtocols[proto] && proto != "all" {
				drift = append(drift, fmt.Sprintf("Protocol %s deployed but not in config", proto))
			}
		}

		// Check include ranges (whitelist mode)
		if len(mgr.IncludeRanges) > 0 {
			for _, ipRange := range mgr.IncludeRanges {
				if !strings.Contains(rulesText, fmt.Sprintf("ip daddr %s", ipRange)) {
					drift = append(drift, fmt.Sprintf("Include range %s not found in deployed rules", ipRange))
				}
			}
		}

		// Check exclude ranges
		if len(mgr.ExcludeRanges) > 0 {
			for _, ipRange := range mgr.ExcludeRanges {
				if !strings.Contains(rulesText, fmt.Sprintf("ip daddr %s return", ipRange)) {
					drift = append(drift, fmt.Sprintf("Exclude range %s not found in deployed rules", ipRange))
				}
			}
		}

	case firewall.TypeIPTables:
		// Read deployed iptables rules from filter table
		cmd := exec.Command("iptables", "-L", mgr.IPTablesChain, "-n")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check protocols (simplified - look for protocol mentions)
		configProtocols := make(map[string]bool)
		for _, proto := range mgr.Protocols {
			configProtocols[strings.ToLower(proto)] = true
		}

		deployedProtocols := make(map[string]bool)
		if strings.Contains(rulesText, "tcp") {
			deployedProtocols["tcp"] = true
		}
		if strings.Contains(rulesText, "udp") {
			deployedProtocols["udp"] = true
		}
		if strings.Contains(rulesText, "icmp") {
			deployedProtocols["icmp"] = true
		}

		// Compare protocols
		for proto := range configProtocols {
			if !deployedProtocols[proto] && proto != "all" {
				drift = append(drift, fmt.Sprintf("Protocol %s configured but not deployed", proto))
			}
		}
		for proto := range deployedProtocols {
			if !configProtocols[proto] && proto != "all" {
				drift = append(drift, fmt.Sprintf("Protocol %s deployed but not in config", proto))
			}
		}
	}

	return drift
}

// checkFirewallInputDrift detects configuration drift for INPUT filtering
func checkFirewallInputDrift(fwMgr *firewall.Manager, cfg *config.Config) []string {
	if cfg.Firewall == nil || !cfg.Firewall.Enabled {
		return nil // No firewall configured
	}

	var drift []string

	switch fwMgr.Type {
	case firewall.TypeNFTables:
		// Read deployed nftables rules
		cmd := exec.Command("nft", "list", "table", "inet", "proxyctl_filter")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check SSH allowed IPs
		for _, ip := range cfg.Firewall.AllowSSHFrom {
			if !strings.Contains(rulesText, fmt.Sprintf("ip saddr %s tcp dport 22", ip)) {
				drift = append(drift, fmt.Sprintf("SSH access from %s not found in deployed rules", ip))
			}
		}

		// Check proxy allowed sources/ports
		for _, rule := range cfg.Firewall.AllowProxyFrom {
			for _, source := range rule.Sources {
				if len(rule.Ports) == 0 {
					// Allow all ports
					if !strings.Contains(rulesText, fmt.Sprintf("ip saddr %s accept", source)) {
						drift = append(drift, fmt.Sprintf("Proxy access from %s (all ports) not found in deployed rules", source))
					}
				} else {
					// Specific ports
					for _, port := range rule.Ports {
						if !strings.Contains(rulesText, fmt.Sprintf("ip saddr %s tcp dport %d", source, port)) {
							drift = append(drift, fmt.Sprintf("Proxy access from %s port %d not found in deployed rules", source, port))
						}
					}
				}
			}
		}

		// Check input policy
		switch cfg.Firewall.InputPolicy {
		case "drop":
			if !strings.Contains(rulesText, "drop") {
				drift = append(drift, "Input policy 'drop' not found in deployed rules")
			}
		case "block":
			if !strings.Contains(rulesText, "reject") {
				drift = append(drift, "Input policy 'block' (reject) not found in deployed rules")
			}
		}

	case firewall.TypeIPTables:
		// Read deployed iptables rules
		cmd := exec.Command("iptables", "-L", "PROXYCTL_INPUT", "-n")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check SSH allowed IPs
		for _, ip := range cfg.Firewall.AllowSSHFrom {
			// Normalize IP: iptables displays single IPs without /32 suffix
			normalizedIP := strings.TrimSuffix(ip, "/32")
			if !strings.Contains(rulesText, normalizedIP) || !strings.Contains(rulesText, "dpt:22") {
				drift = append(drift, fmt.Sprintf("SSH access from %s may not be deployed correctly", ip))
			}
		}

		// Check input policy
		switch cfg.Firewall.InputPolicy {
		case "drop":
			if !strings.Contains(rulesText, "DROP") {
				drift = append(drift, "Input policy 'drop' not found in deployed rules")
			}
		case "block":
			if !strings.Contains(rulesText, "REJECT") {
				drift = append(drift, "Input policy 'block' (REJECT) not found in deployed rules")
			}
		}
	}

	return drift
}

// checkFirewallOutputDrift detects configuration drift for OUTPUT redirect
func checkFirewallOutputDrift(fwMgr *firewall.Manager, cfg *config.Config) []string {
	if cfg.Redirect == nil || !cfg.Redirect.Enabled {
		return nil // No redirect configured
	}

	var drift []string

	switch fwMgr.Type {
	case firewall.TypeNFTables:
		// Read deployed nftables rules
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_redirect")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check redirect type
		switch cfg.Redirect.Type {
		case "partial":
			// Check that specific targets are present
			for _, target := range cfg.Redirect.Targets {
				if !strings.Contains(rulesText, fmt.Sprintf("ip daddr %s", target)) {
					drift = append(drift, fmt.Sprintf("Redirect target %s not found in deployed rules", target))
				}
			}
		case "full":
			// Check for full redirect (should have dnat without specific IP daddr)
			if !strings.Contains(rulesText, "dnat to") {
				drift = append(drift, "Full redirect not found in deployed rules")
			}
		}

	case firewall.TypeIPTables:
		// Read deployed iptables rules
		cmd := exec.Command("iptables", "-t", "nat", "-L", "PROXYCTL_OUTPUT", "-n")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil // Can't check drift if rules don't exist
		}

		rulesText := string(output)

		// Check redirect type
		switch cfg.Redirect.Type {
		case "partial":
			// Check that specific targets are present
			for _, target := range cfg.Redirect.Targets {
				if !strings.Contains(rulesText, target) {
					drift = append(drift, fmt.Sprintf("Redirect target %s not found in deployed rules", target))
				}
			}
		case "full":
			// Check for DNAT rules
			if !strings.Contains(rulesText, "DNAT") {
				drift = append(drift, "Full redirect (DNAT) not found in deployed rules")
			}
		}
	}

	return drift
}

// checkGatewayRoutingDrift detects configuration drift for gateway routing
func checkGatewayRoutingDrift(fwMgr *firewall.Manager, cfg *config.Config) []string {
	if cfg.Redirect == nil || !cfg.Redirect.Enabled || cfg.Redirect.Type != "gateway" {
		return nil // Not gateway routing
	}

	var drift []string
	tableID := cfg.Redirect.RoutingTable
	if tableID == 0 {
		tableID = 200 // Default
	}

	switch fwMgr.Type {
	case firewall.TypeNFTables:
		// Check proxyctl_gateway table exists
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_gateway")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return []string{"Gateway routing not deployed (nftables table missing)"}
		}

		rulesText := string(output)

		// Check targets are marked
		for _, target := range cfg.Redirect.Targets {
			if !strings.Contains(rulesText, fmt.Sprintf("ip daddr %s", target)) {
				drift = append(drift, fmt.Sprintf("Target %s not found in packet marking rules", target))
			}
			if !strings.Contains(rulesText, fmt.Sprintf("mark set %d", tableID)) {
				drift = append(drift, fmt.Sprintf("fwmark %d not set in rules", tableID))
			}
		}

	case firewall.TypeIPTables:
		// Check PROXYCTL_GATEWAY chain exists
		cmd := exec.Command("iptables", "-t", "mangle", "-L", "PROXYCTL_GATEWAY", "-n")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return []string{"Gateway routing not deployed (iptables chain missing)"}
		}

		rulesText := string(output)

		// Check targets are marked
		for _, target := range cfg.Redirect.Targets {
			if !strings.Contains(rulesText, target) {
				drift = append(drift, fmt.Sprintf("Target %s not found in packet marking rules", target))
			}
		}
	}

	// Check policy routing rule exists
	cmd := exec.Command("ip", "rule", "list")
	output, err := cmd.Output()
	if err == nil {
		rulesText := string(output)
		if !strings.Contains(rulesText, fmt.Sprintf("fwmark 0x%x", tableID)) && !strings.Contains(rulesText, fmt.Sprintf("fwmark %d", tableID)) {
			drift = append(drift, fmt.Sprintf("Policy routing rule for fwmark %d not found", tableID))
		}
	}

	// Check gateway route exists
	cmd = exec.Command("ip", "route", "show", "table", "egress")
	output, err = cmd.Output()
	if err == nil {
		routeText := string(output)
		if !strings.Contains(routeText, cfg.Redirect.Gateway) {
			drift = append(drift, fmt.Sprintf("Gateway route via %s not found in routing table", cfg.Redirect.Gateway))
		}
	} else {
		drift = append(drift, "Routing table 'egress' not found")
	}

	// Check systemd service
	cmd = exec.Command("systemctl", "is-active", "proxyctl-routing.service")
	if err := cmd.Run(); err != nil {
		drift = append(drift, "Systemd service proxyctl-routing.service not active")
	}

	return drift
}
