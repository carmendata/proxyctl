package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/carmendata/proxyctl/internal/acl"
	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
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

	if cfg.Proxy == nil || cfg.Proxy.ACL == nil || !cfg.Proxy.ACL.Enabled {
		fmt.Println("  Status: Not configured")
		return
	}

	aclPath := cfg.Proxy.ACL.FilePath
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

	// Check if logger rules exist
	installed, err := checkLoggerInstalled(fwMgr)
	if err != nil {
		fmt.Printf("  Status: ❌ Error checking (%v)\n", err)
		return
	}

	if !installed {
		fmt.Println("  Status: Not installed")
		return
	}

	fmt.Println("  Status: ✓ Installed")

	// Show log directory and current log file
	logDir := "/var/log/proxyctl"
	fmt.Printf("  Log directory: %s\n", logDir)

	// Check current log file
	logFile := fmt.Sprintf("%s/egress.log", logDir)
	if info, err := os.Stat(logFile); err == nil {
		size := float64(info.Size()) / 1024 / 1024 // Convert to MB
		fmt.Printf("  Current log: egress.log (%.1f MB)\n", size)
	}
}

// showFirewallStatusSummary displays a summary of firewall status
func showFirewallStatusSummary() {
	fmt.Println("Firewall:")

	// Detect firewall type (don't try to install)
	fwType, err := firewall.Detect()
	if err != nil {
		fmt.Println("  Status: Not configured (no firewall detected)")
		return
	}

	fwMgr := &firewall.Manager{Type: fwType}
	fmt.Printf("  Type: %s\n", fwType)

	// Check if INPUT filtering is applied
	inputApplied, err := checkInputFilteringApplied(fwMgr)
	if err != nil {
		fmt.Printf("  INPUT filtering: ❌ Error checking (%v)\n", err)
	} else if inputApplied {
		fmt.Println("  INPUT filtering: ✓ Applied")
	} else {
		fmt.Println("  INPUT filtering: Not configured")
	}

	// Check if OUTPUT redirect is applied
	outputApplied, err := checkOutputRedirectApplied(fwMgr)
	if err != nil {
		fmt.Printf("  OUTPUT redirect: ❌ Error checking (%v)\n", err)
	} else if outputApplied {
		fmt.Println("  OUTPUT redirect: ✓ Applied")
	} else {
		fmt.Println("  OUTPUT redirect: Not configured")
	}

	// Show number of backups
	backups, err := fwMgr.ListBackups()
	if err == nil && len(backups) > 0 {
		fmt.Printf("  Backups: %d available\n", len(backups))
	}

	fmt.Println()
	fmt.Printf("  ℹ️  For detailed firewall status, run: %s firewall status\n", os.Args[0])
}

// checkLoggerInstalled checks if logger firewall rules are installed
func checkLoggerInstalled(fwMgr *firewall.Manager) (bool, error) {
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		// Check if PROXYCTL_LOG chain exists
		cmd := exec.Command("iptables", "-t", "nat", "-L", "PROXYCTL_LOG", "-n")
		if err := cmd.Run(); err != nil {
			return false, nil // Chain doesn't exist
		}
		return true, nil

	case firewall.TypeNFTables:
		// Check if proxyctl_logger table exists
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_logger")
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
