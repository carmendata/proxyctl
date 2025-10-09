package logger

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/firewall"
)

const (
	LogPrefix        = "EGRESS_MONITOR"
	LogFile          = "/var/log/proxyctl/egress.log"
	LogDir           = "/var/log/proxyctl"
	RsyslogConf      = "/etc/rsyslog.d/99-egress-monitor.conf"
	LogrotateConf    = "/etc/logrotate.d/egress-monitor"
	NFTablesConf     = "/etc/nftables.d/egress-monitor.nft"
	NFTablesMainConf = "/etc/nftables.conf"
)

// Manager handles connection logger operations
type Manager struct {
	LogFile       string
	RsyslogConf   string
	LogrotateConf string
}

// NewManager creates a new logger manager
func NewManager() *Manager {
	return &Manager{
		LogFile:       LogFile,
		RsyslogConf:   RsyslogConf,
		LogrotateConf: LogrotateConf,
	}
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
	// Remove jump to EGRESS_LOG chain
	exec.Command("iptables", "-D", "OUTPUT", "-j", "EGRESS_LOG").Run()

	// Flush and delete EGRESS_LOG chain
	exec.Command("iptables", "-F", "EGRESS_LOG").Run()
	exec.Command("iptables", "-X", "EGRESS_LOG").Run()

	// Remove systemd service if it exists
	m.removeIPTablesSystemdService()

	return nil
}

// removeRsyslogConfig removes rsyslog configuration
func (m *Manager) removeRsyslogConfig() error {
	if _, err := os.Stat(m.RsyslogConf); err == nil {
		if err := os.Remove(m.RsyslogConf); err != nil {
			return fmt.Errorf("failed to remove rsyslog config: %w", err)
		}

		// Restart rsyslog
		cmd := exec.Command("systemctl", "restart", "rsyslog")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to restart rsyslog: %w", err)
		}
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

	// Check if already installed
	if err := m.checkNotInstalled(fwMgr.Type); err != nil {
		return err
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

	// Private IP ranges to exclude
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	// Skip private IP ranges
	for _, ipRange := range privateRanges {
		cmd := exec.Command("iptables", "-A", "EGRESS_LOG", "-d", ipRange, "-j", "RETURN")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add private range exclusion: %w", err)
		}
	}

	// Log all new outbound TCP connections to public IPs
	cmd = exec.Command("iptables", "-A", "EGRESS_LOG",
		"-p", "tcp",
		"-m", "state", "--state", "NEW",
		"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add TCP logging rule: %w", err)
	}

	// Log all new outbound UDP connections to public IPs
	cmd = exec.Command("iptables", "-A", "EGRESS_LOG",
		"-p", "udp",
		"-m", "state", "--state", "NEW",
		"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "6")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add UDP logging rule: %w", err)
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

// configureRsyslog configures rsyslog
func (m *Manager) configureRsyslog() error {
	content := fmt.Sprintf(`# Egress Connection Monitoring
# Separate kernel logs with %s prefix to dedicated log file

:msg, contains, "%s" %s
& stop
`, LogPrefix, LogPrefix, m.LogFile)

	if err := os.WriteFile(m.RsyslogConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write rsyslog config: %w", err)
	}

	// Restart rsyslog
	cmd := exec.Command("systemctl", "restart", "rsyslog")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart rsyslog: %w", err)
	}

	return nil
}

// configureLogrotate configures logrotate
func (m *Manager) configureLogrotate() error {
	content := fmt.Sprintf(`%s {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl restart rsyslog > /dev/null 2>&1 || true
    endscript
}
`, m.LogFile)

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
		if containsString(string(output), LogPrefix) {
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
	// Private IP ranges to exclude
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	// Build nftables config
	var config strings.Builder
	config.WriteString("# Egress Connection Monitoring\n")
	config.WriteString("# Logs NEW TCP and UDP connections to public IPs (all ports)\n")
	config.WriteString("# Generated by proxyctl - do not edit manually\n\n")
	config.WriteString("table ip egress_monitor {\n")
	config.WriteString("    chain output {\n")
	config.WriteString("        type filter hook output priority -1; policy accept;\n\n")
	config.WriteString("        # Skip private IP ranges\n")

	for _, ipRange := range privateRanges {
		config.WriteString(fmt.Sprintf("        ip daddr %s return\n", ipRange))
	}

	config.WriteString("\n        # Log all NEW TCP connections to public IPs\n")
	config.WriteString(fmt.Sprintf("        meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new log prefix \"%s: \" level info\n", LogPrefix))

	config.WriteString("\n        # Log all NEW UDP connections to public IPs\n")
	config.WriteString(fmt.Sprintf("        meta l4proto udp ct state new log prefix \"%s: \" level info\n", LogPrefix))

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

	// Reload nftables
	cmd := exec.Command("systemctl", "reload", "nftables")
	if err := cmd.Run(); err != nil {
		// Fallback: direct load
		cmd = exec.Command("nft", "-f", NFTablesMainConf)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to reload nftables: %w", err)
		}
	}

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
	content, err := os.ReadFile(NFTablesMainConf)
	if err != nil {
		// If file doesn't exist, create it with just the include
		return os.WriteFile(NFTablesMainConf,
			[]byte(fmt.Sprintf(`include "%s"`+"\n", NFTablesConf)), 0644)
	}

	includeLine := fmt.Sprintf(`include "%s"`, NFTablesConf)
	if strings.Contains(string(content), includeLine) {
		return nil // Already included
	}

	// Append include line
	f, err := os.OpenFile(NFTablesMainConf, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(includeLine + "\n")
	return err
}

// removeIncludeFromNFTablesConf removes include directive from main nftables config
func removeIncludeFromNFTablesConf() error {
	content, err := os.ReadFile(NFTablesMainConf)
	if err != nil {
		return nil // File doesn't exist, nothing to remove
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
		return os.WriteFile(NFTablesMainConf, []byte(strings.Join(newLines, "\n")), 0644)
	}

	return nil
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
