package routing

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/firewall"
)

// Manager handles IP forwarding and MASQUERADE configuration
type Manager struct {
	fwType    firewall.Type
	Interface string // Physical interface name for MASQUERADE
}

// NewManager creates a new routing manager
func NewManager() (*Manager, error) {
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to detect firewall: %w", err)
	}

	return &Manager{
		fwType: fwMgr.Type,
	}, nil
}

// EnableIPForward enables IP forwarding via sysctl
func (m *Manager) EnableIPForward() error {
	// Set sysctl value
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w (output: %s)", err, string(output))
	}

	// Make it persistent across reboots
	if err := m.persistIPForward(true); err != nil {
		return fmt.Errorf("failed to persist IP forwarding: %w", err)
	}

	return nil
}

// DisableIPForward disables IP forwarding via sysctl
func (m *Manager) DisableIPForward() error {
	// Set sysctl value
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to disable IP forwarding: %w (output: %s)", err, string(output))
	}

	// Make it persistent across reboots
	if err := m.persistIPForward(false); err != nil {
		return fmt.Errorf("failed to persist IP forwarding: %w", err)
	}

	return nil
}

// persistIPForward makes IP forwarding persistent across reboots
func (m *Manager) persistIPForward(enable bool) error {
	sysctlConf := "/etc/sysctl.conf"
	setting := "net.ipv4.ip_forward = 1"

	// Read current config
	data, err := os.ReadFile(sysctlConf)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", sysctlConf, err)
	}

	lines := strings.Split(string(data), "\n")
	newLines := []string{}
	found := false

	// Remove any existing ip_forward settings
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "net.ipv4.ip_forward") {
			continue // Skip existing settings
		}
		newLines = append(newLines, line)
	}

	// Add new setting if enabling
	if enable {
		newLines = append(newLines, setting)
		found = true
	}

	// Write back
	content := strings.Join(newLines, "\n")
	if err := os.WriteFile(sysctlConf, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", sysctlConf, err)
	}

	if enable && !found {
		return fmt.Errorf("failed to add IP forwarding setting to %s", sysctlConf)
	}

	return nil
}

// EnableMasquerade enables MASQUERADE on the specified interface
func (m *Manager) EnableMasquerade(iface string) error {
	m.Interface = iface

	switch m.fwType {
	case firewall.TypeIPTables:
		return m.enableMasqueradeIPTables()
	case firewall.TypeNFTables:
		return m.enableMasqueradeNFTables()
	default:
		return fmt.Errorf("unsupported firewall type: %s", m.fwType)
	}
}

// DisableMasquerade disables MASQUERADE
func (m *Manager) DisableMasquerade() error {
	switch m.fwType {
	case firewall.TypeIPTables:
		return m.disableMasqueradeIPTables()
	case firewall.TypeNFTables:
		return m.disableMasqueradeNFTables()
	default:
		return fmt.Errorf("unsupported firewall type: %s", m.fwType)
	}
}

// enableMasqueradeIPTables enables MASQUERADE using iptables
func (m *Manager) enableMasqueradeIPTables() error {
	// Check if rule already exists
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-o", m.Interface, "-j", "MASQUERADE")
	if err := checkCmd.Run(); err == nil {
		// Rule already exists
		return nil
	}

	// Add MASQUERADE rule
	cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-o", m.Interface, "-j", "MASQUERADE")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add MASQUERADE rule: %w (output: %s)", err, string(output))
	}

	// Make persistent
	if err := m.saveIPTablesRules(); err != nil {
		return fmt.Errorf("failed to persist MASQUERADE rule: %w", err)
	}

	return nil
}

// disableMasqueradeIPTables disables MASQUERADE using iptables
func (m *Manager) disableMasqueradeIPTables() error {
	if m.Interface == "" {
		// Try to remove all MASQUERADE rules
		cmd := exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to flush POSTROUTING chain: %w (output: %s)", err, string(output))
		}
	} else {
		// Remove specific rule
		cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-o", m.Interface, "-j", "MASQUERADE")
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Rule might not exist, which is OK
			return nil
		}
		_ = output
	}

	// Make persistent
	if err := m.saveIPTablesRules(); err != nil {
		return fmt.Errorf("failed to persist changes: %w", err)
	}

	return nil
}

// saveIPTablesRules persists iptables rules
func (m *Manager) saveIPTablesRules() error {
	// Try iptables-save with different tools
	tools := []string{"netfilter-persistent", "iptables-save"}

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}

		var cmd *exec.Cmd
		if tool == "netfilter-persistent" {
			cmd = exec.Command("netfilter-persistent", "save")
		} else {
			// iptables-save - write to file
			saveCmd := exec.Command("iptables-save")
			output, err := saveCmd.CombinedOutput()
			if err != nil {
				continue
			}

			// Write to /etc/iptables/rules.v4 or /etc/sysconfig/iptables
			paths := []string{"/etc/iptables/rules.v4", "/etc/sysconfig/iptables"}
			for _, path := range paths {
				dir := strings.TrimSuffix(path, "/"+strings.Split(path, "/")[len(strings.Split(path, "/"))-1])
				if err := os.MkdirAll(dir, 0755); err != nil {
					continue
				}
				if err := os.WriteFile(path, output, 0644); err != nil {
					continue
				}
				return nil
			}
			continue
		}

		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// If no persistence method found, that's OK - rules will be lost on reboot
	// but the config will re-apply them
	return nil
}

// enableMasqueradeNFTables enables MASQUERADE using nftables
func (m *Manager) enableMasqueradeNFTables() error {
	// Create nftables configuration for NAT
	nftConfig := fmt.Sprintf(`#!/usr/sbin/nft -f

# MASQUERADE configuration for routing
table ip proxyctl_nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oifname "%s" masquerade
	}
}
`, m.Interface)

	// Write to /etc/nftables.d/proxyctl_nat.conf
	confDir := "/etc/nftables.d"
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", confDir, err)
	}

	confFile := confDir + "/proxyctl_nat.conf"
	if err := os.WriteFile(confFile, []byte(nftConfig), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", confFile, err)
	}

	// Load the configuration
	cmd := exec.Command("nft", "-f", confFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load nftables NAT config: %w (output: %s)", err, string(output))
	}

	// Ensure it's included in main nftables.conf
	if err := m.ensureNFTablesInclude(); err != nil {
		return fmt.Errorf("failed to ensure nftables include: %w", err)
	}

	return nil
}

// disableMasqueradeNFTables disables MASQUERADE using nftables
func (m *Manager) disableMasqueradeNFTables() error {
	// Delete the table
	cmd := exec.Command("nft", "delete", "table", "ip", "proxyctl_nat")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Table might not exist, which is OK
		_ = output
	}

	// Remove config file
	confFile := "/etc/nftables.d/proxyctl_nat.conf"
	if err := os.Remove(confFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove %s: %w", confFile, err)
	}

	return nil
}

// ensureNFTablesInclude ensures /etc/nftables.d is included in main config
func (m *Manager) ensureNFTablesInclude() error {
	mainConf := "/etc/nftables.conf"
	includeLine := `include "/etc/nftables.d/*.conf"`

	// Read main config
	data, err := os.ReadFile(mainConf)
	if err != nil {
		if os.IsNotExist(err) {
			// Create basic nftables.conf
			baseConfig := `#!/usr/sbin/nft -f

flush ruleset

` + includeLine + "\n"
			return os.WriteFile(mainConf, []byte(baseConfig), 0755)
		}
		return fmt.Errorf("failed to read %s: %w", mainConf, err)
	}

	// Check if include already exists
	if strings.Contains(string(data), includeLine) {
		return nil
	}

	// Add include line
	lines := strings.Split(string(data), "\n")
	newLines := []string{}

	// Add after flush ruleset or at beginning
	added := false
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.Contains(line, "flush ruleset") && !added {
			newLines = append(newLines, "")
			newLines = append(newLines, includeLine)
			added = true
		}
	}

	// If not added after flush ruleset, add at end
	if !added {
		newLines = append(newLines, "")
		newLines = append(newLines, includeLine)
	}

	content := strings.Join(newLines, "\n")
	return os.WriteFile(mainConf, []byte(content), 0755)
}

// GetIPForwardStatus returns the current IP forwarding status
func (m *Manager) GetIPForwardStatus() (bool, error) {
	cmd := exec.Command("sysctl", "-n", "net.ipv4.ip_forward")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to get IP forwarding status: %w", err)
	}

	return strings.TrimSpace(string(output)) == "1", nil
}

// GetMasqueradeStatus checks if MASQUERADE is enabled
func (m *Manager) GetMasqueradeStatus() (bool, error) {
	switch m.fwType {
	case firewall.TypeIPTables:
		return m.getMasqueradeStatusIPTables()
	case firewall.TypeNFTables:
		return m.getMasqueradeStatusNFTables()
	default:
		return false, fmt.Errorf("unsupported firewall type: %s", m.fwType)
	}
}

// getMasqueradeStatusIPTables checks MASQUERADE status with iptables
func (m *Manager) getMasqueradeStatusIPTables() (bool, error) {
	cmd := exec.Command("iptables", "-t", "nat", "-L", "POSTROUTING", "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to list POSTROUTING rules: %w", err)
	}

	return strings.Contains(string(output), "MASQUERADE"), nil
}

// getMasqueradeStatusNFTables checks MASQUERADE status with nftables
func (m *Manager) getMasqueradeStatusNFTables() (bool, error) {
	cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_nat")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Table doesn't exist
		return false, nil
	}

	return strings.Contains(string(output), "masquerade"), nil
}
