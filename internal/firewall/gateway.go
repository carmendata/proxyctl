package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// ApplyGatewayRouting configures policy routing through a gateway
// This implements gateway-based routing as an alternative to DNAT redirect
func (m *Manager) ApplyGatewayRouting(cfg *config.RedirectConfig) error {
	if cfg.Type != "gateway" {
		return fmt.Errorf("redirect type must be 'gateway', got: %s", cfg.Type)
	}

	// Default routing table to 200 if not specified
	tableID := cfg.RoutingTable
	if tableID == 0 {
		tableID = 200
	}

	// Determine table name from config (use "egress" as default)
	tableName := "egress"

	// Step 1: Create routing table entry
	if err := m.createRoutingTable(tableID, tableName); err != nil {
		return fmt.Errorf("failed to create routing table: %w", err)
	}

	// Step 2: Create packet marking rules (nftables/iptables mangle)
	if err := m.createPacketMarking(cfg, tableID); err != nil {
		return fmt.Errorf("failed to create packet marking rules: %w", err)
	}

	// Step 3: Add gateway route to routing table
	if err := m.addGatewayRoute(cfg, tableID, tableName); err != nil {
		return fmt.Errorf("failed to add gateway route: %w", err)
	}

	// Step 4: Add policy routing rule (fwmark -> table)
	if err := m.addPolicyRoutingRule(tableID, tableName); err != nil {
		return fmt.Errorf("failed to add policy routing rule: %w", err)
	}

	// Step 5: Make persistent (systemd service)
	if err := m.makeRoutingPersistent(cfg, tableID, tableName); err != nil {
		return fmt.Errorf("failed to make routing persistent: %w", err)
	}

	return nil
}

// RemoveGatewayRouting removes policy routing configuration
func (m *Manager) RemoveGatewayRouting() error {
	// Default table ID and name
	tableID := 200
	tableName := "egress"

	// Remove packet marking rules
	if err := m.removePacketMarking(); err != nil {
		fmt.Printf("Warning: failed to remove packet marking rules: %v\n", err)
	}

	// Remove policy routing rule
	if err := m.removePolicyRoutingRule(tableID); err != nil {
		fmt.Printf("Warning: failed to remove policy routing rule: %v\n", err)
	}

	// Remove gateway route
	if err := m.removeGatewayRoute(tableName); err != nil {
		fmt.Printf("Warning: failed to remove gateway route: %v\n", err)
	}

	// Remove systemd service
	if err := m.removeRoutingService(); err != nil {
		fmt.Printf("Warning: failed to remove routing service: %v\n", err)
	}

	// Remove routing table entry
	if err := m.removeRoutingTable(tableName); err != nil {
		fmt.Printf("Warning: failed to remove routing table entry: %v\n", err)
	}

	return nil
}

// createRoutingTable adds an entry to /etc/iproute2/rt_tables
func (m *Manager) createRoutingTable(tableID int, tableName string) error {
	rtTablesFile := "/etc/iproute2/rt_tables"
	rtTablesDir := "/etc/iproute2"

	// Ensure directory exists
	if err := os.MkdirAll(rtTablesDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", rtTablesDir, err)
	}

	// Read current content, create file with defaults if it doesn't exist
	content, err := os.ReadFile(rtTablesFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Create file with default routing tables
			defaultContent := `#
# reserved values
#
255	local
254	main
253	default
0	unspec
#
# local
#
`
			content = []byte(defaultContent)
			if err := os.WriteFile(rtTablesFile, content, 0644); err != nil {
				return fmt.Errorf("failed to create %s: %w", rtTablesFile, err)
			}
		} else {
			return fmt.Errorf("failed to read %s: %w", rtTablesFile, err)
		}
	}

	// Check if entry already exists
	entryLine := fmt.Sprintf("%d %s", tableID, tableName)
	if strings.Contains(string(content), entryLine) {
		return nil // Already exists
	}

	// Append entry
	f, err := os.OpenFile(rtTablesFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", rtTablesFile, err)
	}
	defer f.Close()

	if _, err := f.WriteString(fmt.Sprintf("%s\n", entryLine)); err != nil {
		return fmt.Errorf("failed to write to %s: %w", rtTablesFile, err)
	}

	return nil
}

// removeRoutingTable removes an entry from /etc/iproute2/rt_tables
func (m *Manager) removeRoutingTable(tableName string) error {
	rtTablesFile := "/etc/iproute2/rt_tables"

	content, err := os.ReadFile(rtTablesFile)
	if err != nil {
		return nil // File doesn't exist - nothing to do
	}

	// Filter out lines containing the table name
	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, line := range lines {
		// Skip lines that match our table
		if !strings.Contains(line, " "+tableName) && !strings.HasSuffix(line, tableName) {
			newLines = append(newLines, line)
		}
	}

	// Write back
	newContent := strings.Join(newLines, "\n")
	return os.WriteFile(rtTablesFile, []byte(newContent), 0644)
}

// createPacketMarking creates packet marking rules for gateway routing
func (m *Manager) createPacketMarking(cfg *config.RedirectConfig, tableID int) error {
	switch m.Type {
	case TypeNFTables:
		return m.createNFTablesPacketMarking(cfg, tableID)
	case TypeIPTables:
		return m.createIPTablesPacketMarking(cfg, tableID)
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// removePacketMarking removes packet marking rules
func (m *Manager) removePacketMarking() error {
	switch m.Type {
	case TypeNFTables:
		return m.removeNFTablesPacketMarking()
	case TypeIPTables:
		return m.removeIPTablesPacketMarking()
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// createNFTablesPacketMarking creates nftables packet marking rules
func (m *Manager) createNFTablesPacketMarking(cfg *config.RedirectConfig, tableID int) error {
	var nftConfig strings.Builder

	nftConfig.WriteString("#!/usr/sbin/nft -f\n")
	nftConfig.WriteString("# proxyctl Gateway Routing - Packet Marking\n")
	nftConfig.WriteString(fmt.Sprintf("# Generated: proxyctl v%s\n", "0.11.0"))
	nftConfig.WriteString(fmt.Sprintf("# Gateway: %s\n", cfg.Gateway))
	nftConfig.WriteString(fmt.Sprintf("# Routing Table: %d\n\n", tableID))

	nftConfig.WriteString("table ip proxyctl_gateway {\n")
	nftConfig.WriteString("    # OUTPUT chain - Mark packets for gateway routing\n")
	nftConfig.WriteString("    # Priority -150 (mangle) runs before routing decision\n")
	nftConfig.WriteString("    chain output {\n")
	nftConfig.WriteString("        type route hook output priority -150; policy accept;\n\n")

	// Add mark rules for each target IP
	for i, target := range cfg.Targets {
		nftConfig.WriteString(fmt.Sprintf("        # Target %d: %s\n", i+1, target))
		nftConfig.WriteString(fmt.Sprintf("        ip daddr %s mark set %d comment \"Route via gateway\"\n", target, tableID))
	}

	nftConfig.WriteString("    }\n")
	nftConfig.WriteString("}\n")

	// Write to file
	gatewayFile := "/etc/nftables.d/proxyctl-gateway.nft"
	if err := os.MkdirAll("/etc/nftables.d", 0755); err != nil {
		return fmt.Errorf("failed to create nftables.d directory: %w", err)
	}

	if err := os.WriteFile(gatewayFile, []byte(nftConfig.String()), 0644); err != nil {
		return fmt.Errorf("failed to write nftables config: %w", err)
	}

	// Add include to main config if not present
	if err := m.addNFTablesInclude(gatewayFile); err != nil {
		return err
	}

	// Apply the rules
	cmd := exec.Command("nft", "-f", gatewayFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// removeNFTablesPacketMarking removes nftables packet marking rules
func (m *Manager) removeNFTablesPacketMarking() error {
	// Delete table
	exec.Command("nft", "delete", "table", "ip", "proxyctl_gateway").Run() // Ignore error if doesn't exist

	// Remove configuration file
	os.Remove("/etc/nftables.d/proxyctl-gateway.nft")

	// Remove include from main config
	m.removeNFTablesInclude("/etc/nftables.d/proxyctl-gateway.nft")

	return nil
}

// createIPTablesPacketMarking creates iptables packet marking rules in mangle table
func (m *Manager) createIPTablesPacketMarking(cfg *config.RedirectConfig, tableID int) error {
	chainName := "PROXYCTL_GATEWAY"

	// Create custom chain in mangle table
	exec.Command("iptables", "-t", "mangle", "-N", chainName).Run() // Ignore error if exists

	// Flush existing rules
	if err := exec.Command("iptables", "-t", "mangle", "-F", chainName).Run(); err != nil {
		return fmt.Errorf("failed to flush chain %s: %w", chainName, err)
	}

	// Add mark rules for each target IP
	for i, target := range cfg.Targets {
		comment := fmt.Sprintf("Gateway routing target %d", i+1)
		cmd := exec.Command("iptables", "-t", "mangle", "-A", chainName,
			"-d", target,
			"-j", "MARK", "--set-mark", strconv.Itoa(tableID),
			"-m", "comment", "--comment", comment)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add mark rule: %w", err)
		}
	}

	// Remove existing jump to chain and add at top of OUTPUT
	exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-j", chainName).Run() // Ignore error
	if err := exec.Command("iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-j", chainName).Run(); err != nil {
		return fmt.Errorf("failed to insert jump to %s: %w", chainName, err)
	}

	// Save rules
	return m.saveIPTables()
}

// removeIPTablesPacketMarking removes iptables packet marking rules
func (m *Manager) removeIPTablesPacketMarking() error {
	chainName := "PROXYCTL_GATEWAY"

	// Remove jump to chain
	exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-j", chainName).Run()

	// Flush and delete chain
	exec.Command("iptables", "-t", "mangle", "-F", chainName).Run()
	exec.Command("iptables", "-t", "mangle", "-X", chainName).Run()

	// Save rules
	return m.saveIPTables()
}

// addGatewayRoute adds a default route via gateway to the routing table
func (m *Manager) addGatewayRoute(cfg *config.RedirectConfig, tableID int, tableName string) error {
	// Detect primary network interface
	iface, err := m.detectPrimaryInterface()
	if err != nil {
		return fmt.Errorf("failed to detect primary interface: %w", err)
	}

	// Try to add the route
	// Use 'onlink' flag to support gateways not on the same subnet (e.g., public IPs)
	cmd := exec.Command("ip", "route", "add", "default",
		"via", cfg.Gateway,
		"dev", iface,
		"onlink",
		"table", tableName)

	if err := cmd.Run(); err != nil {
		// If error, try replace instead (route might already exist)
		cmd = exec.Command("ip", "route", "replace", "default",
			"via", cfg.Gateway,
			"dev", iface,
			"onlink",
			"table", tableName)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add/replace gateway route (ip route replace default via %s dev %s onlink table %s): %w - Output: %s",
				cfg.Gateway, iface, tableName, err, string(output))
		}
	}

	return nil
}

// removeGatewayRoute removes the gateway route from the routing table
func (m *Manager) removeGatewayRoute(tableName string) error {
	cmd := exec.Command("ip", "route", "del", "default", "table", tableName)
	cmd.Run() // Ignore errors - route might not exist
	return nil
}

// addPolicyRoutingRule adds a policy routing rule (fwmark -> table)
func (m *Manager) addPolicyRoutingRule(tableID int, tableName string) error {
	// Try to add the rule
	cmd := exec.Command("ip", "rule", "add",
		"fwmark", strconv.Itoa(tableID),
		"table", tableName,
		"priority", "100")

	if err := cmd.Run(); err != nil {
		// Rule might already exist - that's okay
		return nil
	}

	return nil
}

// removePolicyRoutingRule removes the policy routing rule
func (m *Manager) removePolicyRoutingRule(tableID int) error {
	cmd := exec.Command("ip", "rule", "del",
		"fwmark", strconv.Itoa(tableID),
		"priority", "100")
	cmd.Run() // Ignore errors - rule might not exist
	return nil
}

// detectPrimaryInterface detects the primary network interface
func (m *Manager) detectPrimaryInterface() (string, error) {
	// Get default route
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse output to find interface
	// Expected format: "default via 10.106.0.1 dev eth1 ..."
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not detect primary interface from default route")
}

// makeRoutingPersistent creates a systemd service for routing persistence
func (m *Manager) makeRoutingPersistent(cfg *config.RedirectConfig, tableID int, tableName string) error {
	iface, err := m.detectPrimaryInterface()
	if err != nil {
		return fmt.Errorf("failed to detect primary interface: %w", err)
	}

	serviceContent := fmt.Sprintf(`[Unit]
Description=proxyctl Gateway Routing
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Setup routing
ExecStart=/bin/bash -c 'ip route add default via %s dev %s onlink table %s 2>/dev/null || ip route replace default via %s dev %s onlink table %s'
ExecStart=/bin/bash -c 'ip rule add fwmark %d table %s priority 100 2>/dev/null || true'

# Cleanup on stop
ExecStop=/bin/bash -c 'ip rule del fwmark %d table %s 2>/dev/null || true'
ExecStop=/bin/bash -c 'ip route del default table %s 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
`, cfg.Gateway, iface, tableName, cfg.Gateway, iface, tableName, tableID, tableName, tableID, tableName, tableName)

	// Write service file
	serviceFile := "/etc/systemd/system/proxyctl-routing.service"
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable and start service
	if err := exec.Command("systemctl", "enable", "proxyctl-routing.service").Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	if err := exec.Command("systemctl", "start", "proxyctl-routing.service").Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// removeRoutingService removes the systemd routing service
func (m *Manager) removeRoutingService() error {
	serviceName := "proxyctl-routing.service"

	// Stop service
	exec.Command("systemctl", "stop", serviceName).Run()

	// Disable service
	exec.Command("systemctl", "disable", serviceName).Run()

	// Remove service file
	os.Remove("/etc/systemd/system/" + serviceName)

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	return nil
}

// IsGatewayRoutingDeployed checks if gateway routing is currently deployed
func (m *Manager) IsGatewayRoutingDeployed() (bool, error) {
	// Check if proxyctl_gateway table exists (nftables) or PROXYCTL_GATEWAY chain (iptables)
	switch m.Type {
	case TypeNFTables:
		cmd := exec.Command("nft", "list", "table", "ip", "proxyctl_gateway")
		err := cmd.Run()
		return err == nil, nil

	case TypeIPTables:
		cmd := exec.Command("iptables", "-t", "mangle", "-L", "PROXYCTL_GATEWAY", "-n")
		err := cmd.Run()
		return err == nil, nil

	default:
		return false, fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}
