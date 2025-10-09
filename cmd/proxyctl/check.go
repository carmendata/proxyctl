package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
)

// CheckResult stores the results of all configuration checks
type CheckResult struct {
	Server          string
	RemoteIP        string
	RemoteHostname  string
	RemoteOS        string
	ProxyIP         string
	FirewallType    string
	RulesExist      bool
	RulesCorrect    bool
	PortsConfigured []string
	RulesPersistent bool
	ConnectivityOK  bool
	InACL           bool
	ACLStatus       string // "exact", "cidr_uncertain", "not_found"
	FullRules       string
	IssuesFound     int
}

// runServerCheck checks internal server configuration via SSH
func runServerCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("INTERNAL_SERVER_IP_OR_HOSTNAME required\n\nUsage: egressctl server check <SERVER> [SSH_USER]")
	}

	server := args[0]
	sshUser := "root"
	if len(args) > 1 {
		sshUser = args[1]
	}

	// Load config to get egress proxy IP
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Egress == nil {
		return fmt.Errorf("egress configuration not found")
	}

	proxyIP := cfg.Egress.PrivateIP
	if proxyIP == "" {
		proxyIP = cfg.Egress.PublicIP
	}
	if proxyIP == "" {
		return fmt.Errorf("egress proxy IP not configured")
	}

	proxyPort := cfg.Egress.Port
	if proxyPort == 0 {
		proxyPort = 8080
	}

	// Initialize result
	result := &CheckResult{
		Server:  server,
		ProxyIP: proxyIP,
	}

	// Print header
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ Internal Server Configuration Check                                      ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Target Server: %s\n", server)
	fmt.Printf("SSH User: %s\n", sshUser)
	fmt.Printf("Egress Proxy IP: %s\n", proxyIP)
	fmt.Println()

	// Run all checks
	if err := runAllChecks(result, server, sshUser, proxyIP, proxyPort, cfg); err != nil {
		return err
	}

	// Generate comprehensive report
	exitCode := generateCheckReport(result)

	// Exit with appropriate code (but return nil for clean error handling)
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}

// runAllChecks executes all diagnostic checks
func runAllChecks(result *CheckResult, server, sshUser, proxyIP string, proxyPort int, cfg *config.Config) error {
	// [1/7] Test SSH connectivity
	fmt.Println("[1/7] Testing SSH connectivity...")
	if err := testSSH(server, sshUser); err != nil {
		return fmt.Errorf("✗ FAILED: Cannot SSH to %s: %w", server, err)
	}
	fmt.Println("✓ SSH connectivity OK")
	fmt.Println()

	// [2/7] Get remote system info
	fmt.Println("[2/7] Gathering system information...")
	if err := getRemoteSystemInfo(result, server, sshUser); err != nil {
		return fmt.Errorf("failed to get system info: %w", err)
	}
	fmt.Printf("✓ Hostname: %s\n", result.RemoteHostname)
	fmt.Printf("✓ OS: %s\n", result.RemoteOS)
	fmt.Printf("✓ IP: %s\n", result.RemoteIP)
	fmt.Println()

	// [3/7] Detect firewall type
	fmt.Println("[3/7] Detecting firewall configuration...")
	fwType, err := detectRemoteFirewall(server, sshUser)
	if err != nil {
		return fmt.Errorf("✗ FAILED: %w", err)
	}
	result.FirewallType = fwType
	fmt.Printf("✓ Firewall detected: %s\n", fwType)
	fmt.Println()

	// [4/7] Check for egress proxy rules (detailed)
	fmt.Println("[4/7] Checking egress proxy routing rules...")
	checkDetailedRules(result, server, sshUser, proxyIP)
	fmt.Println()

	// [5/7] Check persistence
	fmt.Println("[5/7] Checking rule persistence...")
	checkRulePersistence(result, server, sshUser)
	fmt.Println()

	// [6/7] Test connectivity to proxy
	fmt.Println("[6/7] Testing connectivity to egress proxy...")
	checkProxyConnectivity(result, server, sshUser, proxyIP, proxyPort)
	fmt.Println()

	// [7/7] Check ACL membership
	fmt.Println("[7/7] Checking ACL membership...")
	checkACLMembership(result, cfg)
	fmt.Println()

	return nil
}

// getRemoteSystemInfo gathers remote server information
func getRemoteSystemInfo(result *CheckResult, server, user string) error {
	cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server),
		"uname -s && hostname && hostname -I | awk '{print $1}'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) >= 3 {
		result.RemoteOS = strings.TrimSpace(lines[0])
		result.RemoteHostname = strings.TrimSpace(lines[1])
		result.RemoteIP = strings.TrimSpace(lines[2])
	}

	return nil
}

// checkDetailedRules checks egress proxy rules in detail
func checkDetailedRules(result *CheckResult, server, user, proxyIP string) {
	expectedPorts := []string{"80", "443", "22"}
	var fullRules string

	if result.FirewallType == "iptables" {
		cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server),
			"sudo iptables -t nat -L EGRESS_PROXY -n -v 2>/dev/null")
		output, err := cmd.CombinedOutput()
		fullRules = string(output)

		if err != nil || strings.Contains(fullRules, "No chain/target/match") {
			fmt.Println("✗ EGRESS_PROXY chain not found")
			result.RulesExist = false
			result.IssuesFound++
			return
		}

		fmt.Println("✓ EGRESS_PROXY chain exists")
		result.RulesExist = true

		// Check if proxy IP is in rules
		if strings.Contains(fullRules, proxyIP) {
			fmt.Printf("✓ Rules reference egress proxy IP (%s)\n", proxyIP)
			result.RulesCorrect = true
		} else {
			fmt.Printf("✗ Rules do not reference egress proxy IP (expected: %s)\n", proxyIP)
			result.IssuesFound++
		}

		// Check each port
		for _, port := range expectedPorts {
			if strings.Contains(fullRules, "dpt:"+port) {
				fmt.Printf("✓ Port %s redirect configured\n", port)
				result.PortsConfigured = append(result.PortsConfigured, port)
			} else {
				fmt.Printf("⚠ Port %s redirect NOT configured\n", port)
				result.IssuesFound++
			}
		}

		result.FullRules = fullRules

	} else { // nftables
		cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server),
			"sudo nft list table ip egress_proxy 2>/dev/null")
		output, err := cmd.CombinedOutput()
		fullRules = string(output)

		if err != nil || len(fullRules) == 0 {
			fmt.Println("✗ egress_proxy table not found")
			result.RulesExist = false
			result.IssuesFound++
			return
		}

		fmt.Println("✓ egress_proxy table exists")
		result.RulesExist = true

		// Check if proxy IP is in rules
		if strings.Contains(fullRules, proxyIP) {
			fmt.Printf("✓ Rules reference egress proxy IP (%s)\n", proxyIP)
			result.RulesCorrect = true
		} else {
			fmt.Printf("✗ Rules do not reference egress proxy IP (expected: %s)\n", proxyIP)
			result.IssuesFound++
		}

		// Check each port
		for _, port := range expectedPorts {
			if strings.Contains(fullRules, "tcp dport "+port) {
				fmt.Printf("✓ Port %s redirect configured\n", port)
				result.PortsConfigured = append(result.PortsConfigured, port)
			} else {
				fmt.Printf("⚠ Port %s redirect NOT configured\n", port)
				result.IssuesFound++
			}
		}

		result.FullRules = fullRules
	}
}

// checkRulePersistence checks if firewall rules will persist across reboots
func checkRulePersistence(result *CheckResult, server, user string) {
	if result.FirewallType == "iptables" {
		cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server), `
if [ -f /etc/iptables/rules.v4 ] && grep -q "EGRESS_PROXY" /etc/iptables/rules.v4 2>/dev/null; then
    echo "persistent_file"
elif systemctl is-enabled netfilter-persistent &>/dev/null; then
    echo "persistent_service"
else
    echo "not_persistent"
fi`)
		output, _ := cmd.CombinedOutput()
		persistence := strings.TrimSpace(string(output))

		if persistence == "persistent_file" {
			fmt.Println("✓ Rules saved in /etc/iptables/rules.v4")
			result.RulesPersistent = true
		} else if persistence == "persistent_service" {
			fmt.Println("✓ netfilter-persistent service enabled")
			result.RulesPersistent = true
		} else {
			fmt.Println("⚠ Rules may not persist after reboot")
			result.RulesPersistent = false
			result.IssuesFound++
		}

	} else { // nftables
		cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server),
			"systemctl is-enabled nftables 2>/dev/null || echo disabled")
		output, _ := cmd.CombinedOutput()
		status := strings.TrimSpace(string(output))

		if status == "enabled" {
			fmt.Println("✓ nftables service enabled")
			result.RulesPersistent = true
		} else {
			fmt.Println("⚠ nftables service not enabled (rules may not persist)")
			result.RulesPersistent = false
			result.IssuesFound++
		}
	}
}

// checkProxyConnectivity tests network connectivity to the egress proxy
func checkProxyConnectivity(result *CheckResult, server, user, proxyIP string, proxyPort int) {
	cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server),
		fmt.Sprintf("nc -zv -w 5 %s %d 2>&1 | grep -q 'succeeded\\|open' && echo 'ok' || echo 'failed'", proxyIP, proxyPort))
	output, _ := cmd.CombinedOutput()
	status := strings.TrimSpace(string(output))

	if status == "ok" {
		fmt.Printf("✓ Can reach egress proxy at %s:%d\n", proxyIP, proxyPort)
		result.ConnectivityOK = true
	} else {
		fmt.Printf("✗ Cannot reach egress proxy at %s:%d\n", proxyIP, proxyPort)
		fmt.Println("  Possible issues: firewall blocking, network routing, proxy not running")
		result.ConnectivityOK = false
		result.IssuesFound++
	}
}

// checkACLMembership checks if the remote server IP is in the egress proxy ACL
func checkACLMembership(result *CheckResult, cfg *config.Config) {
	if cfg.Egress == nil || cfg.Egress.ACLFile == "" {
		fmt.Println("⚠ ACL file path not configured")
		return
	}

	aclFile := cfg.Egress.ACLFile
	if _, err := os.Stat(aclFile); os.IsNotExist(err) {
		fmt.Printf("⚠ ACL file not found at %s\n", aclFile)
		return
	}

	// Read ACL file
	content, err := os.ReadFile(aclFile)
	if err != nil {
		fmt.Printf("⚠ Cannot read ACL file: %v\n", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	foundExact := false
	hasCIDR := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for exact match
		if line == result.RemoteIP {
			fmt.Printf("✓ Server IP (%s) is in ACL (exact match)\n", result.RemoteIP)
			result.InACL = true
			result.ACLStatus = "exact"
			foundExact = true
			break
		}

		// Check if it's a CIDR range
		if strings.Contains(line, "/") {
			hasCIDR = true
			fmt.Printf("ℹ ACL contains CIDR range: %s\n", line)
			fmt.Printf("  Manual verification needed: check if %s is in this range\n", result.RemoteIP)
		}
	}

	if !foundExact {
		if hasCIDR {
			result.ACLStatus = "cidr_uncertain"
			// Don't count as issue since it might be in CIDR
		} else {
			fmt.Printf("✗ Server IP (%s) NOT in ACL\n", result.RemoteIP)
			result.InACL = false
			result.ACLStatus = "not_found"
			result.IssuesFound++
		}
	}
}

// generateCheckReport generates a comprehensive configuration report
func generateCheckReport(result *CheckResult) int {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ CONFIGURATION SUMMARY                                                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary table
	fmt.Printf("%-50s %s\n", "Check", "Status")
	fmt.Printf("%-50s %s\n", strings.Repeat("─", 50), strings.Repeat("─", 16))

	overallStatus := "OK"
	exitCode := 0

	// Rules exist
	if result.RulesExist {
		fmt.Printf("%-50s ✓ PASS\n", "Egress proxy rules exist")
	} else {
		fmt.Printf("%-50s ✗ FAIL\n", "Egress proxy rules exist")
		overallStatus = "FAILED"
		exitCode = 2
	}

	// Rules correct
	if result.RulesCorrect {
		fmt.Printf("%-50s ✓ PASS\n", "Rules reference correct proxy IP")
	} else {
		fmt.Printf("%-50s ✗ FAIL\n", "Rules reference correct proxy IP")
		overallStatus = "FAILED"
		exitCode = 2
	}

	// Port configuration
	if len(result.PortsConfigured) == 3 {
		fmt.Printf("%-50s ✓ PASS\n", "All ports configured (80, 443, 22)")
	} else if len(result.PortsConfigured) > 0 {
		fmt.Printf("%-50s ⚠ PARTIAL\n", "Port configuration")
		fmt.Printf("  Configured: %s\n", strings.Join(result.PortsConfigured, ", "))
		if overallStatus == "OK" {
			overallStatus = "PARTIAL"
			exitCode = 1
		}
	} else {
		fmt.Printf("%-50s ✗ FAIL\n", "Port configuration")
		overallStatus = "FAILED"
		exitCode = 2
	}

	// Persistence
	if result.RulesPersistent {
		fmt.Printf("%-50s ✓ PASS\n", "Rules will persist after reboot")
	} else {
		fmt.Printf("%-50s ⚠ WARNING\n", "Rules persistence")
	}

	// Connectivity
	if result.ConnectivityOK {
		fmt.Printf("%-50s ✓ PASS\n", "Network connectivity to proxy")
	} else {
		fmt.Printf("%-50s ✗ FAIL\n", "Network connectivity to proxy")
		overallStatus = "FAILED"
		exitCode = 2
	}

	// ACL membership
	if result.ACLStatus == "exact" {
		fmt.Printf("%-50s ✓ PASS\n", "Server IP in ACL")
	} else if result.ACLStatus == "cidr_uncertain" {
		fmt.Printf("%-50s ⚠ UNCERTAIN\n", "Server IP in ACL (CIDR check needed)")
	} else {
		fmt.Printf("%-50s ✗ FAIL\n", "Server IP in ACL")
		overallStatus = "FAILED"
		exitCode = 2
	}

	fmt.Println()
	fmt.Println(strings.Repeat("═", 79))
	fmt.Println()

	// Overall status
	if overallStatus == "OK" {
		fmt.Println("✓ OVERALL STATUS: CONFIGURED CORRECTLY")
		fmt.Println()
		fmt.Println("The server is properly configured to route traffic through the egress proxy.")
	} else if overallStatus == "PARTIAL" {
		fmt.Println("⚠ OVERALL STATUS: PARTIALLY CONFIGURED")
		fmt.Println()
		fmt.Println("The server has some configuration but needs adjustments.")
	} else {
		fmt.Println("✗ OVERALL STATUS: NOT CONFIGURED")
		fmt.Println()
		fmt.Println("The server is not properly configured for egress proxy routing.")
	}

	fmt.Println()

	// Recommendations
	if result.IssuesFound > 0 {
		generateRecommendations(result)
	}

	// Show full rules if there are issues
	if result.IssuesFound > 0 && result.RulesExist {
		fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║ CURRENT FIREWALL RULES                                                    ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println(result.FullRules)
		fmt.Println()
	}

	return exitCode
}

// generateRecommendations provides actionable recommendations
func generateRecommendations(result *CheckResult) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ RECOMMENDED ACTIONS                                                       ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if !result.RulesExist || !result.RulesCorrect {
		fmt.Println("→ Configure the internal server:")
		fmt.Printf("  egressctl server configure %s\n", result.ProxyIP)
		fmt.Printf("  # Or via SSH: ssh %s 'egressctl server configure %s'\n", result.Server, result.ProxyIP)
		fmt.Println()
	}

	if result.ACLStatus == "not_found" {
		fmt.Println("→ Add server IP to egress proxy ACL:")
		fmt.Println("  On egress proxy server:")
		fmt.Printf("  egressctl acl add %s\n", result.RemoteIP)
		fmt.Println("  egressctl acl reload")
		fmt.Println()
	}

	if !result.RulesPersistent {
		fmt.Println("→ Make firewall rules persistent:")
		if result.FirewallType == "iptables" {
			fmt.Printf("  ssh %s 'apt-get install iptables-persistent'\n", result.Server)
			fmt.Printf("  ssh %s 'netfilter-persistent save'\n", result.Server)
		} else {
			fmt.Printf("  ssh %s 'systemctl enable nftables'\n", result.Server)
		}
		fmt.Println()
	}

	if !result.ConnectivityOK {
		fmt.Println("→ Troubleshoot network connectivity:")
		fmt.Println("  - Check firewall rules on both servers")
		fmt.Println("  - Verify HAProxy is running: systemctl status haproxy")
		fmt.Println("  - Check network routing between servers")
		fmt.Println()
	}
}

// testSSH tests SSH connectivity
func testSSH(server, user string) error {
	cmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new", fmt.Sprintf("%s@%s", user, server),
		"echo 'SSH connection successful'")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("SSH failed: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// detectRemoteFirewall detects the firewall type on remote server
func detectRemoteFirewall(server, user string) (string, error) {
	cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", user, server), `
if command -v nft &> /dev/null && [ -f /etc/nftables.conf ]; then
    echo "nftables"
elif command -v iptables &> /dev/null; then
    echo "iptables"
else
    echo "none"
fi`)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to detect firewall: %w", err)
	}

	fwType := strings.TrimSpace(string(output))
	if fwType == "none" {
		return "", fmt.Errorf("no firewall tool detected (iptables or nftables required)")
	}

	return fwType, nil
}
