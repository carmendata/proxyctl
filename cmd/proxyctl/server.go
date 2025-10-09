package main

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/carmendata/proxyctl/internal/firewall"
)

// runServerRemove removes egress proxy configuration from internal server
func runServerRemove(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("remove command does not accept arguments")
	}

	// Check if running as root
	if !isRoot() {
		return fmt.Errorf("this command must be run as root (firewall modification required)")
	}

	if verbose {
		fmt.Println("Removing egress proxy configuration...")
	}

	// Detect firewall
	mgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("firewall detection failed: %w", err)
	}

	if verbose {
		fmt.Printf("Detected firewall: %s\n", mgr.Type)
	}

	// Remove rules
	if err := mgr.RemoveEgressProxyRules(); err != nil {
		return fmt.Errorf("failed to remove firewall rules: %w", err)
	}

	fmt.Println("Egress proxy configuration removed")
	fmt.Println("This server will now route traffic normally (not through egress proxy)")

	return nil
}

// runServerConfigure configures internal server to route through egress proxy
func runServerConfigure(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("EGRESS_PROXY_IP required\n\nUsage: egressctl server configure <EGRESS_PROXY_IP> [PROXY_PORT]")
	}

	// Check if running as root
	if !isRoot() {
		return fmt.Errorf("this command must be run as root (firewall modification required)")
	}

	proxyIP := args[0]
	proxyPort := 8080 // Default

	// Parse optional port argument
	if len(args) > 1 {
		var err error
		if _, err = fmt.Sscanf(args[1], "%d", &proxyPort); err != nil {
			return fmt.Errorf("invalid port number: %s", args[1])
		}
		if proxyPort < 1 || proxyPort > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
	}

	// Validate IP address
	if !isValidIP(proxyIP) {
		return fmt.Errorf("invalid IP address format: %s", proxyIP)
	}

	fmt.Println("Configuring Internal Server for Egress Proxy")
	fmt.Printf("Egress Proxy IP: %s\n", proxyIP)
	fmt.Printf("Proxy Port: %d\n", proxyPort)
	fmt.Println("Ports to redirect: 80 443 22")
	fmt.Println()

	// Detect firewall
	mgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("firewall detection failed: %w", err)
	}

	fmt.Printf("Detected firewall: %s\n", mgr.Type)
	fmt.Println()

	// Configure firewall rules
	if err := mgr.ConfigureEgressProxy(proxyIP, proxyPort); err != nil {
		return fmt.Errorf("failed to configure firewall: %w", err)
	}

	fmt.Println()
	fmt.Println("Configuration complete!")
	fmt.Println()
	fmt.Println("Verification:")
	if mgr.Type == firewall.TypeIPTables {
		fmt.Println("  iptables -t nat -L EGRESS_PROXY -n -v")
	} else {
		fmt.Println("  nft list table ip egress_proxy")
	}
	fmt.Println()
	fmt.Println("Test connectivity:")
	fmt.Println("  curl -I https://example.com")
	fmt.Println()
	fmt.Printf("All outbound HTTP(S) and SSH traffic will now route through: %s\n", proxyIP)
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ IMPORTANT: Add this server's IP to the egress proxy ACL NOW!  ║")
	fmt.Println("║ On egress proxy: egressctl acl add <THIS_SERVER_IP>           ║")
	fmt.Println("║                  egressctl acl reload                          ║")
	fmt.Println("║ Without ACL entry, connections will be REJECTED!              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")

	return nil
}

// isValidIP validates an IPv4 address
func isValidIP(ip string) bool {
	// Check basic IPv4 format
	matched, _ := regexp.MatchString(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`, ip)
	if !matched {
		return false
	}

	// Use net package for proper validation
	return net.ParseIP(ip) != nil
}

// isRoot checks if running as root
func isRoot() bool {
	return os.Geteuid() == 0
}
