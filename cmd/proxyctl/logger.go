package main

import (
	"fmt"

	"github.com/carmendata/proxyctl/internal/logger"
)

// runLoggerRemove removes the connection logger
func runLoggerRemove(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("remove command does not accept arguments")
	}

	// Check if running as root
	if !isRoot() {
		return fmt.Errorf("this command must be run as root (iptables and system configuration required)")
	}

	if verbose {
		fmt.Println("Removing outbound connection logger...")
	}

	mgr := logger.NewManager()

	if err := mgr.Remove(); err != nil {
		return fmt.Errorf("failed to remove logger: %w", err)
	}

	fmt.Println("Removal complete!")
	fmt.Println()
	fmt.Printf("Log file preserved at: %s\n", mgr.LogFile)
	fmt.Printf("Compressed logs preserved in: %s.*.gz\n", mgr.LogFile)
	fmt.Println()
	fmt.Println("Note: Log files were NOT deleted. Analyze or delete manually if needed.")
	fmt.Println()
	fmt.Println("To analyze logs before deletion:")
	fmt.Println("  egressctl logger analyze")
	fmt.Println()
	fmt.Printf("To delete logs:\n  rm -f %s %s.*.gz\n", mgr.LogFile, mgr.LogFile)

	return nil
}

// runLoggerInstall installs the connection logger
func runLoggerInstall(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("install command does not accept arguments")
	}

	// Check if running as root
	if !isRoot() {
		return fmt.Errorf("this command must be run as root (iptables and system configuration required)")
	}

	if verbose {
		fmt.Println("Installing outbound connection logger...")
	}

	fmt.Println("This will monitor ALL outbound TCP/UDP connections to public IPs.")
	fmt.Println("A firewall will be installed if not already present (with permissive rules).")
	fmt.Println("No changes to traffic flow - monitoring only.")
	fmt.Println()

	mgr := logger.NewManager()

	if err := mgr.Install(); err != nil {
		return fmt.Errorf("failed to install logger: %w", err)
	}

	fmt.Println()
	fmt.Println("Installation complete!")
	fmt.Println()
	fmt.Println("Monitoring Details:")
	fmt.Printf("  Log file: %s\n", mgr.LogFile)
	fmt.Println("  Protocols: TCP and UDP (all ports)")
	fmt.Println("  Target: Public IPs only (private IPs excluded)")
	fmt.Println("  Impact: None - monitoring only, no traffic blocking")
	fmt.Println()
	fmt.Println("Next Steps:")
	fmt.Println("  1. Wait 7 days to collect data")
	fmt.Println("  2. Analyze logs: egressctl logger analyze")
	fmt.Println("  3. Remove monitoring: egressctl logger remove")
	fmt.Println()
	fmt.Printf("View live connections:\n  tail -f %s\n", mgr.LogFile)
	fmt.Println()
	fmt.Println("Verify installation:")
	fmt.Println("  iptables: iptables -L EGRESS_LOG -n -v")
	fmt.Println("  nftables: nft list table ip egress_monitor")
	fmt.Println()
	fmt.Println("Persistence: Rules will automatically persist across reboots")
	fmt.Println("  iptables: systemd service enabled (check with: systemctl status egressctl-logger)")
	fmt.Println("  nftables: config file loaded on boot (/etc/nftables.d/egress-monitor.nft)")

	return nil
}
