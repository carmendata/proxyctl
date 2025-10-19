package main

import (
	"fmt"
	"strings"

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

	// Load configuration to get logger settings
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create manager from config if logger config exists, otherwise use defaults
	var mgr *logger.Manager
	if cfg.Logger != nil && cfg.Logger.Enabled {
		mgr = logger.NewManagerFromConfig(cfg.Logger)
	} else {
		mgr = logger.NewManager()
	}

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
		fmt.Println("Installing connection logger...")
	}

	// Load configuration to get logger settings
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Create manager from config if logger config exists, otherwise use defaults
	var mgr *logger.Manager
	if cfg.Logger != nil && cfg.Logger.Enabled {
		mgr = logger.NewManagerFromConfig(cfg.Logger)
		fmt.Println("Using logger configuration from config file")
	} else {
		mgr = logger.NewManager()
		fmt.Println("Using default logger configuration (no logger config in file)")
	}

	// Display what will be monitored
	fmt.Println()
	displayLoggerConfig(mgr)
	fmt.Println()

	if err := mgr.Install(); err != nil {
		return fmt.Errorf("failed to install logger: %w", err)
	}

	fmt.Println()
	fmt.Println("Installation complete!")
	fmt.Println()
	fmt.Println("Monitoring Details:")
	fmt.Printf("  Log file: %s\n", mgr.LogFile)
	displayMonitoringScope(mgr)
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

// displayLoggerConfig shows what will be monitored based on configuration
func displayLoggerConfig(mgr *logger.Manager) {
	fmt.Println("Configuration:")

	// Chains
	if len(mgr.Chains) > 0 {
		fmt.Printf("  Chains: %s\n", strings.Join(mgr.Chains, ", "))
	}

	// Protocols
	if len(mgr.Protocols) > 0 {
		fmt.Printf("  Protocols: %s\n", strings.Join(mgr.Protocols, ", "))
	}

	// Whitelist mode
	if len(mgr.IncludeRanges) > 0 {
		fmt.Printf("  Mode: Whitelist (only monitoring %d specific IP(s)/range(s))\n", len(mgr.IncludeRanges))
		for _, ip := range mgr.IncludeRanges {
			fmt.Printf("    - %s\n", ip)
		}
	} else {
		// Normal mode - show what's included
		includes := []string{}
		if !mgr.IncludePrivate && !mgr.IncludeLoopback && !mgr.IncludeMulticast {
			includes = append(includes, "public IPs")
		} else {
			if mgr.IncludePrivate {
				includes = append(includes, "private IPs")
			} else {
				includes = append(includes, "public IPs")
			}
			if mgr.IncludeLoopback {
				includes = append(includes, "loopback")
			}
			if mgr.IncludeMulticast {
				includes = append(includes, "multicast")
			}
		}
		fmt.Printf("  Monitoring: %s\n", strings.Join(includes, ", "))

		// Show excludes if any
		if len(mgr.ExcludeRanges) > 0 {
			fmt.Printf("  Excluding: %s\n", strings.Join(mgr.ExcludeRanges, ", "))
		}
	}
}

// displayMonitoringScope shows monitoring scope in success message
func displayMonitoringScope(mgr *logger.Manager) {
	// Protocols
	protocols := strings.Join(mgr.Protocols, ", ")
	fmt.Printf("  Protocols: %s\n", protocols)

	// Target scope
	if len(mgr.IncludeRanges) > 0 {
		fmt.Printf("  Target: Specific IPs only (%d range(s))\n", len(mgr.IncludeRanges))
	} else if mgr.IncludePrivate && mgr.IncludeLoopback && mgr.IncludeMulticast {
		fmt.Println("  Target: All traffic (public + private + loopback + multicast)")
	} else if mgr.IncludePrivate {
		fmt.Println("  Target: Public and private IPs")
	} else {
		fmt.Println("  Target: Public IPs only")
	}
}
