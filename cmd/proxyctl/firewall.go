package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
)

// runFirewallApply applies firewall rules from configuration
func runFirewallApply(args []string) error {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Detect firewall type
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to detect firewall: %w", err)
	}

	fmt.Printf("Detected firewall type: %s\n", fwMgr.Type)

	// Safety check: Detect SSH connection and check for potential lockout
	sshIP, err := detectSSHConnectionIP()
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not detect SSH connection: %v\n", err)
	} else if sshIP != "" {
		fmt.Printf("SSH connection detected from: %s\n", sshIP)

		// Check if applying rules would lock out this SSH connection
		if err := checkSSHLockout(cfg.Firewall, sshIP); err != nil {
			fmt.Printf("\n⛔ %v\n", err)
			fmt.Println("\n⚠️  Proceeding will likely LOCK YOU OUT of this server!")
			fmt.Println("   Add your IP to allow_ssh_from in the config before applying.")
			return fmt.Errorf("aborting to prevent SSH lockout")
		}
		fmt.Println("✓ SSH lockout check passed - your IP is in allow list")
	}

	// Check if firewall config is present
	if cfg.Firewall == nil && cfg.Redirect == nil {
		return fmt.Errorf("no firewall or redirect configuration found in config file")
	}

	// Show configuration summary and ask for confirmation
	if err := confirmApply(cfg); err != nil {
		return err
	}

	// Create backup before applying changes
	fmt.Println("\nCreating backup of current firewall rules...")
	backupPath, err := fwMgr.Backup()
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	fmt.Printf("✓ Backup created: %s\n", backupPath)

	// Track if we need to rollback
	var appliedSomething bool
	defer func() {
		if err != nil && appliedSomething {
			fmt.Println("\n⚠️  Error occurred, rolling back changes...")
			if restoreErr := fwMgr.Restore(backupPath); restoreErr != nil {
				fmt.Printf("❌ Failed to rollback: %v\n", restoreErr)
				fmt.Printf("   Manual restore required: %s restore %s\n", os.Args[0], backupPath)
			} else {
				fmt.Println("✓ Successfully rolled back changes")
			}
		}
	}()

	// Apply INPUT filtering if configured
	if cfg.Firewall != nil && cfg.Firewall.Enabled {
		fmt.Println("\nApplying INPUT filtering rules...")

		// Check for priority conflicts
		if err := fwMgr.CheckInputFilteringPriorityConflict(); err != nil {
			return fmt.Errorf("priority conflict detected: %w", err)
		}

		// Apply INPUT filtering
		if err := fwMgr.ApplyInputFiltering(cfg.Firewall); err != nil {
			appliedSomething = true
			return fmt.Errorf("failed to apply INPUT filtering: %w", err)
		}
		appliedSomething = true

		fmt.Println("✓ INPUT filtering applied successfully")
		fmt.Printf("  Policy: %s\n", cfg.Firewall.InputPolicy)
		if len(cfg.Firewall.AllowSSHFrom) > 0 {
			fmt.Printf("  SSH allowed from: %s\n", strings.Join(cfg.Firewall.AllowSSHFrom, ", "))
		}
		if len(cfg.Firewall.AllowProxyFrom) > 0 {
			fmt.Printf("  Proxy access allowed from %d rule(s)\n", len(cfg.Firewall.AllowProxyFrom))
		}
	}

	// Apply OUTPUT redirect if configured
	if cfg.Redirect != nil && cfg.Redirect.Enabled {
		fmt.Println("\nApplying OUTPUT redirect rules...")

		// Validate proxy config is present
		if cfg.Proxy == nil {
			return fmt.Errorf("redirect requires proxy configuration")
		}

		// Apply OUTPUT redirect
		if err := fwMgr.ApplyOutputRedirect(cfg.Redirect, cfg.Proxy.IP, cfg.Proxy.Port); err != nil {
			appliedSomething = true
			return fmt.Errorf("failed to apply OUTPUT redirect: %w", err)
		}
		appliedSomething = true

		fmt.Println("✓ OUTPUT redirect applied successfully")
		fmt.Printf("  Type: %s\n", cfg.Redirect.Type)
		fmt.Printf("  Proxy: %s:%d\n", cfg.Proxy.IP, cfg.Proxy.Port)
		if cfg.Redirect.Type == "partial" {
			fmt.Printf("  Targets: %s\n", strings.Join(cfg.Redirect.Targets, ", "))
		}
	}

	fmt.Println("\n✅ Firewall configuration applied successfully")
	fmt.Printf("   Backup available at: %s\n", backupPath)

	return nil
}

// runFirewallRemove removes all proxyctl firewall rules
func runFirewallRemove(args []string) error {
	// Detect firewall type
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to detect firewall: %w", err)
	}

	fmt.Printf("Detected firewall type: %s\n", fwMgr.Type)

	// Create backup before removing rules
	fmt.Println("\nCreating backup of current firewall rules...")
	backupPath, err := fwMgr.Backup()
	if err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	fmt.Printf("✓ Backup created: %s\n", backupPath)

	// Remove INPUT filtering
	fmt.Println("\nRemoving INPUT filtering rules...")
	if err := fwMgr.RemoveInputFiltering(); err != nil {
		fmt.Printf("⚠️  Failed to remove INPUT filtering: %v\n", err)
	} else {
		fmt.Println("✓ INPUT filtering removed")
	}

	// Remove OUTPUT redirect
	fmt.Println("\nRemoving OUTPUT redirect rules...")
	if err := fwMgr.RemoveOutputRedirect(); err != nil {
		fmt.Printf("⚠️  Failed to remove OUTPUT redirect: %v\n", err)
	} else {
		fmt.Println("✓ OUTPUT redirect removed")
	}

	fmt.Println("\n✅ Firewall rules removed")
	fmt.Printf("   Backup available at: %s\n", backupPath)

	return nil
}

// runFirewallStatus shows current firewall configuration status
func runFirewallStatus(args []string) error {
	// Detect firewall type
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to detect firewall: %w", err)
	}

	fmt.Printf("Firewall Type: %s\n", fwMgr.Type)
	fmt.Println()

	// List backups
	backups, err := fwMgr.ListBackups()
	if err != nil {
		fmt.Printf("Failed to list backups: %v\n", err)
	} else if len(backups) == 0 {
		fmt.Println("Backups: None")
	} else {
		fmt.Printf("Backups: %d available\n", len(backups))
		fmt.Println("\nMost recent backups:")
		// Show up to 5 most recent backups
		limit := 5
		if len(backups) < limit {
			limit = len(backups)
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("  - %s\n", backups[i])
		}
		if len(backups) > 5 {
			fmt.Printf("  ... and %d more\n", len(backups)-5)
		}
	}

	fmt.Println()

	// Show INPUT filtering status
	fmt.Println("INPUT Filtering:")
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		fmt.Println("  Chain: PROXYCTL_INPUT (iptables)")
		// TODO: Check if chain exists and show rules
	case firewall.TypeNFTables:
		fmt.Println("  Table: proxyctl_filter (nftables)")
		// TODO: Check if table exists and show rules
	}

	// Show OUTPUT redirect status
	fmt.Println("\nOUTPUT Redirect:")
	switch fwMgr.Type {
	case firewall.TypeIPTables:
		fmt.Println("  Chain: PROXYCTL_OUTPUT (iptables nat)")
		// TODO: Check if chain exists and show rules
	case firewall.TypeNFTables:
		fmt.Println("  Table: proxyctl_redirect (nftables)")
		// TODO: Check if table exists and show rules
	}

	fmt.Println("\nℹ️  Use 'iptables -L' or 'nft list ruleset' to view detailed rules")

	return nil
}

// runFirewallRestore restores firewall rules from a backup
func runFirewallRestore(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: firewall restore <backup-file>")
	}

	backupPath := args[0]

	// Detect firewall type
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to detect firewall: %w", err)
	}

	fmt.Printf("Detected firewall type: %s\n", fwMgr.Type)
	fmt.Printf("Restoring from: %s\n", backupPath)

	// Confirm before restoring
	fmt.Print("\n⚠️  This will replace current firewall rules. Continue? (yes/no): ")
	var response string
	fmt.Scanln(&response)
	if response != "yes" {
		fmt.Println("Restore cancelled")
		return nil
	}

	// Restore from backup
	if err := fwMgr.Restore(backupPath); err != nil {
		return fmt.Errorf("failed to restore: %w", err)
	}

	fmt.Println("✅ Firewall rules restored successfully")

	return nil
}

// loadConfig loads configuration from file or default location
func loadConfig() (*config.Config, error) {
	// Load and validate config (mode and cfgFile are global variables)
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// detectSSHConnectionIP detects the IP address of the current SSH connection
func detectSSHConnectionIP() (string, error) {
	// Check if SSH_CONNECTION environment variable is set
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn == "" {
		return "", nil // Not an SSH connection
	}

	// SSH_CONNECTION format: "client_ip client_port server_ip server_port"
	parts := strings.Fields(sshConn)
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid SSH_CONNECTION format: %s", sshConn)
	}

	return parts[0], nil
}

// checkSSHLockout checks if applying firewall rules would lock out the current SSH connection
func checkSSHLockout(cfg *config.FirewallConfig, sshIP string) error {
	if cfg == nil || !cfg.Enabled {
		return nil // No INPUT filtering, no lockout risk
	}

	if len(cfg.AllowSSHFrom) == 0 {
		return nil // No SSH rules, so SSH might be locked out but we can't help
	}

	// Check if SSH IP is in allow list
	for _, allowedIP := range cfg.AllowSSHFrom {
		// Check if it's an exact match
		if sshIP == allowedIP {
			return nil // Safe
		}

		// Check if it's in a CIDR block
		_, ipNet, err := net.ParseCIDR(allowedIP)
		if err == nil {
			// It's a CIDR block - check if SSH IP is in it
			ip := net.ParseIP(sshIP)
			if ip != nil && ipNet.Contains(ip) {
				return nil // Safe
			}
		}
	}

	// SSH IP is not in allow list - potential lockout
	return fmt.Errorf("SSH lockout risk: your IP %s is not in allow_ssh_from list", sshIP)
}

// confirmApply prompts the user to confirm applying firewall rules
func confirmApply(cfg *config.Config) error {
	// Show what will be applied
	fmt.Println("\n📋 Configuration Summary:")
	fmt.Println("========================")

	if cfg.Firewall != nil && cfg.Firewall.Enabled {
		fmt.Printf("INPUT Filtering: ENABLED\n")
		fmt.Printf("  Policy: %s\n", cfg.Firewall.InputPolicy)
		if len(cfg.Firewall.AllowSSHFrom) > 0 {
			fmt.Printf("  SSH allowed from: %s\n", strings.Join(cfg.Firewall.AllowSSHFrom, ", "))
		}
		if len(cfg.Firewall.AllowProxyFrom) > 0 {
			fmt.Printf("  Proxy access: %d rule(s)\n", len(cfg.Firewall.AllowProxyFrom))
		}
	}

	if cfg.Redirect != nil && cfg.Redirect.Enabled {
		fmt.Printf("\nOUTPUT Redirect: ENABLED\n")
		fmt.Printf("  Type: %s\n", cfg.Redirect.Type)
		if cfg.Proxy != nil {
			fmt.Printf("  Proxy: %s:%d\n", cfg.Proxy.IP, cfg.Proxy.Port)
		}
		if cfg.Redirect.Type == "partial" && len(cfg.Redirect.Targets) > 0 {
			fmt.Printf("  Targets: %s\n", strings.Join(cfg.Redirect.Targets, ", "))
		}
	}

	fmt.Println()

	// Prompt for confirmation
	fmt.Print("Apply these firewall rules? (yes/no): ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response != "yes" {
		return fmt.Errorf("operation cancelled by user")
	}

	return nil
}
