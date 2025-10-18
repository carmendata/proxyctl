package main

import (
	"fmt"

	"github.com/carmendata/proxyctl/internal/acl"
	"github.com/carmendata/proxyctl/internal/config"
)

// runACLAdd adds an IP/CIDR to the ACL
func runACLAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("IP address or CIDR required")
	}

	ip := args[0]

	// Load config to get ACL file path
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ACL == nil || cfg.ACL.File == "" {
		return fmt.Errorf("ACL configuration not found (acl.file required)")
	}

	// Create ACL manager
	mgr := acl.NewManager(cfg.ACL.File)

	// Add IP
	if err := mgr.Add(ip); err != nil {
		return fmt.Errorf("failed to add IP: %w", err)
	}

	if verbose {
		fmt.Printf("Added to ACL: %s\n", ip)
		fmt.Printf("ACL file: %s\n", cfg.ACL.File)
	} else {
		fmt.Printf("Added to ACL: %s\n", ip)
	}

	// Auto-reload HAProxy (always enabled in V2)
	fmt.Println("Reloading HAProxy...")
	if err := mgr.Reload(); err != nil {
		return fmt.Errorf("failed to reload HAProxy: %w", err)
	}
	fmt.Println("HAProxy reloaded successfully")

	return nil
}

// runACLRemove removes an IP/CIDR from the ACL
func runACLRemove(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("IP address or CIDR required")
	}

	ip := args[0]

	// Load config to get ACL file path
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ACL == nil || cfg.ACL.File == "" {
		return fmt.Errorf("ACL configuration not found (acl.file required)")
	}

	// Create ACL manager
	mgr := acl.NewManager(cfg.ACL.File)

	// Remove IP
	if err := mgr.Remove(ip); err != nil {
		return fmt.Errorf("failed to remove IP: %w", err)
	}

	if verbose {
		fmt.Printf("Removed from ACL: %s\n", ip)
		fmt.Printf("ACL file: %s\n", cfg.ACL.File)
	} else {
		fmt.Printf("Removed from ACL: %s\n", ip)
	}

	// Auto-reload HAProxy (always enabled in V2)
	fmt.Println("Reloading HAProxy...")
	if err := mgr.Reload(); err != nil {
		return fmt.Errorf("failed to reload HAProxy: %w", err)
	}
	fmt.Println("HAProxy reloaded successfully")

	return nil
}

// runACLList lists all ACL entries
func runACLList(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("list command does not accept arguments")
	}

	// Load config to get ACL file path
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ACL == nil || cfg.ACL.File == "" {
		return fmt.Errorf("ACL configuration not found (acl.file required)")
	}

	// Create ACL manager
	mgr := acl.NewManager(cfg.ACL.File)

	// List entries
	entries, err := mgr.List()
	if err != nil {
		return fmt.Errorf("failed to list ACL entries: %w", err)
	}

	if jsonOut {
		// JSON output
		fmt.Println("[")
		for i, entry := range entries {
			if i < len(entries)-1 {
				fmt.Printf("  \"%s\",\n", entry)
			} else {
				fmt.Printf("  \"%s\"\n", entry)
			}
		}
		fmt.Println("]")
	} else {
		// Human-readable output
		fmt.Printf("HAProxy ACL entries (%s):\n", cfg.ACL.File)
		fmt.Println("================================")
		if len(entries) == 0 {
			fmt.Println("(empty)")
		} else {
			for _, entry := range entries {
				fmt.Println(entry)
			}
		}
	}

	return nil
}

// runACLReload reloads HAProxy configuration
func runACLReload(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("reload command does not accept arguments")
	}

	// Load config to get ACL file path
	cfg, err := config.Load(mode, cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.ACL == nil || cfg.ACL.File == "" {
		return fmt.Errorf("ACL configuration not found (acl.file required)")
	}

	// Create ACL manager
	mgr := acl.NewManager(cfg.ACL.File)

	// Reload HAProxy
	if verbose {
		fmt.Println("Reloading HAProxy configuration...")
	}

	if err := mgr.Reload(); err != nil {
		return fmt.Errorf("failed to reload HAProxy: %w", err)
	}

	fmt.Println("HAProxy reloaded successfully")

	return nil
}
