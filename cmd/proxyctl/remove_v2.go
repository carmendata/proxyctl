package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
	"github.com/carmendata/proxyctl/internal/routing"
)

// runRemoveV2 removes v2.0 configuration (removes routing, HAProxy, and intercept)
func runRemoveV2(configFile string) error {
	fmt.Println("🗑️  Removing v2.0 configuration")
	fmt.Println()

	// Load v2 configuration to know what to remove
	var cfg *config.Config
	var err error
	if configFile != "" {
		cfg, err = config.Load(configFile)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not load config file: %v\n", err)
			fmt.Println("   Will attempt to remove all v2 components")
			cfg = nil
		}
	}

	// Confirm before removing
	if err := confirmV2Remove(); err != nil {
		return err
	}

	var errors []string

	// Step 1: Remove port interception
	fmt.Println("\n🔀 Removing port interception...")
	if err := removeIntercept(); err != nil {
		errors = append(errors, fmt.Sprintf("port interception: %v", err))
		fmt.Printf("⚠️  Failed to remove port interception: %v\n", err)
	} else {
		fmt.Println("✓ Port interception removed")
	}

	// Step 2: Stop and disable HAProxy
	fmt.Println("\n🔧 Stopping HAProxy...")
	if err := removeHAProxy(); err != nil {
		errors = append(errors, fmt.Sprintf("HAProxy: %v", err))
		fmt.Printf("⚠️  Failed to stop HAProxy: %v\n", err)
	} else {
		fmt.Println("✓ HAProxy stopped and disabled")
	}

	// Step 3: Remove routing configuration
	fmt.Println("\n📡 Removing routing configuration...")
	if err := removeRouting(cfg); err != nil {
		errors = append(errors, fmt.Sprintf("routing: %v", err))
		fmt.Printf("⚠️  Failed to remove routing: %v\n", err)
	} else {
		fmt.Println("✓ Routing configuration removed")
	}

	// Summary
	fmt.Println()
	if len(errors) > 0 {
		fmt.Println("⚠️  Removal completed with errors:")
		for _, errMsg := range errors {
			fmt.Printf("   - %s\n", errMsg)
		}
		fmt.Println("\nℹ️  Some components may require manual cleanup")
		return fmt.Errorf("removal completed with %d error(s)", len(errors))
	}

	fmt.Println("✅ V2 configuration removed successfully")
	fmt.Println("\n📝 Cleanup notes:")
	fmt.Println("   - HAProxy config file still exists at /etc/haproxy/haproxy.cfg")
	fmt.Println("   - You may want to remove it manually if no longer needed")
	fmt.Println("   - IP forwarding and MASQUERADE have been disabled")

	return nil
}

// removeIntercept removes port interception rules
func removeIntercept() error {
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to create firewall manager: %w", err)
	}

	fmt.Printf("  Detected firewall type: %s\n", fwMgr.Type)

	// Check if intercept is active
	active, err := fwMgr.GetInterceptStatus()
	if err != nil {
		return fmt.Errorf("failed to check intercept status: %w", err)
	}

	if !active {
		fmt.Println("  ℹ️  Port interception is not active")
		return nil
	}

	// Remove intercept rules
	fmt.Println("  Removing PREROUTING redirect rules...")
	if err := fwMgr.RemoveIntercept(); err != nil {
		return fmt.Errorf("failed to remove intercept rules: %w", err)
	}

	return nil
}

// removeHAProxy stops and disables HAProxy service
func removeHAProxy() error {
	// Check if HAProxy is running
	statusCmd := exec.Command("systemctl", "is-active", "haproxy")
	isRunning := statusCmd.Run() == nil

	if isRunning {
		// Stop HAProxy
		fmt.Println("  Stopping HAProxy service...")
		stopCmd := exec.Command("systemctl", "stop", "haproxy")
		if output, err := stopCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to stop HAProxy: %w (output: %s)", err, string(output))
		}
		fmt.Println("  ✓ HAProxy stopped")
	} else {
		fmt.Println("  ℹ️  HAProxy is not running")
	}

	// Disable HAProxy
	fmt.Println("  Disabling HAProxy service...")
	disableCmd := exec.Command("systemctl", "disable", "haproxy")
	if output, err := disableCmd.CombinedOutput(); err != nil {
		// Ignore errors if service is not enabled
		fmt.Printf("  ℹ️  Could not disable HAProxy: %s\n", strings.TrimSpace(string(output)))
	} else {
		fmt.Println("  ✓ HAProxy disabled")
	}

	return nil
}

// removeRouting removes routing configuration (IP forwarding + MASQUERADE)
func removeRouting(cfg *config.Config) error {
	routingMgr, err := routing.NewManager()
	if err != nil {
		return fmt.Errorf("failed to create routing manager: %w", err)
	}

	// Check if routing is enabled in config
	if cfg != nil && cfg.Routing != nil && cfg.Routing.Enabled {
		// Disable MASQUERADE if it was enabled
		if cfg.Routing.Masquerade.Enabled {
			fmt.Println("  Disabling MASQUERADE...")
			if err := routingMgr.DisableMasquerade(); err != nil {
				fmt.Printf("  ⚠️  Failed to disable MASQUERADE: %v\n", err)
			} else {
				fmt.Println("  ✓ MASQUERADE disabled")
			}
		}

		// Disable IP forwarding if it was enabled
		if cfg.Routing.IPForward {
			fmt.Println("  Disabling IP forwarding...")
			if err := routingMgr.DisableIPForward(); err != nil {
				fmt.Printf("  ⚠️  Failed to disable IP forwarding: %v\n", err)
			} else {
				fmt.Println("  ✓ IP forwarding disabled")
			}
		}
	} else {
		// Config not available or routing not enabled, try to remove anyway
		fmt.Println("  Attempting to disable MASQUERADE...")
		if err := routingMgr.DisableMasquerade(); err != nil {
			fmt.Printf("  ℹ️  MASQUERADE not active or failed to disable: %v\n", err)
		} else {
			fmt.Println("  ✓ MASQUERADE disabled")
		}

		fmt.Println("  Attempting to disable IP forwarding...")
		if err := routingMgr.DisableIPForward(); err != nil {
			fmt.Printf("  ℹ️  IP forwarding not active or failed to disable: %v\n", err)
		} else {
			fmt.Println("  ✓ IP forwarding disabled")
		}
	}

	return nil
}

// confirmV2Remove prompts the user to confirm removing v2 configuration
func confirmV2Remove() error {
	fmt.Print("\n⚠️  This will remove all v2.0 configuration. Continue? (yes/no): ")
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

// runStatusV2 shows v2.0 configuration status
func runStatusV2(configFile string) error {
	fmt.Println("📊 V2.0 Configuration Status")
	fmt.Println("============================")
	fmt.Println()

	// Load configuration if provided
	var cfg *config.Config
	if configFile != "" {
		var err error
		cfg, err = config.Load(configFile)
		if err != nil {
			fmt.Printf("⚠️  Warning: Could not load config file: %v\n", err)
			cfg = nil
		} else {
			fmt.Printf("Configuration file: %s\n", configFile)
			fmt.Println("✓ Configuration is valid")
			fmt.Println()
		}
	}

	// Check routing status
	fmt.Println("Routing:")
	routingMgr, err := routing.NewManager()
	if err != nil {
		fmt.Printf("  ⚠️  Failed to create routing manager: %v\n", err)
	} else {
		// Check IP forwarding
		ipForward, err := routingMgr.GetIPForwardStatus()
		if err != nil {
			fmt.Printf("  IP Forwarding: error - %v\n", err)
		} else {
			if ipForward {
				fmt.Println("  IP Forwarding: ✓ enabled")
			} else {
				fmt.Println("  IP Forwarding: ✗ disabled")
			}
		}

		// Check MASQUERADE
		masquerade, err := routingMgr.GetMasqueradeStatus()
		if err != nil {
			fmt.Printf("  MASQUERADE: error - %v\n", err)
		} else {
			if masquerade {
				fmt.Println("  MASQUERADE: ✓ enabled")
			} else {
				fmt.Println("  MASQUERADE: ✗ disabled")
			}
		}
	}

	// Check HAProxy status
	fmt.Println("\nHAProxy:")
	statusCmd := exec.Command("systemctl", "is-active", "haproxy")
	isRunning := statusCmd.Run() == nil

	if isRunning {
		fmt.Println("  Service: ✓ running")
	} else {
		fmt.Println("  Service: ✗ not running")
	}

	// Check if enabled
	enabledCmd := exec.Command("systemctl", "is-enabled", "haproxy")
	isEnabled := enabledCmd.Run() == nil

	if isEnabled {
		fmt.Println("  Autostart: ✓ enabled")
	} else {
		fmt.Println("  Autostart: ✗ disabled")
	}

	// Check port interception
	fmt.Println("\nPort Interception:")
	fwMgr, err := firewall.NewManager()
	if err != nil {
		fmt.Printf("  ⚠️  Failed to create firewall manager: %v\n", err)
	} else {
		active, err := fwMgr.GetInterceptStatus()
		if err != nil {
			fmt.Printf("  Status: error - %v\n", err)
		} else {
			if active {
				fmt.Println("  Status: ✓ active")
			} else {
				fmt.Println("  Status: ✗ not active")
			}
		}
		fmt.Printf("  Firewall type: %s\n", fwMgr.Type)
	}

	// Show config summary if available
	if cfg != nil {
		fmt.Println("\nConfiguration Summary:")
		if cfg.Routing != nil && cfg.Routing.Enabled {
			fmt.Printf("  - Routing: enabled\n")
		}
		if cfg.Proxy != nil && cfg.Proxy.Enabled {
			fmt.Printf("  - Proxy: %s %s\n", cfg.Proxy.Mode, cfg.Proxy.Type)
		}
		if cfg.Firewall != nil && cfg.Firewall.Enabled {
			fmt.Printf("  - Firewall: enabled (%d rules)\n", len(cfg.Firewall.Rules))
		}
	}

	fmt.Println()
	return nil
}
