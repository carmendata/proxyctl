package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/firewall"
	"github.com/carmendata/proxyctl/internal/haproxy"
	"github.com/carmendata/proxyctl/internal/routing"
)

// runApplyV2 applies v2.0 configuration (orchestrates routing, HAProxy, and intercept)
func runApplyV2(dryRun bool, configFile string) error {
	if dryRun {
		fmt.Println("🔍 DRY RUN MODE - No changes will be made")
		fmt.Println()
	}

	// Load configuration
	fmt.Printf("Loading configuration from: %s\n", configFile)
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	fmt.Println("✓ Configuration loaded and validated")
	fmt.Println()

	// Show configuration summary
	showV2ConfigurationSummary(cfg)

	// Confirm before applying (skip in dry-run mode)
	if !dryRun {
		if err := confirmV2Apply(); err != nil {
			return err
		}
	}

	// Track what was applied for rollback
	var appliedRouting, appliedHAProxy, appliedIntercept bool

	// Rollback on error
	defer func() {
		if err != nil && !dryRun {
			fmt.Println("\n⚠️  Error occurred, attempting rollback...")
			rollbackV2(appliedRouting, appliedHAProxy, appliedIntercept)
		}
	}()

	// Step 1: Setup Routing (IP forwarding + MASQUERADE)
	if cfg.Routing != nil && cfg.Routing.Enabled {
		if !dryRun {
			fmt.Println("\n📡 Setting up routing...")
			if err := applyRouting(cfg); err != nil {
				return fmt.Errorf("failed to apply routing: %w", err)
			}
			appliedRouting = true
			fmt.Println("✓ Routing configured successfully")
		} else {
			fmt.Println("\n[DRY RUN] Would setup routing:")
			fmt.Printf("  - IP Forwarding: %v\n", cfg.Routing.IPForward)
			fmt.Printf("  - MASQUERADE on %s\n", cfg.Routing.Masquerade.Interface)
		}
	}

	// Step 2: Generate and validate HAProxy configuration
	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		if !dryRun {
			fmt.Println("\n🔧 Configuring HAProxy...")
			if err := applyHAProxy(cfg); err != nil {
				return fmt.Errorf("failed to configure HAProxy: %w", err)
			}
			appliedHAProxy = true
			fmt.Println("✓ HAProxy configured successfully")
		} else {
			fmt.Println("\n[DRY RUN] Would configure HAProxy:")
			fmt.Printf("  - Mode: %s\n", cfg.Proxy.Mode)
			fmt.Printf("  - Type: %s\n", cfg.Proxy.Type)
			fmt.Printf("  - Bind: %s:%d\n", cfg.Proxy.Bind.Interface, cfg.Proxy.Bind.Port)
		}
	}

	// Step 3: Setup port interception (PREROUTING)
	if cfg.Proxy != nil && cfg.Proxy.Enabled && cfg.Proxy.Intercept != nil {
		if !dryRun {
			fmt.Println("\n🔀 Setting up port interception...")
			if err := applyIntercept(cfg); err != nil {
				return fmt.Errorf("failed to setup port interception: %w", err)
			}
			appliedIntercept = true
			fmt.Println("✓ Port interception configured successfully")
		} else {
			fmt.Println("\n[DRY RUN] Would setup port interception:")
			fmt.Printf("  - From interface: %s\n", cfg.Proxy.Intercept.FromInterface)
			fmt.Printf("  - Ports: %v\n", cfg.Proxy.Intercept.Ports)
		}
	}

	if !dryRun {
		fmt.Println("\n✅ V2 configuration applied successfully")
		fmt.Println("\n📝 Next steps:")
		if cfg.Proxy != nil && cfg.Proxy.Enabled {
			fmt.Println("   - HAProxy will start automatically on boot")
			fmt.Println("   - View logs: journalctl -u haproxy -f")
			fmt.Println("   - Check status: systemctl status haproxy")
		}
		if cfg.Routing != nil && cfg.Routing.Enabled {
			fmt.Println("   - IP forwarding is enabled and persistent")
			fmt.Println("   - MASQUERADE is active and will persist across reboots")
		}
	} else {
		fmt.Println("\n✅ DRY RUN complete - no changes were made")
		fmt.Println("   Run without --dry-run to apply this configuration")
	}

	return nil
}

// applyRouting sets up IP forwarding and MASQUERADE
func applyRouting(cfg *config.Config) error {
	// Create routing manager
	routingMgr, err := routing.NewManager()
	if err != nil {
		return fmt.Errorf("failed to create routing manager: %w", err)
	}

	// Enable IP forwarding if configured
	if cfg.Routing.IPForward {
		fmt.Println("  Enabling IP forwarding...")
		if err := routingMgr.EnableIPForward(); err != nil {
			return fmt.Errorf("failed to enable IP forwarding: %w", err)
		}
		fmt.Println("  ✓ IP forwarding enabled")
	}

	// Enable MASQUERADE if configured
	if cfg.Routing.Masquerade.Enabled {
		// Resolve interface name
		physicalIface, ok := cfg.Interfaces[cfg.Routing.Masquerade.Interface]
		if !ok {
			return fmt.Errorf("interface '%s' not found in configuration", cfg.Routing.Masquerade.Interface)
		}

		fmt.Printf("  Enabling MASQUERADE on %s (%s)...\n", cfg.Routing.Masquerade.Interface, physicalIface)
		if err := routingMgr.EnableMasquerade(physicalIface); err != nil {
			return fmt.Errorf("failed to enable MASQUERADE: %w", err)
		}
		fmt.Println("  ✓ MASQUERADE enabled")
	}

	return nil
}

// applyHAProxy generates HAProxy configuration and starts the service
func applyHAProxy(cfg *config.Config) error {
	// Ensure HAProxy is installed
	fmt.Println("  Checking HAProxy installation...")
	if err := firewall.EnsureHAProxy(); err != nil {
		return fmt.Errorf("failed to ensure HAProxy is installed: %w", err)
	}
	fmt.Println("  ✓ HAProxy is installed")

	// Create HAProxy manager
	haproxyMgr := haproxy.NewManager()

	// Generate HAProxy configuration
	fmt.Println("  Generating HAProxy configuration...")
	if err := haproxyMgr.GenerateConfig(cfg); err != nil {
		return fmt.Errorf("failed to generate HAProxy configuration: %w", err)
	}
	fmt.Printf("  ✓ Configuration written to %s\n", haproxyMgr.ConfigPath)

	// Enable HAProxy service
	fmt.Println("  Enabling HAProxy service...")
	if err := haproxyMgr.Enable(); err != nil {
		return fmt.Errorf("failed to enable HAProxy service: %w", err)
	}
	fmt.Println("  ✓ HAProxy service enabled")

	// Restart HAProxy to apply new configuration
	fmt.Println("  Restarting HAProxy...")
	if err := haproxyMgr.Restart(); err != nil {
		return fmt.Errorf("failed to restart HAProxy: %w", err)
	}
	fmt.Println("  ✓ HAProxy restarted successfully")

	return nil
}

// applyIntercept sets up PREROUTING port interception
func applyIntercept(cfg *config.Config) error {
	// Create firewall manager
	fwMgr, err := firewall.NewManager()
	if err != nil {
		return fmt.Errorf("failed to create firewall manager: %w", err)
	}

	fmt.Printf("  Detected firewall type: %s\n", fwMgr.Type)

	// Apply port interception
	fmt.Println("  Setting up PREROUTING redirect rules...")
	if err := fwMgr.InterceptPorts(cfg); err != nil {
		return fmt.Errorf("failed to setup port interception: %w", err)
	}
	fmt.Println("  ✓ Port interception rules applied")

	return nil
}

// rollbackV2 attempts to rollback applied changes
func rollbackV2(appliedRouting, appliedHAProxy, appliedIntercept bool) {
	if appliedIntercept {
		fmt.Println("  Rolling back port interception...")
		fwMgr, err := firewall.NewManager()
		if err == nil {
			if err := fwMgr.RemoveIntercept(); err != nil {
				fmt.Printf("  ⚠️  Failed to remove intercept rules: %v\n", err)
			} else {
				fmt.Println("  ✓ Port interception removed")
			}
		}
	}

	if appliedHAProxy {
		fmt.Println("  Rolling back HAProxy...")
		// Stop HAProxy
		if err := exec.Command("systemctl", "stop", "haproxy").Run(); err != nil {
			fmt.Printf("  ⚠️  Failed to stop HAProxy: %v\n", err)
		} else {
			fmt.Println("  ✓ HAProxy stopped")
		}
	}

	if appliedRouting {
		fmt.Println("  Rolling back routing...")
		routingMgr, err := routing.NewManager()
		if err == nil {
			// Disable MASQUERADE
			if err := routingMgr.DisableMasquerade(); err != nil {
				fmt.Printf("  ⚠️  Failed to disable MASQUERADE: %v\n", err)
			}
			// Disable IP forwarding
			if err := routingMgr.DisableIPForward(); err != nil {
				fmt.Printf("  ⚠️  Failed to disable IP forwarding: %v\n", err)
			} else {
				fmt.Println("  ✓ Routing disabled")
			}
		}
	}

	fmt.Println("✓ Rollback completed")
	fmt.Println("\nℹ️  Some changes may require manual cleanup")
}

// showV2ConfigurationSummary displays the v2 configuration that will be applied
func showV2ConfigurationSummary(cfg *config.Config) {
	fmt.Println("\n📋 Configuration Summary (v2.0):")
	fmt.Println("=================================")

	// Admin section
	if len(cfg.Admin.Sources) > 0 {
		fmt.Printf("\nAdmin Access:\n")
		fmt.Printf("  Sources: %s\n", strings.Join(cfg.Admin.Sources, ", "))
		fmt.Printf("  Ports: %v\n", cfg.Admin.Ports)
	}

	// Interfaces
	fmt.Printf("\nInterfaces:\n")
	for logical, physical := range cfg.Interfaces {
		fmt.Printf("  %s → %s\n", logical, physical)
	}

	// Routing
	if cfg.Routing != nil && cfg.Routing.Enabled {
		fmt.Printf("\nRouting:\n")
		fmt.Printf("  IP Forwarding: %v\n", cfg.Routing.IPForward)
		if cfg.Routing.Masquerade.Enabled {
			fmt.Printf("  MASQUERADE: enabled on %s\n", cfg.Routing.Masquerade.Interface)
		}
	}

	// Proxy
	if cfg.Proxy != nil && cfg.Proxy.Enabled {
		fmt.Printf("\nProxy:\n")
		fmt.Printf("  Mode: %s\n", cfg.Proxy.Mode)
		fmt.Printf("  Type: %s\n", cfg.Proxy.Type)
		fmt.Printf("  Bind: %s:%d\n", cfg.Proxy.Bind.Interface, cfg.Proxy.Bind.Port)

		if cfg.Proxy.Intercept != nil {
			fmt.Printf("  Intercept from: %s\n", cfg.Proxy.Intercept.FromInterface)
			fmt.Printf("  Intercept ports: %v\n", cfg.Proxy.Intercept.Ports)
		}

		if cfg.Proxy.Backends != nil && len(cfg.Proxy.Backends.Servers) > 0 {
			fmt.Printf("  Backend servers: %d\n", len(cfg.Proxy.Backends.Servers))
		}

		if cfg.Proxy.SSL != nil && cfg.Proxy.SSL.Enabled {
			fmt.Printf("  SSL: enabled\n")
		}

		if cfg.Proxy.Logging != nil && cfg.Proxy.Logging.Enabled {
			fmt.Printf("  Logging: %s format\n", cfg.Proxy.Logging.Format)
		}
	}

	// Firewall
	if cfg.Firewall != nil && cfg.Firewall.Enabled {
		fmt.Printf("\nFirewall:\n")
		fmt.Printf("  Default policy: %s\n", cfg.Firewall.DefaultPolicy)
		if len(cfg.Firewall.Rules) > 0 {
			fmt.Printf("  Rules: %d configured\n", len(cfg.Firewall.Rules))
		}
	}

	fmt.Println()
}

// confirmV2Apply prompts the user to confirm applying v2 configuration
func confirmV2Apply() error {
	fmt.Print("\nApply this v2.0 configuration? (yes/no): ")
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
