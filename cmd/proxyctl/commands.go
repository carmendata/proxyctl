package main

import (
	"flag"
	"fmt"
)

// Command represents a CLI command with subcommands and flags
type Command struct {
	Name        string
	Description string
	LongDesc    string
	Flags       *flag.FlagSet
	Run         func(args []string) error
	Subcommands map[string]*Command
	Parent      *Command
}

// NewCommand creates a new command
func NewCommand(name, description string) *Command {
	return &Command{
		Name:        name,
		Description: description,
		Flags:       flag.NewFlagSet(name, flag.ContinueOnError),
		Subcommands: make(map[string]*Command),
	}
}

// AddCommand adds a subcommand
func (c *Command) AddCommand(sub *Command) {
	sub.Parent = c
	c.Subcommands[sub.Name] = sub
}

// Execute runs the command with the given arguments
func (c *Command) Execute(args []string) error {
	// Filter out global flags from args
	filteredArgs := filterGlobalFlags(args)

	// Set custom usage function
	c.Flags.Usage = func() {
		printHelp(c)
	}

	// Parse flags
	if err := c.Flags.Parse(filteredArgs); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	// Get remaining args after flags
	remainingArgs := c.Flags.Args()

	// Check for help flag
	if len(remainingArgs) > 0 && (remainingArgs[0] == "help" || remainingArgs[0] == "-h" || remainingArgs[0] == "--help") {
		printHelp(c)
		return nil
	}

	// If there are subcommands, route to them
	if len(remainingArgs) > 0 && len(c.Subcommands) > 0 {
		subCmdName := remainingArgs[0]
		if subCmd, ok := c.Subcommands[subCmdName]; ok {
			return subCmd.Execute(remainingArgs[1:])
		}
		return fmt.Errorf("unknown command: %s\nRun '%s --help' for usage", subCmdName, c.FullName())
	}

	// If no Run function and we have subcommands, show help
	if c.Run == nil && len(c.Subcommands) > 0 {
		printHelp(c)
		return nil
	}

	// If no Run function and no subcommands, error
	if c.Run == nil {
		return fmt.Errorf("command %s has no implementation", c.Name)
	}

	// Execute the command
	return c.Run(remainingArgs)
}

// FullName returns the full command name including parents
func (c *Command) FullName() string {
	if c.Parent == nil {
		return c.Name
	}
	return c.Parent.FullName() + " " + c.Name
}

// buildCommands creates the command tree based on mode
func buildCommands(mode string) *Command {
	var root *Command

	switch mode {
	case "egress":
		root = NewCommand("egressctl", "Manage HAProxy egress proxy (outbound traffic)")
		root.LongDesc = `egressctl - HAProxy Egress Proxy Management CLI

Mode: egress

This binary manages the egress proxy (outbound traffic) configuration.

Configuration is loaded from:
  - /etc/proxyctl/egress.json (default)
  - --config flag (override)
  - Environment variables (PROXYCTL_*)

For more information: https://github.com/carmendata/proxyctl`
		addEgressCommands(root)

	case "ingress":
		root = NewCommand("ingressctl", "Manage HAProxy ingress proxy (inbound traffic)")
		root.LongDesc = `ingressctl - HAProxy Ingress Proxy Management CLI

Mode: ingress

This binary manages the ingress proxy (inbound traffic) configuration.

Configuration is loaded from:
  - /etc/proxyctl/ingress.json (default)
  - --config flag (override)
  - Environment variables (PROXYCTL_*)

For more information: https://github.com/carmendata/proxyctl`
		addIngressCommands(root)

	default: // proxyctl
		root = NewCommand("proxyctl", "Manage HAProxy proxy infrastructure")
		root.LongDesc = `proxyctl - HAProxy Proxy Management CLI

Mode: proxyctl

This binary operates in different modes based on how it's called:
  - egressctl:  Manage egress proxy (outbound traffic)
  - ingressctl: Manage ingress proxy (inbound traffic)
  - proxyctl:   Explicit mode selection (use subcommands)

Configuration is loaded from:
  - /etc/proxyctl/{mode}.json (default)
  - --config flag (override)
  - Environment variables (PROXYCTL_*)

For more information: https://github.com/carmendata/proxyctl`

		// Add mode-specific command groups
		egressGroup := NewCommand("egress", "Egress proxy commands")
		addEgressCommands(egressGroup)
		root.AddCommand(egressGroup)

		ingressGroup := NewCommand("ingress", "Ingress proxy commands")
		addIngressCommands(ingressGroup)
		root.AddCommand(ingressGroup)
	}

	// Add version command to all modes
	root.AddCommand(createVersionCommand())

	return root
}

// addEgressCommands adds egress-specific commands
func addEgressCommands(root *Command) {
	// ACL command
	aclCmd := NewCommand("acl", "Manage egress ACL")
	aclCmd.LongDesc = "Manage the egress proxy Access Control List (ACL)"

	// ACL add subcommand
	aclAddCmd := NewCommand("add", "Add IP/CIDR to ACL")
	aclAddCmd.Run = func(args []string) error {
		return runACLAdd(args)
	}
	aclCmd.AddCommand(aclAddCmd)

	// ACL remove subcommand
	aclRemoveCmd := NewCommand("remove", "Remove IP/CIDR from ACL")
	aclRemoveCmd.Run = func(args []string) error {
		return runACLRemove(args)
	}
	aclCmd.AddCommand(aclRemoveCmd)

	// ACL list subcommand
	aclListCmd := NewCommand("list", "List all ACL entries")
	aclListCmd.Run = func(args []string) error {
		return runACLList(args)
	}
	aclCmd.AddCommand(aclListCmd)

	// ACL reload subcommand
	aclReloadCmd := NewCommand("reload", "Reload HAProxy configuration")
	aclReloadCmd.Run = func(args []string) error {
		return runACLReload(args)
	}
	aclCmd.AddCommand(aclReloadCmd)

	root.AddCommand(aclCmd)

	// Status command
	statusCmd := NewCommand("status", "Show egress proxy status")
	statusCmd.Run = func(args []string) error {
		return runStatus(args)
	}
	root.AddCommand(statusCmd)

	// Server command
	serverCmd := NewCommand("server", "Manage internal servers")

	// Server configure subcommand
	serverConfigureCmd := NewCommand("configure", "Configure egress proxy routing")
	serverConfigureCmd.Run = func(args []string) error {
		return runServerConfigure(args)
	}
	serverCmd.AddCommand(serverConfigureCmd)

	// Server remove subcommand
	serverRemoveCmd := NewCommand("remove", "Remove egress proxy configuration")
	serverRemoveCmd.Run = func(args []string) error {
		return runServerRemove(args)
	}
	serverCmd.AddCommand(serverRemoveCmd)

	// Server check subcommand
	serverCheckCmd := NewCommand("check", "Check remote server configuration")
	serverCheckCmd.Run = func(args []string) error {
		return runServerCheck(args)
	}
	serverCmd.AddCommand(serverCheckCmd)

	root.AddCommand(serverCmd)

	// Logger command
	loggerCmd := NewCommand("logger", "Manage connection logger")

	// Logger install subcommand
	loggerInstallCmd := NewCommand("install", "Install connection logger")
	loggerInstallCmd.Run = func(args []string) error {
		return runLoggerInstall(args)
	}
	loggerCmd.AddCommand(loggerInstallCmd)

	// Logger remove subcommand
	loggerRemoveCmd := NewCommand("remove", "Remove connection logger")
	loggerRemoveCmd.Run = func(args []string) error {
		return runLoggerRemove(args)
	}
	loggerCmd.AddCommand(loggerRemoveCmd)

	// Logger analyze subcommand
	loggerAnalyzeCmd := NewCommand("analyze", "Analyze connection logs")
	// Add flags to the command's FlagSet
	var analyzeDate string
	loggerAnalyzeCmd.Flags.StringVar(&analyzeDate, "date", "", "Analyze specific date (YYYYMMDD format, e.g., 20251012)")
	loggerAnalyzeCmd.Run = func(args []string) error {
		return runLoggerAnalyze(analyzeDate, args)
	}
	loggerCmd.AddCommand(loggerAnalyzeCmd)

	root.AddCommand(loggerCmd)

	// Firewall command (v0.8.0+)
	firewallCmd := NewCommand("firewall", "Manage firewall rules")
	firewallCmd.LongDesc = "Manage INPUT filtering and OUTPUT redirect firewall rules"

	// Firewall apply subcommand
	firewallApplyCmd := NewCommand("apply", "Apply firewall rules from configuration")
	firewallApplyCmd.Run = func(args []string) error {
		return runFirewallApply(args)
	}
	firewallCmd.AddCommand(firewallApplyCmd)

	// Firewall remove subcommand
	firewallRemoveCmd := NewCommand("remove", "Remove all proxyctl firewall rules")
	firewallRemoveCmd.Run = func(args []string) error {
		return runFirewallRemove(args)
	}
	firewallCmd.AddCommand(firewallRemoveCmd)

	// Firewall status subcommand
	firewallStatusCmd := NewCommand("status", "Show firewall configuration status")
	firewallStatusCmd.Run = func(args []string) error {
		return runFirewallStatus(args)
	}
	firewallCmd.AddCommand(firewallStatusCmd)

	// Firewall restore subcommand
	firewallRestoreCmd := NewCommand("restore", "Restore firewall rules from backup")
	firewallRestoreCmd.Run = func(args []string) error {
		return runFirewallRestore(args)
	}
	firewallCmd.AddCommand(firewallRestoreCmd)

	root.AddCommand(firewallCmd)

	// Daemon command
	daemonCmd := NewCommand("daemon", "Daemon operations")
	daemonCmd.Run = func(args []string) error {
		fmt.Println("Daemon operations coming soon...")
		return nil
	}
	root.AddCommand(daemonCmd)
}

// addIngressCommands adds ingress-specific commands
func addIngressCommands(root *Command) {
	// Backend command
	backendCmd := NewCommand("backend", "Manage ingress backends")
	backendCmd.LongDesc = "Manage backend servers for the ingress proxy"
	backendCmd.Run = func(args []string) error {
		fmt.Println("Ingress backend commands coming soon...")
		fmt.Println("Available subcommands: add, remove, list, sync")
		return nil
	}
	root.AddCommand(backendCmd)

	// Status command
	statusCmd := NewCommand("status", "Show ingress proxy status")
	statusCmd.Run = func(args []string) error {
		fmt.Println("Ingress proxy status coming soon...")
		return nil
	}
	root.AddCommand(statusCmd)

	// SSL command
	sslCmd := NewCommand("ssl", "Manage SSL certificates")
	sslCmd.Run = func(args []string) error {
		fmt.Println("SSL management coming soon...")
		return nil
	}
	root.AddCommand(sslCmd)

	// Routing command
	routingCmd := NewCommand("routing", "Manage routing rules")
	routingCmd.Run = func(args []string) error {
		fmt.Println("Routing management coming soon...")
		return nil
	}
	root.AddCommand(routingCmd)

	// Daemon command
	daemonCmd := NewCommand("daemon", "Daemon operations")
	daemonCmd.Run = func(args []string) error {
		fmt.Println("Daemon operations coming soon...")
		return nil
	}
	root.AddCommand(daemonCmd)
}

// createVersionCommand creates the version command
func createVersionCommand() *Command {
	cmd := NewCommand("version", "Print version information")
	cmd.Run = func(args []string) error {
		printVersion()
		return nil
	}
	return cmd
}

// filterGlobalFlags removes global flags from args
func filterGlobalFlags(args []string) []string {
	filtered := []string{}
	skipNext := false

	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		// Check if this is a global flag
		switch arg {
		case "--config":
			// Skip this flag and its value
			skipNext = true
			continue
		case "--verbose", "-v", "--json", "-j":
			// Skip this flag
			continue
		default:
			// Keep this arg
			filtered = append(filtered, arg)
		}
	}

	return filtered
}
