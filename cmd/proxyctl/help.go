package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/carmendata/proxyctl/internal/version"
)

// printHelp prints help text for a command
func printHelp(cmd *Command) {
	w := os.Stdout

	// Print description
	if cmd.LongDesc != "" {
		fmt.Fprintln(w, cmd.LongDesc)
	} else {
		fmt.Fprintf(w, "%s - %s\n", cmd.Name, cmd.Description)
	}
	fmt.Fprintln(w)

	// Print usage
	fmt.Fprintf(w, "Usage:\n")
	if len(cmd.Subcommands) > 0 {
		fmt.Fprintf(w, "  %s [flags] <command> [args]\n", cmd.FullName())
	} else {
		fmt.Fprintf(w, "  %s [flags] [args]\n", cmd.FullName())
	}
	fmt.Fprintln(w)

	// Print available commands
	if len(cmd.Subcommands) > 0 {
		fmt.Fprintln(w, "Available Commands:")

		// Sort commands alphabetically
		names := make([]string, 0, len(cmd.Subcommands))
		for name := range cmd.Subcommands {
			names = append(names, name)
		}
		sort.Strings(names)

		// Find max name length for alignment
		maxLen := 0
		for _, name := range names {
			if len(name) > maxLen {
				maxLen = len(name)
			}
		}

		// Print commands
		for _, name := range names {
			subCmd := cmd.Subcommands[name]
			padding := strings.Repeat(" ", maxLen-len(name)+2)
			fmt.Fprintf(w, "  %s%s%s\n", name, padding, subCmd.Description)
		}
		fmt.Fprintln(w)
	}

	// Print flags
	hasFlags := false
	cmd.Flags.VisitAll(func(f *flag.Flag) {
		hasFlags = true
	})

	if hasFlags || cmd.Parent == nil {
		fmt.Fprintln(w, "Flags:")

		// Print command-specific flags
		cmd.Flags.VisitAll(func(f *flag.Flag) {
			printFlag(w, f)
		})

		// If this is root command, show global flags
		if cmd.Parent == nil {
			if globalVerbose != nil {
				fmt.Fprintf(w, "  -v, --verbose        verbose output\n")
			}
			if globalJSON != nil {
				fmt.Fprintf(w, "  -j, --json           output in JSON format\n")
			}
			if globalConfig != nil {
				fmt.Fprintf(w, "  --config string      config file (default: /etc/proxyctl/%s.json)\n", mode)
			}
		}

		fmt.Fprintln(w)
	}

	// Print usage examples
	fmt.Fprintf(w, "Use \"%s <command> --help\" for more information about a command.\n", cmd.FullName())
}

// printFlag prints a single flag with formatting
func printFlag(w *os.File, f *flag.Flag) {
	// Format: -s, --long type    description (default: value)
	name := f.Name

	// Add short form if applicable
	shortForm := ""
	if len(name) > 1 {
		shortForm = fmt.Sprintf("-%c, ", name[0])
	}

	// Determine type
	typeName := ""
	if f.DefValue != "" && f.DefValue != "false" {
		typeName = " " + inferType(f.DefValue)
	}

	// Build flag string
	flagStr := fmt.Sprintf("  %s--%s%s", shortForm, name, typeName)

	// Add padding
	const minPadding = 25
	padding := minPadding - len(flagStr)
	if padding < 1 {
		padding = 1
	}

	// Print flag with description
	fmt.Fprintf(w, "%s%s%s", flagStr, strings.Repeat(" ", padding), f.Usage)

	// Add default value if present
	if f.DefValue != "" && f.DefValue != "false" {
		fmt.Fprintf(w, " (default: %s)", f.DefValue)
	}

	fmt.Fprintln(w)
}

// inferType infers the type name from default value
func inferType(defValue string) string {
	if defValue == "true" || defValue == "false" {
		return ""
	}
	if _, err := fmt.Sscanf(defValue, "%d", new(int)); err == nil {
		return "int"
	}
	if _, err := fmt.Sscanf(defValue, "%f", new(float64)); err == nil {
		return "float"
	}
	return "string"
}

// printVersion prints version information
func printVersion() {
	fmt.Printf("proxyctl %s (%s)\n", version.Version, mode)
	fmt.Printf("Built: %s\n", version.BuildDate)
	fmt.Printf("Commit: %s\n", version.GitCommit)
	fmt.Printf("Go version: %s\n", version.GoVersion)
}

// printUsageError prints a usage error and exits
func printUsageError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
