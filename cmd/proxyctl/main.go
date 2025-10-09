package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	// Global flags
	globalConfig  *string
	globalVerbose *bool
	globalJSON    *bool

	// Global state
	cfgFile string
	mode    string
	verbose bool
	jsonOut bool
)

func main() {
	// Detect mode from binary name (symlink detection)
	mode = detectMode(os.Args[0])

	// Parse global flags
	parseGlobalFlagsMain()

	// Build command tree
	root := buildCommands(mode)

	// Execute command
	if err := root.Execute(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// detectMode determines operating mode from argv[0]
func detectMode(arg0 string) string {
	base := strings.ToLower(filepath.Base(arg0))

	if strings.Contains(base, "egress") {
		return "egress"
	}
	if strings.Contains(base, "ingress") {
		return "ingress"
	}
	return "proxyctl"
}

// parseGlobalFlagsMain parses global flags from command line
func parseGlobalFlagsMain() {
	// Initialize global flag pointers
	configDefault := ""
	verboseDefault := false
	jsonDefault := false

	globalConfig = &configDefault
	globalVerbose = &verboseDefault
	globalJSON = &jsonDefault

	// Manually parse global flags
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "--config":
			if i+1 < len(args) {
				*globalConfig = args[i+1]
				i++
			}
		case "--verbose", "-v":
			*globalVerbose = true
		case "--json", "-j":
			*globalJSON = true
		}
	}

	// Store parsed values in global variables
	cfgFile = *globalConfig
	verbose = *globalVerbose
	jsonOut = *globalJSON
}
