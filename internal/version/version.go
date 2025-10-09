package version

import "runtime"

var (
	// Version is the semantic version (set by linker flags)
	Version = "dev"

	// GitCommit is the git commit hash (set by linker flags)
	GitCommit = "unknown"

	// BuildDate is the build timestamp (set by linker flags)
	BuildDate = "unknown"

	// GoVersion is the Go version used to build
	GoVersion = runtime.Version()
)
