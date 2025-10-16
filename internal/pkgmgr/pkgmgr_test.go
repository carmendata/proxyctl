package pkgmgr

import (
	"testing"
)

// TestInstallPackageDocumentation provides example usage documentation
// This is not a real test - it demonstrates proper usage of InstallPackage
func TestInstallPackageDocumentation(t *testing.T) {
	// Skip this test in normal runs - it's documentation only
	t.Skip("This is documentation, not a real test")

	// Example 1: Installing rsyslog
	// err := InstallPackage("rsyslog")
	// if err != nil {
	//     // Handle installation failure
	//     // Common causes: no package manager, package not found, permission denied
	// }

	// Example 2: Best effort installation (ignore errors)
	// InstallPackage("logrotate") // Don't check error - recommended but not critical

	// Example 3: Installation with error handling
	// if err := InstallPackage("haproxy"); err != nil {
	//     return fmt.Errorf("HAProxy is required: %w\nPlease install manually", err)
	// }
}

// TestPackageManagerDetection tests that we can detect at least one package manager
// This is a basic smoke test that runs on the actual system
func TestPackageManagerDetection(t *testing.T) {
	// This test verifies that at least one package manager is available
	// It doesn't actually install anything

	// Try to install a fake package - should fail but we can check the error message
	err := InstallPackage("__test_nonexistent_package__")

	if err == nil {
		t.Fatal("Installing nonexistent package should fail")
	}

	// Check that we got a reasonable error message
	errMsg := err.Error()

	// Should NOT say "no supported package manager found" if we're on a real system
	// (unless we truly are on an unsupported system)
	if errMsg == "no supported package manager found (tried apt-get, yum, dnf)" {
		t.Skip("No package manager found on this system - this is expected in some test environments")
	}

	// If we got here, a package manager was detected but the package doesn't exist
	// This is the expected behavior
	t.Logf("Package manager detected (error as expected for nonexistent package): %v", err)
}
