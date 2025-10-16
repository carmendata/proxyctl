package pkgmgr

import (
	"fmt"
	"os/exec"
)

// InstallPackage attempts to install a package using the system's package manager
// Supports apt-get (Debian/Ubuntu), yum (RHEL/CentOS), and dnf (Fedora/RHEL 8+)
func InstallPackage(packageName string) error {
	// Try apt-get (Debian/Ubuntu)
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd := exec.Command("apt-get", "update")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}

		cmd = exec.Command("apt-get", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("apt-get install failed: %w", err)
		}
		return nil
	}

	// Try yum (RHEL/CentOS)
	if _, err := exec.LookPath("yum"); err == nil {
		cmd := exec.Command("yum", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("yum install failed: %w", err)
		}
		return nil
	}

	// Try dnf (Fedora/RHEL 8+)
	if _, err := exec.LookPath("dnf"); err == nil {
		cmd := exec.Command("dnf", "install", "-y", packageName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dnf install failed: %w", err)
		}
		return nil
	}

	return fmt.Errorf("no supported package manager found (tried apt-get, yum, dnf)")
}
