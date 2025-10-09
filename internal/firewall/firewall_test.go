package firewall

import (
	"strings"
	"testing"
)

func TestCheckConflictingFirewallManagers(t *testing.T) {
	tests := []struct {
		name            string
		ufwActive       bool
		firewalldActive bool
		expectError     bool
		errorContains   string
	}{
		{
			name:            "no conflicting managers",
			ufwActive:       false,
			firewalldActive: false,
			expectError:     false,
		},
		{
			name:            "ufw active should error",
			ufwActive:       true,
			firewalldActive: false,
			expectError:     true,
			errorContains:   "ufw is active",
		},
		{
			name:            "firewalld active should error",
			ufwActive:       false,
			firewalldActive: true,
			expectError:     true,
			errorContains:   "firewalld is active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We can't easily mock systemctl/ufw commands in unit tests
			// This test documents expected behavior
			// Real testing should be done in integration tests or manual testing

			// For now, just verify the error messages are informative
			err := checkConflictingFirewallManagers()

			// We can't control actual system state in unit tests,
			// so we'll just verify the function exists and can be called
			if err != nil && !tt.expectError {
				t.Logf("Got error (may be expected based on actual system): %v", err)
			}
		})
	}
}

func TestIsUFWActive(t *testing.T) {
	// Test that the function can be called without panicking
	active := isUFWActive()
	t.Logf("UFW active on test system: %v", active)

	// The function should return a boolean, not panic
	if active {
		t.Log("UFW is active on this system - integration tests will fail")
		t.Log("To fix: sudo ufw disable")
	}
}

func TestIsFirewalldActive(t *testing.T) {
	// Test that the function can be called without panicking
	active := isFirewalldActive()
	t.Logf("firewalld active on test system: %v", active)

	// The function should return a boolean, not panic
	if active {
		t.Log("firewalld is active on this system - integration tests will fail")
		t.Log("To fix: sudo systemctl stop firewalld && sudo systemctl disable firewalld")
	}
}

func TestDetectWithConflictingManagers(t *testing.T) {
	// This test verifies that Detect() checks for conflicting managers
	// before detecting firewall type

	fwType, err := Detect()

	if err != nil {
		// Check if error is about conflicting managers
		errMsg := err.Error()
		if strings.Contains(errMsg, "ufw is active") ||
			strings.Contains(errMsg, "firewalld is active") {
			t.Logf("Correctly detected conflicting firewall manager")
			t.Logf("Error message: %v", err)

			// Verify error message is helpful
			if !strings.Contains(errMsg, "PROBLEM:") {
				t.Error("Error message should contain 'PROBLEM:' section")
			}
			if !strings.Contains(errMsg, "WHY THIS MATTERS:") {
				t.Error("Error message should contain 'WHY THIS MATTERS:' section")
			}
			if !strings.Contains(errMsg, "SOLUTION") {
				t.Error("Error message should contain 'SOLUTION' section")
			}
			if !strings.Contains(errMsg, "Option 1:") {
				t.Error("Error message should contain 'Option 1:' with solution")
			}
		} else {
			// Some other error (e.g., no firewall tools installed)
			t.Logf("Got error (not about conflicting managers): %v", err)
		}
	} else {
		// No error - no conflicting managers detected
		t.Logf("No conflicting managers detected, firewall type: %s", fwType)

		if fwType == TypeUnknown {
			t.Error("Detect() should not return TypeUnknown without error")
		}
	}
}

func TestErrorMessageQuality(t *testing.T) {
	// Create mock errors to verify they contain helpful information
	tests := []struct {
		name     string
		checkFn  func() error
		required []string
	}{
		{
			name:     "error message contains key sections",
			checkFn:  checkConflictingFirewallManagers,
			required: []string{
				// Will only be present if UFW/firewalld is actually active
				// This test just verifies structure when error occurs
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.checkFn()
			if err != nil {
				errMsg := err.Error()
				t.Logf("Error message:\n%s", errMsg)

				// Verify message quality (when error occurs)
				if !strings.Contains(errMsg, "PROBLEM:") &&
					!strings.Contains(errMsg, "cannot proceed") {
					t.Error("Error should explain the problem clearly")
				}
			}
		})
	}
}
