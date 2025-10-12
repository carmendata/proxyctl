package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// AssertFileExists checks if a file exists at the given path
func AssertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Errorf("expected file to exist at %s, but it does not", path)
	}
}

// AssertFileNotExists checks if a file does not exist at the given path
func AssertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Errorf("expected file to not exist at %s, but it does", path)
	}
}

// AssertFileContent checks if file content matches expected
func AssertFileContent(t *testing.T, path string, expectedContent string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	if string(content) != expectedContent {
		t.Errorf("file content mismatch at %s\nGot:\n%s\nWant:\n%s", path, string(content), expectedContent)
	}
}

// AssertFileContains checks if file contains expected substring
func AssertFileContains(t *testing.T, path string, expectedSubstring string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	if !containsString(string(content), expectedSubstring) {
		t.Errorf("file at %s does not contain expected substring: %s\nContent:\n%s", path, expectedSubstring, string(content))
	}
}

// AssertFilePermissions checks if file has expected permissions
func AssertFilePermissions(t *testing.T, path string, expectedMode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat file %s: %v", path, err)
	}
	if info.Mode().Perm() != expectedMode {
		t.Errorf("file permissions mismatch at %s: got %o, want %o", path, info.Mode().Perm(), expectedMode)
	}
}

// CreateTempDir creates a temporary directory for testing
func CreateTempDir(t *testing.T, pattern string) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// CreateTempFile creates a temporary file with content
func CreateTempFile(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create temp file %s: %v", path, err)
	}
	return path
}

// CreateTempConfigFile creates a temporary config file with JSON content
func CreateTempConfigFile(t *testing.T, dir, filename, jsonContent string) string {
	t.Helper()
	return CreateTempFile(t, dir, filename, jsonContent)
}

// AssertErrorContains checks if error contains expected substring
func AssertErrorContains(t *testing.T, err error, expectedSubstring string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing '%s', but got nil", expectedSubstring)
	}
	if !containsString(err.Error(), expectedSubstring) {
		t.Errorf("expected error to contain '%s', but got: %v", expectedSubstring, err)
	}
}

// AssertNoError checks if error is nil
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected no error, but got: %v", err)
	}
}

// containsString checks if string contains substring
func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr || containsInMiddle(s, substr)))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
