package acl

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Manager handles ACL file operations
type Manager struct {
	ACLFile string
}

// NewManager creates a new ACL manager
func NewManager(aclFile string) *Manager {
	return &Manager{
		ACLFile: aclFile,
	}
}

// Add adds an IP or CIDR to the ACL file (idempotent)
func (m *Manager) Add(ip string) error {
	// Check if ACL file exists
	if _, err := os.Stat(m.ACLFile); os.IsNotExist(err) {
		return fmt.Errorf("ACL file not found: %s", m.ACLFile)
	}

	// Check if already exists
	exists, err := m.contains(ip)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already exists, idempotent
	}

	// Append to ACL file
	f, err := os.OpenFile(m.ACLFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open ACL file: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintln(f, ip); err != nil {
		return fmt.Errorf("failed to write to ACL file: %w", err)
	}

	return nil
}

// Remove removes an IP or CIDR from the ACL file
func (m *Manager) Remove(ip string) error {
	// Check if ACL file exists
	if _, err := os.Stat(m.ACLFile); os.IsNotExist(err) {
		return fmt.Errorf("ACL file not found: %s", m.ACLFile)
	}

	// Read all lines
	lines, err := m.readLines()
	if err != nil {
		return err
	}

	// Filter out the IP
	var filtered []string
	found := false
	for _, line := range lines {
		if line == ip {
			found = true
			continue
		}
		filtered = append(filtered, line)
	}

	if !found {
		return fmt.Errorf("IP not found in ACL: %s", ip)
	}

	// Write back to file
	return m.writeLines(filtered)
}

// List returns all non-comment, non-empty entries from the ACL file
func (m *Manager) List() ([]string, error) {
	// Check if ACL file exists
	if _, err := os.Stat(m.ACLFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("ACL file not found: %s", m.ACLFile)
	}

	lines, err := m.readLines()
	if err != nil {
		return nil, err
	}

	var entries []string
	for _, line := range lines {
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entries = append(entries, trimmed)
	}

	return entries, nil
}

// Reload reloads HAProxy configuration using systemctl
func (m *Manager) Reload() error {
	cmd := exec.Command("systemctl", "reload", "haproxy")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to reload HAProxy: %w\nOutput: %s", err, string(output))
	}
	return nil
}

// contains checks if an IP exists in the ACL file
func (m *Manager) contains(ip string) (bool, error) {
	file, err := os.Open(m.ACLFile)
	if err != nil {
		return false, fmt.Errorf("failed to open ACL file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() == ip {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("error reading ACL file: %w", err)
	}

	return false, nil
}

// readLines reads all lines from the ACL file
func (m *Manager) readLines() ([]string, error) {
	file, err := os.Open(m.ACLFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open ACL file: %w", err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading ACL file: %w", err)
	}

	return lines, nil
}

// writeLines writes lines to the ACL file
func (m *Manager) writeLines(lines []string) error {
	file, err := os.Create(m.ACLFile)
	if err != nil {
		return fmt.Errorf("failed to create ACL file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return fmt.Errorf("failed to write to ACL file: %w", err)
		}
	}

	return writer.Flush()
}
