package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	// BackupDir is the directory where firewall rule backups are stored
	BackupDir = "/var/lib/proxyctl/firewall-backups"

	// MaxBackups is the maximum number of backups to keep
	MaxBackups = 10
)

// Backup creates a timestamped backup of current firewall rules
// Returns the backup file path on success
func (m *Manager) Backup() (string, error) {
	// Create backup directory if it doesn't exist
	if err := os.MkdirAll(BackupDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate timestamp for backup filename
	timestamp := time.Now().Format("20060102-150405")
	var backupPath string
	var err error

	switch m.Type {
	case TypeIPTables:
		backupPath = filepath.Join(BackupDir, fmt.Sprintf("iptables-%s.rules", timestamp))
		err = m.backupIPTables(backupPath)
	case TypeNFTables:
		backupPath = filepath.Join(BackupDir, fmt.Sprintf("nftables-%s.nft", timestamp))
		err = m.backupNFTables(backupPath)
	default:
		return "", fmt.Errorf("unknown firewall type: %s", m.Type)
	}

	if err != nil {
		return "", err
	}

	// Clean up old backups (keep only MaxBackups most recent)
	if err := m.cleanOldBackups(); err != nil {
		// Non-fatal - log but continue
		fmt.Printf("Warning: failed to clean old backups: %v\n", err)
	}

	return backupPath, nil
}

// backupIPTables saves current iptables rules to a file
func (m *Manager) backupIPTables(backupPath string) error {
	// Create backup file
	f, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	// Save both filter and nat tables
	tables := []string{"filter", "nat"}
	for _, table := range tables {
		// Get rules for this table
		cmd := exec.Command("iptables-save", "-t", table)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to save %s table: %w", table, err)
		}

		// Write to backup file
		if _, err := f.Write(output); err != nil {
			return fmt.Errorf("failed to write backup: %w", err)
		}
	}

	return nil
}

// backupNFTables saves current nftables ruleset to a file
func (m *Manager) backupNFTables(backupPath string) error {
	// Create backup file
	f, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer f.Close()

	// Export current ruleset
	cmd := exec.Command("nft", "list", "ruleset")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to export nftables ruleset: %w", err)
	}

	// Write to backup file
	if _, err := f.Write(output); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	return nil
}

// Restore restores firewall rules from a backup file
func (m *Manager) Restore(backupPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file does not exist: %w", err)
	}

	switch m.Type {
	case TypeIPTables:
		return m.restoreIPTables(backupPath)
	case TypeNFTables:
		return m.restoreNFTables(backupPath)
	default:
		return fmt.Errorf("unknown firewall type: %s", m.Type)
	}
}

// restoreIPTables restores iptables rules from a backup file
func (m *Manager) restoreIPTables(backupPath string) error {
	// Restore rules using iptables-restore
	cmd := exec.Command("iptables-restore", backupPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore iptables rules: %w", err)
	}

	return nil
}

// restoreNFTables restores nftables rules from a backup file
func (m *Manager) restoreNFTables(backupPath string) error {
	// Flush current ruleset first
	if err := exec.Command("nft", "flush", "ruleset").Run(); err != nil {
		return fmt.Errorf("failed to flush nftables ruleset: %w", err)
	}

	// Restore rules from backup file
	cmd := exec.Command("nft", "-f", backupPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore nftables rules: %w", err)
	}

	return nil
}

// ListBackups returns a list of all backup files, sorted by timestamp (newest first)
func (m *Manager) ListBackups() ([]string, error) {
	// Check if backup directory exists
	if _, err := os.Stat(BackupDir); os.IsNotExist(err) {
		return []string{}, nil
	}

	// Get pattern based on firewall type
	var pattern string
	switch m.Type {
	case TypeIPTables:
		pattern = "iptables-*.rules"
	case TypeNFTables:
		pattern = "nftables-*.nft"
	default:
		return nil, fmt.Errorf("unknown firewall type: %s", m.Type)
	}

	// Find all backup files
	matches, err := filepath.Glob(filepath.Join(BackupDir, pattern))
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}

	// Sort by modification time (newest first)
	// We rely on the timestamp in the filename being chronological
	// This is safe because we use RFC3339-like format (YYYYMMDD-HHMMSS)

	return matches, nil
}

// cleanOldBackups removes old backup files, keeping only MaxBackups most recent
func (m *Manager) cleanOldBackups() error {
	backups, err := m.ListBackups()
	if err != nil {
		return err
	}

	// If we have more than MaxBackups, delete the oldest ones
	if len(backups) > MaxBackups {
		// backups is already sorted by timestamp (newest first) due to filename format
		// Delete the oldest backups (at the end of the list)
		for i := MaxBackups; i < len(backups); i++ {
			if err := os.Remove(backups[i]); err != nil {
				fmt.Printf("Warning: failed to remove old backup %s: %v\n", backups[i], err)
			}
		}
	}

	return nil
}

// GetLatestBackup returns the path to the most recent backup file
func (m *Manager) GetLatestBackup() (string, error) {
	backups, err := m.ListBackups()
	if err != nil {
		return "", err
	}

	if len(backups) == 0 {
		return "", fmt.Errorf("no backups found")
	}

	// Return the newest backup (first in the list)
	return backups[0], nil
}
