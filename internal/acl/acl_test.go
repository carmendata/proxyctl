package acl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestACLAdd(t *testing.T) {
	tests := []struct {
		name      string
		initial   string
		addIP     string
		wantErr   bool
		wantLines []string
	}{
		{
			name:      "add new IP",
			initial:   "10.0.0.1\n10.0.0.2\n",
			addIP:     "10.0.0.3",
			wantErr:   false,
			wantLines: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:      "add existing IP (idempotent)",
			initial:   "10.0.0.1\n10.0.0.2\n",
			addIP:     "10.0.0.1",
			wantErr:   false,
			wantLines: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:      "add CIDR",
			initial:   "10.0.0.1\n",
			addIP:     "192.168.1.0/24",
			wantErr:   false,
			wantLines: []string{"10.0.0.1", "192.168.1.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp ACL file
			tmpDir := t.TempDir()
			aclFile := filepath.Join(tmpDir, "acl.lst")
			if err := os.WriteFile(aclFile, []byte(tt.initial), 0644); err != nil {
				t.Fatalf("failed to create test ACL file: %v", err)
			}

			// Create manager and add IP
			mgr := NewManager(aclFile)
			err := mgr.Add(tt.addIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("Add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify contents
			entries, err := mgr.List()
			if err != nil {
				t.Fatalf("failed to list ACL entries: %v", err)
			}

			if len(entries) != len(tt.wantLines) {
				t.Errorf("got %d entries, want %d", len(entries), len(tt.wantLines))
			}

			for i, want := range tt.wantLines {
				if i >= len(entries) {
					t.Errorf("missing entry at index %d: %s", i, want)
					continue
				}
				if entries[i] != want {
					t.Errorf("entry[%d] = %s, want %s", i, entries[i], want)
				}
			}
		})
	}
}

func TestACLRemove(t *testing.T) {
	tests := []struct {
		name      string
		initial   string
		removeIP  string
		wantErr   bool
		wantLines []string
	}{
		{
			name:      "remove existing IP",
			initial:   "10.0.0.1\n10.0.0.2\n10.0.0.3\n",
			removeIP:  "10.0.0.2",
			wantErr:   false,
			wantLines: []string{"10.0.0.1", "10.0.0.3"},
		},
		{
			name:      "remove non-existing IP",
			initial:   "10.0.0.1\n10.0.0.2\n",
			removeIP:  "10.0.0.3",
			wantErr:   true,
			wantLines: nil,
		},
		{
			name:      "remove CIDR",
			initial:   "10.0.0.1\n192.168.1.0/24\n10.0.0.2\n",
			removeIP:  "192.168.1.0/24",
			wantErr:   false,
			wantLines: []string{"10.0.0.1", "10.0.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp ACL file
			tmpDir := t.TempDir()
			aclFile := filepath.Join(tmpDir, "acl.lst")
			if err := os.WriteFile(aclFile, []byte(tt.initial), 0644); err != nil {
				t.Fatalf("failed to create test ACL file: %v", err)
			}

			// Create manager and remove IP
			mgr := NewManager(aclFile)
			err := mgr.Remove(tt.removeIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("Remove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify contents
			entries, err := mgr.List()
			if err != nil {
				t.Fatalf("failed to list ACL entries: %v", err)
			}

			if len(entries) != len(tt.wantLines) {
				t.Errorf("got %d entries, want %d", len(entries), len(tt.wantLines))
			}

			for i, want := range tt.wantLines {
				if i >= len(entries) {
					t.Errorf("missing entry at index %d: %s", i, want)
					continue
				}
				if entries[i] != want {
					t.Errorf("entry[%d] = %s, want %s", i, entries[i], want)
				}
			}
		})
	}
}

func TestACLList(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantLines []string
	}{
		{
			name:      "simple list",
			content:   "10.0.0.1\n10.0.0.2\n10.0.0.3\n",
			wantLines: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:      "list with comments",
			content:   "# Comment\n10.0.0.1\n# Another comment\n10.0.0.2\n",
			wantLines: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:      "list with empty lines",
			content:   "10.0.0.1\n\n10.0.0.2\n\n\n10.0.0.3\n",
			wantLines: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:      "empty file",
			content:   "",
			wantLines: []string{},
		},
		{
			name:      "only comments",
			content:   "# Comment 1\n# Comment 2\n",
			wantLines: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp ACL file
			tmpDir := t.TempDir()
			aclFile := filepath.Join(tmpDir, "acl.lst")
			if err := os.WriteFile(aclFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to create test ACL file: %v", err)
			}

			// Create manager and list
			mgr := NewManager(aclFile)
			entries, err := mgr.List()
			if err != nil {
				t.Fatalf("List() error = %v", err)
			}

			if len(entries) != len(tt.wantLines) {
				t.Errorf("got %d entries, want %d", len(entries), len(tt.wantLines))
			}

			for i, want := range tt.wantLines {
				if i >= len(entries) {
					t.Errorf("missing entry at index %d: %s", i, want)
					continue
				}
				if entries[i] != want {
					t.Errorf("entry[%d] = %s, want %s", i, entries[i], want)
				}
			}
		})
	}
}

func TestACLFileNotFound(t *testing.T) {
	mgr := NewManager("/nonexistent/acl.lst")

	// Test Add
	err := mgr.Add("10.0.0.1")
	if err == nil {
		t.Error("Add() expected error for nonexistent file, got nil")
	}

	// Test Remove
	err = mgr.Remove("10.0.0.1")
	if err == nil {
		t.Error("Remove() expected error for nonexistent file, got nil")
	}

	// Test List
	_, err = mgr.List()
	if err == nil {
		t.Error("List() expected error for nonexistent file, got nil")
	}
}
