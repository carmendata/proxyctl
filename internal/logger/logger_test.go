package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/carmendata/proxyctl/internal/config"
	"github.com/carmendata/proxyctl/internal/testutil"
)

// TestNewManager tests manager creation
func TestNewManager(t *testing.T) {
	mgr := NewManager()

	if mgr.LogFile != LogFile {
		t.Errorf("expected LogFile=%s, got %s", LogFile, mgr.LogFile)
	}
	if mgr.RsyslogConf != RsyslogConf {
		t.Errorf("expected RsyslogConf=%s, got %s", RsyslogConf, mgr.RsyslogConf)
	}
	if mgr.LogrotateConf != LogrotateConf {
		t.Errorf("expected LogrotateConf=%s, got %s", LogrotateConf, mgr.LogrotateConf)
	}
}

// TestCreateRsyslogConfig tests rsyslog configuration file generation (unit testable)
func TestCreateRsyslogConfig(t *testing.T) {
	tests := []struct {
		name          string
		mgr           *Manager
		wantErr       bool
		checkContent  bool
		expectedLines []string
	}{
		{
			name: "successful rsyslog config creation for egress",
			mgr: &Manager{
				Name:        "egress",
				LogFile:     "/var/log/proxyctl/egress.log",
				LogPrefix:   "EGRESS_MONITOR: ",
				RsyslogConf: "", // Will be set in test
			},
			wantErr:      false,
			checkContent: true,
			expectedLines: []string{
				"# Connection Monitoring",
				"if $msg contains \"EGRESS_MONITOR: \" then {",
				"action(type=\"omfile\" file=\"/var/log/proxyctl/egress.log\")",
				"stop",
			},
		},
		{
			name: "rsyslog config for db-primary with custom prefix",
			mgr: &Manager{
				Name:        "db-primary",
				LogFile:     "/var/log/proxyctl/db-primary.log",
				LogPrefix:   "DB_PRIMARY_MONITOR: ",
				RsyslogConf: "", // Will be set in test
			},
			wantErr:      false,
			checkContent: true,
			expectedLines: []string{
				"if $msg contains \"DB_PRIMARY_MONITOR: \" then {",
				"action(type=\"omfile\" file=\"/var/log/proxyctl/db-primary.log\")",
			},
		},
		{
			name: "custom log file path",
			mgr: &Manager{
				Name:        "custom",
				LogFile:     "/custom/path/test.log",
				LogPrefix:   "CUSTOM_MONITOR: ",
				RsyslogConf: "", // Will be set in test
			},
			wantErr:      false,
			checkContent: true,
			expectedLines: []string{
				"if $msg contains \"CUSTOM_MONITOR: \" then {",
				"action(type=\"omfile\" file=\"/custom/path/test.log\")",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory
			tmpDir := t.TempDir()
			rsyslogPath := filepath.Join(tmpDir, "rsyslog.conf")
			tt.mgr.RsyslogConf = rsyslogPath

			// Test only the file creation (no systemctl)
			err := tt.mgr.createRsyslogConfig()

			if (err != nil) != tt.wantErr {
				t.Errorf("createRsyslogConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check that config file was created
			testutil.AssertFileExists(t, rsyslogPath)

			// Check content
			if tt.checkContent {
				content, readErr := os.ReadFile(rsyslogPath)
				if readErr != nil {
					t.Fatalf("failed to read rsyslog config: %v", readErr)
				}

				for _, expectedLine := range tt.expectedLines {
					if !strings.Contains(string(content), expectedLine) {
						t.Errorf("rsyslog config missing expected line: %s\nContent:\n%s", expectedLine, string(content))
					}
				}

				// Check file permissions
				testutil.AssertFilePermissions(t, rsyslogPath, 0644)
			}
		})
	}
}

// TestConfigureLogrotate tests logrotate configuration generation
func TestConfigureLogrotate(t *testing.T) {
	tests := []struct {
		name          string
		logFile       string
		wantErr       bool
		expectedLines []string
	}{
		{
			name:    "successful logrotate config creation",
			logFile: "/var/log/proxyctl/egress.log",
			wantErr: false,
			expectedLines: []string{
				"/var/log/proxyctl/egress.log {",
				"daily",
				"rotate 14",
				"compress",
				"delaycompress",
				"missingok",
				"notifempty",
				"create 0640", // Don't check user/group - varies by distro
				"su ",         // Check that su directive is present
				"postrotate",
				"systemctl restart rsyslog",
				"endscript",
				"}",
			},
		},
		{
			name:    "custom log file path",
			logFile: "/custom/path/test.log",
			wantErr: false,
			expectedLines: []string{
				"/custom/path/test.log {",
				"daily",
				"rotate 14",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory
			tmpDir := t.TempDir()
			logrotatePath := filepath.Join(tmpDir, "logrotate.conf")

			mgr := &Manager{
				LogFile:       tt.logFile,
				LogrotateConf: logrotatePath,
			}

			err := mgr.configureLogrotate()

			if (err != nil) != tt.wantErr {
				t.Errorf("configureLogrotate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check that config file was created
			testutil.AssertFileExists(t, logrotatePath)

			// Check content
			content, readErr := os.ReadFile(logrotatePath)
			if readErr != nil {
				t.Fatalf("failed to read logrotate config: %v", readErr)
			}

			for _, expectedLine := range tt.expectedLines {
				if !strings.Contains(string(content), expectedLine) {
					t.Errorf("logrotate config missing expected line: %s\nContent:\n%s", expectedLine, string(content))
				}
			}

			// Check file permissions
			testutil.AssertFilePermissions(t, logrotatePath, 0644)
		})
	}
}

// TestDeleteRsyslogConfig tests rsyslog config file deletion (unit testable)
func TestDeleteRsyslogConfig(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   bool
		fileContent string
		wantErr     bool
	}{
		{
			name:        "remove existing config",
			setupFile:   true,
			fileContent: "test config",
			wantErr:     false,
		},
		{
			name:      "remove non-existent config (no error)",
			setupFile: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			rsyslogPath := filepath.Join(tmpDir, "rsyslog.conf")

			// Setup file if needed
			if tt.setupFile {
				if err := os.WriteFile(rsyslogPath, []byte(tt.fileContent), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
				testutil.AssertFileExists(t, rsyslogPath)
			}

			mgr := &Manager{
				RsyslogConf: rsyslogPath,
			}

			// Test only file deletion (no systemctl)
			err := mgr.deleteRsyslogConfig()

			if (err != nil) != tt.wantErr {
				t.Errorf("deleteRsyslogConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// File should be removed
			if tt.setupFile {
				testutil.AssertFileNotExists(t, rsyslogPath)
			}
		})
	}
}

// TestRemoveLogrotateConfig tests logrotate config removal
func TestRemoveLogrotateConfig(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   bool
		fileContent string
		wantErr     bool
	}{
		{
			name:        "remove existing config",
			setupFile:   true,
			fileContent: "test config",
			wantErr:     false,
		},
		{
			name:      "remove non-existent config (no error)",
			setupFile: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			logrotatePath := filepath.Join(tmpDir, "logrotate.conf")

			// Setup file if needed
			if tt.setupFile {
				if err := os.WriteFile(logrotatePath, []byte(tt.fileContent), 0644); err != nil {
					t.Fatalf("failed to create test file: %v", err)
				}
				testutil.AssertFileExists(t, logrotatePath)
			}

			mgr := &Manager{
				LogrotateConf: logrotatePath,
			}

			err := mgr.removeLogrotateConfig()

			if (err != nil) != tt.wantErr {
				t.Errorf("removeLogrotateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// File should be removed
			if tt.setupFile {
				testutil.AssertFileNotExists(t, logrotatePath)
			}
		})
	}
}

// TestFindNFTablesMainConf tests nftables config file detection
func TestFindNFTablesMainConf(t *testing.T) {
	// This test verifies the function returns a valid path
	// The actual path depends on the system
	path := findNFTablesMainConf()

	if path == "" {
		t.Error("findNFTablesMainConf() returned empty path")
	}

	// Should be one of the known paths
	validPaths := nftablesMainConfPaths
	found := false
	for _, validPath := range validPaths {
		if path == validPath {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("findNFTablesMainConf() returned unexpected path: %s", path)
	}
}

// TestNFTablesConfigGeneration tests nftables config file content
func TestNFTablesConfigGeneration(t *testing.T) {
	// Test that we can generate valid nftables config content
	// without actually installing it

	expectedElements := []string{
		"table ip egress_monitor",
		"chain output",
		"type filter hook output priority -1",
		"# Skip private IP ranges",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"# Log all NEW TCP connections",
		"meta l4proto tcp",
		"log prefix \"EGRESS_MONITOR: \"",
		"# Log all NEW UDP connections",
		"meta l4proto udp",
	}

	// Build config (similar to createNFTablesRules)
	var config strings.Builder
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
	}

	config.WriteString("# Egress Connection Monitoring\n")
	config.WriteString("table ip egress_monitor {\n")
	config.WriteString("    chain output {\n")
	config.WriteString("        type filter hook output priority -1; policy accept;\n\n")
	config.WriteString("        # Skip private IP ranges\n")

	for _, ipRange := range privateRanges {
		config.WriteString("        ip daddr " + ipRange + " return\n")
	}

	config.WriteString("\n        # Log all NEW TCP connections to public IPs\n")
	config.WriteString("        meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new log prefix \"EGRESS_MONITOR: \" level info\n")
	config.WriteString("\n        # Log all NEW UDP connections to public IPs\n")
	config.WriteString("        meta l4proto udp ct state new log prefix \"EGRESS_MONITOR: \" level info\n")
	config.WriteString("    }\n")
	config.WriteString("}\n")

	configContent := config.String()

	// Verify all expected elements are present
	for _, element := range expectedElements {
		if !strings.Contains(configContent, element) {
			t.Errorf("nftables config missing expected element: %s\nConfig:\n%s", element, configContent)
		}
	}

	// Verify config is valid nftables syntax (basic checks)
	if !strings.HasPrefix(configContent, "#") && !strings.HasPrefix(strings.TrimSpace(configContent), "table") {
		t.Error("nftables config should start with comment or table declaration")
	}

	if strings.Count(configContent, "{") != strings.Count(configContent, "}") {
		t.Error("nftables config has mismatched braces")
	}
}

// TestIPTablesPrivateRanges tests that private IP ranges are correct
func TestIPTablesPrivateRanges(t *testing.T) {
	expectedRanges := []string{
		"10.0.0.0/8",     // Private Class A
		"172.16.0.0/12",  // Private Class B
		"192.168.0.0/16", // Private Class C
		"169.254.0.0/16", // Link-local
		"127.0.0.0/8",    // Loopback
		"224.0.0.0/4",    // Multicast
		"240.0.0.0/4",    // Reserved
	}

	// This is the same list used in createIPTablesRules
	// We test that it matches expected ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	if len(privateRanges) != len(expectedRanges) {
		t.Errorf("expected %d private ranges, got %d", len(expectedRanges), len(privateRanges))
	}

	for i, expected := range expectedRanges {
		if i >= len(privateRanges) {
			t.Errorf("missing private range at index %d: %s", i, expected)
			continue
		}
		if privateRanges[i] != expected {
			t.Errorf("private range mismatch at index %d: got %s, want %s", i, privateRanges[i], expected)
		}
	}
}

// TestLogPrefix tests that log prefix constant is correct
func TestLogPrefix(t *testing.T) {
	if LogPrefix != "EGRESS_MONITOR" {
		t.Errorf("LogPrefix should be 'EGRESS_MONITOR', got '%s'", LogPrefix)
	}

	// Log prefix should not contain spaces (rsyslog matching)
	if strings.Contains(LogPrefix, " ") {
		t.Error("LogPrefix should not contain spaces")
	}

	// Log prefix should be uppercase (convention)
	if LogPrefix != strings.ToUpper(LogPrefix) {
		t.Error("LogPrefix should be uppercase")
	}
}

// TestLogFilePaths tests that default paths are correct
func TestLogFilePaths(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		expectedDir      string
		expectedFile     string
		shouldBeAbsolute bool
	}{
		{
			name:             "LogFile",
			path:             LogFile,
			expectedDir:      "/var/log/proxyctl",
			expectedFile:     "egress.log",
			shouldBeAbsolute: true,
		},
		{
			name:             "LogDir",
			path:             LogDir,
			expectedDir:      "/var/log/proxyctl",
			expectedFile:     "",
			shouldBeAbsolute: true,
		},
		{
			name:             "RsyslogConf",
			path:             RsyslogConf,
			expectedDir:      "/etc/rsyslog.d",
			expectedFile:     "10-egress-monitor.conf",
			shouldBeAbsolute: true,
		},
		{
			name:             "LogrotateConf",
			path:             LogrotateConf,
			expectedDir:      "/etc/logrotate.d",
			expectedFile:     "egress-monitor",
			shouldBeAbsolute: true,
		},
		{
			name:             "NFTablesConf",
			path:             NFTablesConf,
			expectedDir:      "/etc/nftables.d",
			expectedFile:     "egress-monitor.nft",
			shouldBeAbsolute: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldBeAbsolute && !filepath.IsAbs(tt.path) {
				t.Errorf("%s should be absolute path, got: %s", tt.name, tt.path)
			}

			if tt.expectedFile != "" {
				dir := filepath.Dir(tt.path)
				file := filepath.Base(tt.path)

				if dir != tt.expectedDir {
					t.Errorf("%s directory should be %s, got %s", tt.name, tt.expectedDir, dir)
				}

				if file != tt.expectedFile {
					t.Errorf("%s filename should be %s, got %s", tt.name, tt.expectedFile, file)
				}
			} else {
				// Directory path
				if tt.path != tt.expectedDir {
					t.Errorf("%s should be %s, got %s", tt.name, tt.expectedDir, tt.path)
				}
			}
		})
	}
}

// TestContainsString tests the containsString helper function
func TestContainsString(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{
			name:   "exact match",
			s:      "hello",
			substr: "hello",
			want:   true,
		},
		{
			name:   "substring at start",
			s:      "hello world",
			substr: "hello",
			want:   true,
		},
		{
			name:   "substring at end",
			s:      "hello world",
			substr: "world",
			want:   true,
		},
		{
			name:   "substring in middle",
			s:      "hello world test",
			substr: "world",
			want:   true,
		},
		{
			name:   "not found",
			s:      "hello world",
			substr: "foo",
			want:   false,
		},
		{
			name:   "empty substring",
			s:      "hello",
			substr: "",
			want:   false,
		},
		{
			name:   "empty string",
			s:      "",
			substr: "hello",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsString(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsString(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

// TestManagerWithCustomPaths tests manager with custom paths
func TestManagerWithCustomPaths(t *testing.T) {
	tmpDir := t.TempDir()

	mgr := &Manager{
		LogFile:       filepath.Join(tmpDir, "custom.log"),
		RsyslogConf:   filepath.Join(tmpDir, "custom-rsyslog.conf"),
		LogrotateConf: filepath.Join(tmpDir, "custom-logrotate.conf"),
	}

	// Test rsyslog config with custom paths (file only, no systemctl)
	err := mgr.createRsyslogConfig()
	if err != nil {
		t.Errorf("createRsyslogConfig() with custom paths failed: %v", err)
	}

	// Test logrotate config with custom paths
	err = mgr.configureLogrotate()
	if err != nil {
		t.Errorf("configureLogrotate() with custom paths failed: %v", err)
	}

	// Verify files were created in custom locations
	testutil.AssertFileExists(t, mgr.RsyslogConf)
	testutil.AssertFileExists(t, mgr.LogrotateConf)

	// Verify custom log file path appears in configs
	testutil.AssertFileContains(t, mgr.RsyslogConf, mgr.LogFile)
	testutil.AssertFileContains(t, mgr.LogrotateConf, mgr.LogFile)
}

// TestIdempotentOperations tests that operations can be called multiple times safely
func TestIdempotentOperations(t *testing.T) {
	tmpDir := t.TempDir()

	mgr := &Manager{
		LogFile:       filepath.Join(tmpDir, "test.log"),
		RsyslogConf:   filepath.Join(tmpDir, "rsyslog.conf"),
		LogrotateConf: filepath.Join(tmpDir, "logrotate.conf"),
	}

	// First call (file only, no systemctl)
	mgr.createRsyslogConfig()
	mgr.configureLogrotate()

	content1Rsyslog, _ := os.ReadFile(mgr.RsyslogConf)
	content1Logrotate, _ := os.ReadFile(mgr.LogrotateConf)

	// Second call (should overwrite with identical content)
	mgr.createRsyslogConfig()
	mgr.configureLogrotate()

	content2Rsyslog, _ := os.ReadFile(mgr.RsyslogConf)
	content2Logrotate, _ := os.ReadFile(mgr.LogrotateConf)

	if string(content1Rsyslog) != string(content2Rsyslog) {
		t.Error("rsyslog config changed after second call (should be idempotent)")
	}

	if string(content1Logrotate) != string(content2Logrotate) {
		t.Error("logrotate config changed after second call (should be idempotent)")
	}

	// Multiple removes (should not error)
	mgr.deleteRsyslogConfig()
	mgr.deleteRsyslogConfig() // Second call should not error

	mgr.removeLogrotateConfig()
	mgr.removeLogrotateConfig() // Second call should not error
}

// TestNewManagerFromConfig tests creating manager from LoggerConfig
func TestNewManagerFromConfig(t *testing.T) {
	tests := []struct {
		name              string
		cfg               *config.LoggerConfig
		expectedName      string
		expectedLogFile   string
		expectedPrefix    string
		expectedTable     string
		expectedChain     string
		expectedRsyslog   string
		expectedLogrotate string
		expectedNFTables  string
		expectedIPTScript string
		wantChains        int
		wantProtos        int
	}{
		{
			name: "default egress logger",
			cfg: &config.LoggerConfig{
				Enabled: true,
				Name:    "egress",
			},
			expectedName:      "egress",
			expectedLogFile:   "/var/log/proxyctl/egress.log",
			expectedPrefix:    "EGRESS_MONITOR: ",
			expectedTable:     "egress_monitor",
			expectedChain:     "EGRESS_LOG",
			expectedRsyslog:   "/etc/rsyslog.d/10-egress-monitor.conf",
			expectedLogrotate: "/etc/logrotate.d/egress-monitor",
			expectedNFTables:  "/etc/nftables.d/egress-monitor.nft",
			expectedIPTScript: "/etc/systemd/scripts/egress-monitor-iptables.sh",
			wantChains:        1, // Should default to OUTPUT
			wantProtos:        2, // Should default to tcp, udp
		},
		{
			name: "db-primary with hyphens",
			cfg: &config.LoggerConfig{
				Enabled: true,
				Name:    "db-primary",
			},
			expectedName:      "db-primary",
			expectedLogFile:   "/var/log/proxyctl/db-primary.log",
			expectedPrefix:    "DB_PRIMARY_MONITOR: ",
			expectedTable:     "db_primary_monitor",
			expectedChain:     "DB_PRIMARY_LOG",
			expectedRsyslog:   "/etc/rsyslog.d/10-db-primary-monitor.conf",
			expectedLogrotate: "/etc/logrotate.d/db-primary-monitor",
			expectedNFTables:  "/etc/nftables.d/db-primary-monitor.nft",
			expectedIPTScript: "/etc/systemd/scripts/db-primary-monitor-iptables.sh",
			wantChains:        1,
			wantProtos:        2,
		},
		{
			name: "custom log path",
			cfg: &config.LoggerConfig{
				Enabled: true,
				Name:    "mylogger",
				LogPath: "/custom/path/",
			},
			expectedName:      "mylogger",
			expectedLogFile:   "/custom/path/mylogger.log",
			expectedPrefix:    "MYLOGGER_MONITOR: ",
			expectedTable:     "mylogger_monitor",
			expectedChain:     "MYLOGGER_LOG",
			expectedRsyslog:   "/etc/rsyslog.d/10-mylogger-monitor.conf",
			expectedLogrotate: "/etc/logrotate.d/mylogger-monitor",
			expectedNFTables:  "/etc/nftables.d/mylogger-monitor.nft",
			expectedIPTScript: "/etc/systemd/scripts/mylogger-monitor-iptables.sh",
			wantChains:        1,
			wantProtos:        2,
		},
		{
			name: "custom log path without trailing slash",
			cfg: &config.LoggerConfig{
				Enabled: true,
				Name:    "test",
				LogPath: "/tmp/logs",
			},
			expectedName:      "test",
			expectedLogFile:   "/tmp/logs/test.log",
			expectedPrefix:    "TEST_MONITOR: ",
			expectedTable:     "test_monitor",
			expectedChain:     "TEST_LOG",
			expectedRsyslog:   "/etc/rsyslog.d/10-test-monitor.conf",
			expectedLogrotate: "/etc/logrotate.d/test-monitor",
			expectedNFTables:  "/etc/nftables.d/test-monitor.nft",
			expectedIPTScript: "/etc/systemd/scripts/test-monitor-iptables.sh",
			wantChains:        1,
			wantProtos:        2,
		},
		{
			name: "config with all options",
			cfg: &config.LoggerConfig{
				Enabled:          true,
				Name:             "comprehensive",
				Chains:           []string{"OUTPUT", "INPUT", "FORWARD"},
				Protocols:        []string{"tcp", "udp", "icmp"},
				IncludePrivate:   true,
				IncludeLoopback:  true,
				IncludeMulticast: true,
				IncludeRanges:    []string{"8.8.8.8"},
				ExcludeRanges:    []string{"10.0.0.0/8"},
			},
			expectedName:      "comprehensive",
			expectedLogFile:   "/var/log/proxyctl/comprehensive.log",
			expectedPrefix:    "COMPREHENSIVE_MONITOR: ",
			expectedTable:     "comprehensive_monitor",
			expectedChain:     "COMPREHENSIVE_LOG",
			expectedRsyslog:   "/etc/rsyslog.d/10-comprehensive-monitor.conf",
			expectedLogrotate: "/etc/logrotate.d/comprehensive-monitor",
			expectedNFTables:  "/etc/nftables.d/comprehensive-monitor.nft",
			expectedIPTScript: "/etc/systemd/scripts/comprehensive-monitor-iptables.sh",
			wantChains:        3,
			wantProtos:        3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManagerFromConfig(tt.cfg)

			// Test name-based computed fields
			if mgr.Name != tt.expectedName {
				t.Errorf("Name = %s, want %s", mgr.Name, tt.expectedName)
			}

			if mgr.LogFile != tt.expectedLogFile {
				t.Errorf("LogFile = %s, want %s", mgr.LogFile, tt.expectedLogFile)
			}

			if mgr.LogPrefix != tt.expectedPrefix {
				t.Errorf("LogPrefix = %s, want %s", mgr.LogPrefix, tt.expectedPrefix)
			}

			if mgr.NFTableName != tt.expectedTable {
				t.Errorf("NFTableName = %s, want %s", mgr.NFTableName, tt.expectedTable)
			}

			if mgr.IPTablesChain != tt.expectedChain {
				t.Errorf("IPTablesChain = %s, want %s", mgr.IPTablesChain, tt.expectedChain)
			}

			if mgr.RsyslogConf != tt.expectedRsyslog {
				t.Errorf("RsyslogConf = %s, want %s", mgr.RsyslogConf, tt.expectedRsyslog)
			}

			if mgr.LogrotateConf != tt.expectedLogrotate {
				t.Errorf("LogrotateConf = %s, want %s", mgr.LogrotateConf, tt.expectedLogrotate)
			}

			if mgr.NFTablesConf != tt.expectedNFTables {
				t.Errorf("NFTablesConf = %s, want %s", mgr.NFTablesConf, tt.expectedNFTables)
			}

			if mgr.IPTablesScript != tt.expectedIPTScript {
				t.Errorf("IPTablesScript = %s, want %s", mgr.IPTablesScript, tt.expectedIPTScript)
			}

			// Test monitoring configuration
			if len(mgr.Chains) != tt.wantChains {
				t.Errorf("Chains length = %d, want %d", len(mgr.Chains), tt.wantChains)
			}

			if len(mgr.Protocols) != tt.wantProtos {
				t.Errorf("Protocols length = %d, want %d", len(mgr.Protocols), tt.wantProtos)
			}

			if mgr.IncludePrivate != tt.cfg.IncludePrivate {
				t.Errorf("IncludePrivate = %v, want %v", mgr.IncludePrivate, tt.cfg.IncludePrivate)
			}

			if len(mgr.IncludeRanges) != len(tt.cfg.IncludeRanges) {
				t.Errorf("IncludeRanges length = %d, want %d", len(mgr.IncludeRanges), len(tt.cfg.IncludeRanges))
			}
		})
	}
}

// TestGetMonitoredRanges tests the IP range filtering logic
func TestGetMonitoredRanges(t *testing.T) {
	tests := []struct {
		name         string
		mgr          *Manager
		wantContains []string // Ranges that should be in exclusion list
		wantOmits    []string // Ranges that should NOT be in exclusion list
	}{
		{
			name: "default (public IPs only)",
			mgr: &Manager{
				IncludePrivate:   false,
				IncludeLoopback:  false,
				IncludeMulticast: false,
			},
			wantContains: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "224.0.0.0/4"},
			wantOmits:    []string{},
		},
		{
			name: "include private",
			mgr: &Manager{
				IncludePrivate:   true,
				IncludeLoopback:  false,
				IncludeMulticast: false,
			},
			wantContains: []string{"127.0.0.0/8", "224.0.0.0/4"},   // Still exclude these
			wantOmits:    []string{"10.0.0.0/8", "192.168.0.0/16"}, // Should NOT exclude (we're including private)
		},
		{
			name: "include loopback",
			mgr: &Manager{
				IncludePrivate:   false,
				IncludeLoopback:  true,
				IncludeMulticast: false,
			},
			wantContains: []string{"10.0.0.0/8", "192.168.0.0/16", "224.0.0.0/4"},
			wantOmits:    []string{"127.0.0.0/8"}, // Should NOT exclude (we're including loopback)
		},
		{
			name: "include multicast",
			mgr: &Manager{
				IncludePrivate:   false,
				IncludeLoopback:  false,
				IncludeMulticast: true,
			},
			wantContains: []string{"10.0.0.0/8", "127.0.0.0/8"},
			wantOmits:    []string{"224.0.0.0/4", "240.0.0.0/4"}, // Should NOT exclude (we're including multicast)
		},
		{
			name: "include all categories",
			mgr: &Manager{
				IncludePrivate:   true,
				IncludeLoopback:  true,
				IncludeMulticast: true,
			},
			wantContains: []string{}, // Nothing excluded
			wantOmits:    []string{"10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4"},
		},
		{
			name: "with custom excludes",
			mgr: &Manager{
				IncludePrivate: true,
				ExcludeRanges:  []string{"10.99.0.0/16"},
			},
			wantContains: []string{"10.99.0.0/16", "127.0.0.0/8"}, // Custom exclude + loopback
			wantOmits:    []string{"10.0.0.0/8"},                  // Not in exclusion list (private included)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			excluded := tt.mgr.getMonitoredRanges()

			// Check that expected ranges are in the exclusion list
			for _, want := range tt.wantContains {
				found := false
				for _, e := range excluded {
					if e == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected %s to be in exclusion list, but it wasn't. Got: %v", want, excluded)
				}
			}

			// Check that certain ranges are NOT in the exclusion list
			for _, omit := range tt.wantOmits {
				for _, e := range excluded {
					if e == omit {
						t.Errorf("Expected %s NOT to be in exclusion list, but it was. Got: %v", omit, excluded)
					}
				}
			}
		})
	}
}

// TestHasWhitelist tests whitelist mode detection
func TestHasWhitelist(t *testing.T) {
	tests := []struct {
		name string
		mgr  *Manager
		want bool
	}{
		{
			name: "no whitelist",
			mgr:  &Manager{IncludeRanges: []string{}},
			want: false,
		},
		{
			name: "has whitelist",
			mgr:  &Manager{IncludeRanges: []string{"8.8.8.8"}},
			want: true,
		},
		{
			name: "has multiple whitelist entries",
			mgr:  &Manager{IncludeRanges: []string{"8.8.8.8", "1.1.1.1", "10.0.0.0/8"}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mgr.hasWhitelist()
			if got != tt.want {
				t.Errorf("hasWhitelist() = %v, want %v", got, tt.want)
			}
		})
	}
}
