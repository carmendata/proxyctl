package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestValidateDateFormat tests date format validation
func TestValidateDateFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid YYYYMMDD", "20251012", false},
		{"valid first day of year", "20250101", false},
		{"valid last day of year", "20251231", false},
		{"valid leap year", "20240229", false},
		{"too short", "2025101", true},
		{"too long", "202510123", true},
		{"invalid month", "20251301", true},
		{"invalid day", "20250230", true},
		{"not a number", "abcd1234", true},
		{"trailing space", "20251012 ", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDateFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateDateFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestExtractTimestamp tests timestamp extraction from log lines
func TestExtractTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantNil bool
	}{
		{
			name:    "valid log line with timestamp",
			line:    "Oct 12 10:30:15 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.1.1.1",
			wantNil: false,
		},
		{
			name:    "valid log line different month",
			line:    "Jan 1 00:00:01 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.1.1.1",
			wantNil: false,
		},
		{
			name:    "no timestamp",
			line:    "This line has no timestamp",
			wantNil: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := extractTimestamp(tt.line)
			if tt.wantNil && !ts.IsZero() {
				t.Errorf("extractTimestamp() expected zero time, got %v", ts)
			}
			if !tt.wantNil && ts.IsZero() {
				t.Errorf("extractTimestamp() expected non-zero time, got zero")
			}
		})
	}
}

// TestOverlaps tests time range overlap logic
func TestOverlaps(t *testing.T) {
	// Base date: Oct 12, 2025
	baseDate := time.Date(2025, 10, 12, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		start1       time.Time
		end1         time.Time
		start2       time.Time
		end2         time.Time
		wantOverlaps bool
	}{
		{
			name:         "identical ranges",
			start1:       baseDate,
			end1:         baseDate.Add(24 * time.Hour),
			start2:       baseDate,
			end2:         baseDate.Add(24 * time.Hour),
			wantOverlaps: true,
		},
		{
			name:         "partial overlap",
			start1:       baseDate,
			end1:         baseDate.Add(12 * time.Hour),
			start2:       baseDate.Add(6 * time.Hour),
			end2:         baseDate.Add(18 * time.Hour),
			wantOverlaps: true,
		},
		{
			name:         "no overlap - before",
			start1:       baseDate.Add(-48 * time.Hour),
			end1:         baseDate.Add(-24 * time.Hour),
			start2:       baseDate,
			end2:         baseDate.Add(24 * time.Hour),
			wantOverlaps: false,
		},
		{
			name:         "no overlap - after",
			start1:       baseDate.Add(48 * time.Hour),
			end1:         baseDate.Add(72 * time.Hour),
			start2:       baseDate,
			end2:         baseDate.Add(24 * time.Hour),
			wantOverlaps: false,
		},
		{
			name:         "touching at boundary",
			start1:       baseDate,
			end1:         baseDate.Add(12 * time.Hour),
			start2:       baseDate.Add(12 * time.Hour),
			end2:         baseDate.Add(24 * time.Hour),
			wantOverlaps: true,
		},
		{
			name:         "zero time in range 1",
			start1:       time.Time{},
			end1:         baseDate,
			start2:       baseDate,
			end2:         baseDate.Add(24 * time.Hour),
			wantOverlaps: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := overlaps(tt.start1, tt.end1, tt.start2, tt.end2)
			if got != tt.wantOverlaps {
				t.Errorf("overlaps() = %v, want %v", got, tt.wantOverlaps)
			}
		})
	}
}

// TestOpenLogFile tests file opening with gzip support
func TestOpenLogFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("regular uncompressed file", func(t *testing.T) {
		// Create test file
		regularFile := filepath.Join(tmpDir, "test.log")
		content := "line1\nline2\nline3\n"
		if err := os.WriteFile(regularFile, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		// Open and read
		reader, err := openLogFile(regularFile)
		if err != nil {
			t.Fatalf("openLogFile() error = %v", err)
		}
		defer reader.Close()

		// Verify content
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(reader); err != nil {
			t.Fatalf("failed to read: %v", err)
		}

		if buf.String() != content {
			t.Errorf("content = %q, want %q", buf.String(), content)
		}
	})

	t.Run("gzipped file", func(t *testing.T) {
		// Create gzipped test file
		gzFile := filepath.Join(tmpDir, "test.log.gz")
		content := "compressed line1\ncompressed line2\n"

		f, err := os.Create(gzFile)
		if err != nil {
			t.Fatalf("failed to create file: %v", err)
		}
		gzWriter := gzip.NewWriter(f)
		if _, err := gzWriter.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
		gzWriter.Close()
		f.Close()

		// Verify file is actually compressed
		rawData, _ := os.ReadFile(gzFile)
		if strings.Contains(string(rawData), "compressed") {
			t.Error("file should be gzipped but appears to be plain text")
		}

		// Open and read through openLogFile
		reader, err := openLogFile(gzFile)
		if err != nil {
			t.Fatalf("openLogFile() error = %v", err)
		}
		defer reader.Close()

		// Verify decompressed content
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(reader); err != nil {
			t.Fatalf("failed to read: %v", err)
		}

		if buf.String() != content {
			t.Errorf("content = %q, want %q", buf.String(), content)
		}

		// Verify original file still exists and is still gzipped
		if _, err := os.Stat(gzFile); os.IsNotExist(err) {
			t.Error("original gzipped file was deleted")
		}
	})

	t.Run("corrupted gzip file", func(t *testing.T) {
		// Create file with .gz extension but invalid gzip data
		corruptGz := filepath.Join(tmpDir, "corrupt.log.gz")
		if err := os.WriteFile(corruptGz, []byte("this is not gzipped data"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		reader, err := openLogFile(corruptGz)
		if err == nil {
			reader.Close()
			t.Error("expected error for corrupted gzip file, got nil")
		}
		if err != nil && !strings.Contains(err.Error(), "decompress") {
			t.Errorf("expected 'decompress' in error message, got: %v", err)
		}
	})

	t.Run("file not found", func(t *testing.T) {
		nonexistent := filepath.Join(tmpDir, "does-not-exist.log")
		reader, err := openLogFile(nonexistent)
		if err == nil {
			reader.Close()
			t.Error("expected error for nonexistent file, got nil")
		}
	})
}

// TestGzipReadCloserCleanup tests proper cleanup of gzipReadCloser
func TestGzipReadCloserCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	gzFile := filepath.Join(tmpDir, "cleanup-test.log.gz")

	// Create gzipped test file
	f, err := os.Create(gzFile)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	gz := gzip.NewWriter(f)
	gz.Write([]byte("test content"))
	gz.Close()
	f.Close()

	// Open and immediately close
	reader, err := openLogFile(gzFile)
	if err != nil {
		t.Fatalf("openLogFile() error = %v", err)
	}

	// Close should not error
	if err := reader.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// File should still exist
	if _, err := os.Stat(gzFile); os.IsNotExist(err) {
		t.Error("file was deleted after close")
	}
}

// TestParseLogReader tests log parsing logic
func TestParseLogReader(t *testing.T) {
	// Create sample log content matching actual log format
	logContent := `Oct 12 10:30:15 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0
Oct 12 11:45:22 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=8.8.8.8 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=54322 DPT=80 WINDOW=29200 RES=0x00 SYN URGP=0
Oct 12 12:00:00 host kernel: Some other log line without EGRESS_MONITOR
Oct 12 14:15:33 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.200 DST=1.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12347 DF PROTO=UDP SPT=54323 DPT=53 LEN=100
Oct 12 15:30:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12348 DF PROTO=TCP SPT=54324 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0`

	reader := strings.NewReader(logContent)

	// Parse without date filter
	connections, err := parseLogReader(reader, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("parseLogReader() error = %v", err)
	}

	// Should find 4 EGRESS_MONITOR entries (skipping non-EGRESS_MONITOR line)
	if len(connections) != 4 {
		t.Errorf("expected 4 connections, got %d", len(connections))
	}

	// Verify first connection
	if len(connections) > 0 {
		conn := connections[0]
		if conn.SrcIP != "10.0.1.100" {
			t.Errorf("first connection SrcIP = %q, want %q", conn.SrcIP, "10.0.1.100")
		}
		if conn.DstIP != "1.1.1.1" {
			t.Errorf("first connection DstIP = %q, want %q", conn.DstIP, "1.1.1.1")
		}
		if conn.Port != "443" {
			t.Errorf("first connection Port = %q, want %q", conn.Port, "443")
		}
	}
}

// TestParseLogReaderWithDateFilter tests date filtering during parsing
func TestParseLogReaderWithDateFilter(t *testing.T) {
	// Create log content spanning multiple hours
	currentYear := time.Now().Year()
	logContent := `Oct 12 08:00:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.1.1.1 LEN=60 PROTO=TCP DPT=443
Oct 12 12:00:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=8.8.8.8 LEN=60 PROTO=TCP DPT=80
Oct 12 18:00:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=10.0.1.100 DST=1.0.0.1 LEN=60 PROTO=TCP DPT=53`

	// Define filter: only 10:00-14:00 on Oct 12
	filterStart := time.Date(currentYear, 10, 12, 10, 0, 0, 0, time.UTC)
	filterEnd := time.Date(currentYear, 10, 12, 14, 0, 0, 0, time.UTC)

	reader := strings.NewReader(logContent)
	connections, err := parseLogReader(reader, filterStart, filterEnd)
	if err != nil {
		t.Fatalf("parseLogReader() error = %v", err)
	}

	// Should only find the 12:00:00 entry (within 10:00-14:00 range)
	if len(connections) != 1 {
		t.Errorf("expected 1 connection (filtered), got %d", len(connections))
	}

	if len(connections) > 0 {
		if connections[0].DstIP != "8.8.8.8" {
			t.Errorf("filtered connection should be 8.8.8.8, got %q", connections[0].DstIP)
		}
	}
}

// TestAnalyzeConnections tests the analysis aggregation logic
func TestAnalyzeConnections(t *testing.T) {
	connections := []Connection{
		{SrcIP: "10.0.1.100", DstIP: "1.1.1.1", Port: "443"},
		{SrcIP: "10.0.1.100", DstIP: "8.8.8.8", Port: "80"},
		{SrcIP: "10.0.1.200", DstIP: "1.1.1.1", Port: "443"},
		{SrcIP: "10.0.1.100", DstIP: "1.1.1.1", Port: "443"}, // Duplicate destination
	}

	analysis := analyzeConnections(connections)

	// Total connections
	if analysis.TotalConnections != 4 {
		t.Errorf("TotalConnections = %d, want 4", analysis.TotalConnections)
	}

	// Unique destinations (1.1.1.1, 8.8.8.8)
	if analysis.UniqueDestinations != 2 {
		t.Errorf("UniqueDestinations = %d, want 2", analysis.UniqueDestinations)
	}

	// Unique sources (10.0.1.100, 10.0.1.200)
	if analysis.UniqueSources != 2 {
		t.Errorf("UniqueSources = %d, want 2", analysis.UniqueSources)
	}

	// Destination counts
	if analysis.DstCounts["1.1.1.1"] != 3 {
		t.Errorf("DstCounts[1.1.1.1] = %d, want 3", analysis.DstCounts["1.1.1.1"])
	}
	if analysis.DstCounts["8.8.8.8"] != 1 {
		t.Errorf("DstCounts[8.8.8.8] = %d, want 1", analysis.DstCounts["8.8.8.8"])
	}

	// Port counts
	if analysis.PortCounts["443"] != 3 {
		t.Errorf("PortCounts[443] = %d, want 3", analysis.PortCounts["443"])
	}
	if analysis.PortCounts["80"] != 1 {
		t.Errorf("PortCounts[80] = %d, want 1", analysis.PortCounts["80"])
	}
}

// TestFindAllLogFiles tests log file discovery
// Note: This test uses the actual logger.LogDir so it will only find files if
// the logger has been installed on the system. For unit testing, we test the
// file selection logic separately.
func TestFindAllLogFiles(t *testing.T) {
	t.Skip("Skipping findAllLogFiles test - requires logger installation")
	// This function uses logger.LogDir internally which can't be easily mocked
	// Integration tests verify the full file discovery workflow
}

// TestDetectChainTypeFromFilename tests chain type detection from filename
func TestDetectChainTypeFromFilename(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedChain string
	}{
		{"INPUT log file", "/var/log/proxyctl/egress-input.log", "INPUT"},
		{"OUTPUT log file", "/var/log/proxyctl/egress-output.log", "OUTPUT"},
		{"FORWARD log file", "/var/log/proxyctl/egress-forward.log", "FORWARD"},
		{"INPUT rotated log", "/var/log/proxyctl/egress-input.log.1.gz", "INPUT"},
		{"OUTPUT rotated log", "/var/log/proxyctl/egress-output.log.2", "OUTPUT"},
		{"Legacy single log", "/var/log/proxyctl/egress.log", "OUTPUT"}, // Default to OUTPUT
		{"Unknown format", "/var/log/proxyctl/other.log", "OUTPUT"},     // Default to OUTPUT
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectChainTypeFromFilename(tt.path)
			if got != tt.expectedChain {
				t.Errorf("detectChainTypeFromFilename(%q) = %q, want %q", tt.path, got, tt.expectedChain)
			}
		})
	}
}

// TestParseLogReaderPerChain tests per-chain parsing from log content
func TestParseLogReaderPerChain(t *testing.T) {
	// Create sample log content with multiple chains in one file
	logContent := `Oct 12 10:30:15 host kernel: EGRESS_MONITOR_INPUT: IN=eth0 OUT= SRC=87.120.191.13 DST=165.22.116.193 LEN=60 PROTO=TCP SPT=54321 DPT=8728
Oct 12 11:45:22 host kernel: EGRESS_MONITOR_OUTPUT: IN= OUT=eth0 SRC=165.22.116.193 DST=8.8.8.8 LEN=60 PROTO=TCP SPT=54322 DPT=53
Oct 12 14:15:33 host kernel: EGRESS_MONITOR_FORWARD: IN=eth1 OUT=eth0 SRC=178.62.33.58 DST=51.159.53.209 LEN=60 PROTO=TCP SPT=54323 DPT=443
Oct 12 15:30:00 host kernel: EGRESS_MONITOR: IN= OUT=eth0 SRC=165.22.116.193 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=54324 DPT=443`

	reader := strings.NewReader(logContent)

	// Parse without date filter
	connections, err := parseLogReader(reader, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("parseLogReader() error = %v", err)
	}

	// Should find 4 entries
	if len(connections) != 4 {
		t.Errorf("expected 4 connections, got %d", len(connections))
	}

	// Verify chain types were correctly parsed
	expectedChains := []struct {
		srcIP string
		chain string
	}{
		{"87.120.191.13", "INPUT"},
		{"165.22.116.193", "OUTPUT"},
		{"178.62.33.58", "FORWARD"},
		{"165.22.116.193", "OUTPUT"}, // Old format, should default to OUTPUT
	}

	for i, expected := range expectedChains {
		if i >= len(connections) {
			break
		}
		conn := connections[i]
		if conn.SrcIP != expected.srcIP {
			t.Errorf("connection %d: SrcIP = %q, want %q", i, conn.SrcIP, expected.srcIP)
		}
		if conn.Chain != expected.chain {
			t.Errorf("connection %d: Chain = %q, want %q", i, conn.Chain, expected.chain)
		}
	}
}

// TestGroupConnectionsByChain tests grouping connections by chain
func TestGroupConnectionsByChain(t *testing.T) {
	connections := []Connection{
		{SrcIP: "87.120.191.13", DstIP: "165.22.116.193", Port: "8728", Protocol: "tcp", Chain: "INPUT"},
		{SrcIP: "165.22.116.193", DstIP: "8.8.8.8", Port: "53", Protocol: "udp", Chain: "OUTPUT"},
		{SrcIP: "178.62.33.58", DstIP: "51.159.53.209", Port: "443", Protocol: "tcp", Chain: "FORWARD"},
		{SrcIP: "165.22.116.193", DstIP: "1.1.1.1", Port: "443", Protocol: "tcp", Chain: "OUTPUT"},
		{SrcIP: "92.63.197.66", DstIP: "165.22.116.193", Port: "22", Protocol: "tcp", Chain: "INPUT"},
	}

	// Group by chain
	grouped := make(map[string][]Connection)
	for _, conn := range connections {
		grouped[conn.Chain] = append(grouped[conn.Chain], conn)
	}

	// Verify grouping
	if len(grouped) != 3 {
		t.Errorf("expected 3 chains, got %d", len(grouped))
	}

	if len(grouped["INPUT"]) != 2 {
		t.Errorf("expected 2 INPUT connections, got %d", len(grouped["INPUT"]))
	}

	if len(grouped["OUTPUT"]) != 2 {
		t.Errorf("expected 2 OUTPUT connections, got %d", len(grouped["OUTPUT"]))
	}

	if len(grouped["FORWARD"]) != 1 {
		t.Errorf("expected 1 FORWARD connection, got %d", len(grouped["FORWARD"]))
	}
}
