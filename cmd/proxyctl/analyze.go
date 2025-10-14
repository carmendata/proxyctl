package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/carmendata/proxyctl/internal/logger"
)

const LogFile = logger.LogFile

// validateDateFormat validates YYYYMMDD format
func validateDateFormat(date string) error {
	if len(date) != 8 {
		return fmt.Errorf("date must be 8 characters (YYYYMMDD), got %d", len(date))
	}

	// Parse as YYYYMMDD
	_, err := time.Parse("20060102", date)
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}

	return nil
}

// LogFileInfo contains metadata about a log file
type LogFileInfo struct {
	Path      string
	FirstTime time.Time
	LastTime  time.Time
}

// findAllLogFiles discovers all egress log files
func findAllLogFiles() ([]string, error) {
	logDir := logger.LogDir
	pattern := filepath.Join(logDir, "egress.log*")

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to find log files: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no log files found in %s\nHave you installed the connection logger?", logDir)
	}

	// Sort by modification time (newest first helps with current log)
	sort.Slice(matches, func(i, j int) bool {
		iInfo, _ := os.Stat(matches[i])
		jInfo, _ := os.Stat(matches[j])
		if iInfo == nil || jInfo == nil {
			return false
		}
		return iInfo.ModTime().After(jInfo.ModTime())
	})

	return matches, nil
}

// extractTimestamp extracts timestamp from a log line
func extractTimestamp(line string) time.Time {
	// Syslog format: "Oct 12 10:30:15"
	timestampRe := regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)`)

	if match := timestampRe.FindStringSubmatch(line); len(match) > 1 {
		// Parse timestamp (assumes current year)
		timeStr := match[1] + " " + fmt.Sprintf("%d", time.Now().Year())
		if ts, err := time.Parse("Jan 2 15:04:05 2006", timeStr); err == nil {
			return ts
		}
	}

	return time.Time{}
}

// peekTimestamps reads first and last timestamps from a log file
func peekTimestamps(path string) (first, last time.Time, err error) {
	reader, err := openLogFile(path)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	// Find first line with EGRESS_MONITOR and timestamp
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "EGRESS_MONITOR") {
			if ts := extractTimestamp(line); !ts.IsZero() {
				first = ts
				break
			}
		}
	}

	// Continue reading to find last timestamp
	var lastLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "EGRESS_MONITOR") {
			lastLine = line
		}
	}

	if lastLine != "" {
		last = extractTimestamp(lastLine)
	}

	// If we only have one line, first == last
	if last.IsZero() && !first.IsZero() {
		last = first
	}

	return first, last, scanner.Err()
}

// overlaps checks if two time ranges overlap
func overlaps(start1, end1, start2, end2 time.Time) bool {
	// Handle zero times (missing data)
	if start1.IsZero() || end1.IsZero() || start2.IsZero() || end2.IsZero() {
		return false
	}
	// Ranges overlap if: start1 <= end2 AND start2 <= end1
	return !start1.After(end2) && !start2.After(end1)
}

// selectLogFiles selects log files based on requested date range
// Returns files whose timestamp range overlaps the requested range
func selectLogFiles(dateFlag string) ([]LogFileInfo, error) {
	// Find all log files
	allFiles, err := findAllLogFiles()
	if err != nil {
		return nil, err
	}

	// Determine requested date range
	var requestedStart, requestedEnd time.Time

	if dateFlag == "" {
		// No date specified: analyze today only (current log)
		// Use wide range to catch everything in current log
		requestedStart = time.Now().Add(-24 * time.Hour) // Yesterday
		requestedEnd = time.Now().Add(24 * time.Hour)    // Tomorrow
	} else {
		// Specific date: start at 00:00:00, end at 23:59:59
		dataDate, err := time.Parse("20060102", dateFlag)
		if err != nil {
			return nil, fmt.Errorf("failed to parse date: %w", err)
		}

		requestedStart = time.Date(dataDate.Year(), dataDate.Month(), dataDate.Day(), 0, 0, 0, 0, dataDate.Location())
		requestedEnd = time.Date(dataDate.Year(), dataDate.Month(), dataDate.Day(), 23, 59, 59, 999999999, dataDate.Location())
	}

	// Examine each file and select those that overlap
	var selectedFiles []LogFileInfo

	for _, path := range allFiles {
		first, last, err := peekTimestamps(path)
		if err != nil {
			// Log warning but continue
			fmt.Printf("Warning: Could not read timestamps from %s: %v\n", filepath.Base(path), err)
			continue
		}

		// Skip files with no valid timestamps
		if first.IsZero() && last.IsZero() {
			continue
		}

		// Check if file's time range overlaps requested range
		if overlaps(first, last, requestedStart, requestedEnd) {
			selectedFiles = append(selectedFiles, LogFileInfo{
				Path:      path,
				FirstTime: first,
				LastTime:  last,
			})
		}
	}

	if len(selectedFiles) == 0 {
		if dateFlag == "" {
			return nil, fmt.Errorf("no log files found with recent data")
		}
		return nil, fmt.Errorf("no log files found containing data for %s\n\n"+
			"Checked %d log files in range.\n"+
			"Note: Logs are kept for 14 days.", dateFlag, len(allFiles))
	}

	// Sort by first timestamp (oldest first)
	sort.Slice(selectedFiles, func(i, j int) bool {
		return selectedFiles[i].FirstTime.Before(selectedFiles[j].FirstTime)
	})

	return selectedFiles, nil
}

// gzipReadCloser wraps gzip.Reader and underlying file for proper cleanup
type gzipReadCloser struct {
	*gzip.Reader
	file *os.File
}

// Close closes both the gzip reader and underlying file
func (g *gzipReadCloser) Close() error {
	// Close gzip reader first
	gzipErr := g.Reader.Close()

	// Then close underlying file
	fileErr := g.file.Close()

	// Return first error encountered
	if gzipErr != nil {
		return gzipErr
	}
	return fileErr
}

// openLogFile opens a log file and returns a reader (handles gzip automatically)
// Caller must close the returned ReadCloser
func openLogFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}

	// If gzipped, wrap in gzip reader
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to decompress %s: %w\nFile may be corrupted.", path, err)
		}

		// Return composite closer that closes both gzip reader and file
		return &gzipReadCloser{
			Reader: gzReader,
			file:   file,
		}, nil
	}

	// Regular uncompressed file
	return file, nil
}

// runLoggerAnalyze analyzes connection logs
func runLoggerAnalyze(analyzeDate string, args []string) error {
	// Validate args (should be empty now that flags are parsed)
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %v", args)
	}

	// Validate date format if provided
	if analyzeDate != "" {
		if err := validateDateFormat(analyzeDate); err != nil {
			return fmt.Errorf("invalid --date format: %w\n\nExpected: YYYYMMDD (e.g., 20251012)", err)
		}
	}

	fmt.Println("Analyzing Outbound Connection Logs")
	fmt.Println()

	// Select log files based on timestamp ranges
	selectedFiles, err := selectLogFiles(analyzeDate)
	if err != nil {
		return err
	}

	// Show which files are being analyzed
	if analyzeDate != "" {
		fmt.Printf("Analyzing date: %s\n", analyzeDate)
	} else {
		fmt.Println("Analyzing current logs")
	}
	fmt.Printf("Selected %d log file(s):\n", len(selectedFiles))
	for _, fileInfo := range selectedFiles {
		fmt.Printf("  - %s (", filepath.Base(fileInfo.Path))
		if !fileInfo.FirstTime.IsZero() && !fileInfo.LastTime.IsZero() {
			fmt.Printf("%s to %s", fileInfo.FirstTime.Format("Jan 2 15:04"), fileInfo.LastTime.Format("Jan 2 15:04"))
		} else {
			fmt.Printf("no timestamps")
		}
		fmt.Println(")")
	}
	fmt.Println()

	// Determine date range for filtering
	var filterStart, filterEnd time.Time
	if analyzeDate != "" {
		dataDate, _ := time.Parse("20060102", analyzeDate)
		filterStart = time.Date(dataDate.Year(), dataDate.Month(), dataDate.Day(), 0, 0, 0, 0, dataDate.Location())
		filterEnd = time.Date(dataDate.Year(), dataDate.Month(), dataDate.Day(), 23, 59, 59, 999999999, dataDate.Location())
	}
	// If no date specified, filterStart/filterEnd remain zero (no filtering)

	// Parse all selected files and aggregate results
	var allConnections []Connection
	for _, fileInfo := range selectedFiles {
		fmt.Printf("Processing: %s\n", filepath.Base(fileInfo.Path))

		reader, err := openLogFile(fileInfo.Path)
		if err != nil {
			fmt.Printf("Warning: Could not open %s: %v\n", filepath.Base(fileInfo.Path), err)
			continue
		}

		connections, err := parseLogReader(reader, filterStart, filterEnd)
		reader.Close()

		if err != nil {
			fmt.Printf("Warning: Error parsing %s: %v\n", filepath.Base(fileInfo.Path), err)
			continue
		}

		allConnections = append(allConnections, connections...)
	}
	fmt.Println()

	if len(allConnections) == 0 {
		fmt.Println("No connection data found in selected log files")
		return nil
	}

	// Analyze aggregated connections
	analysis := analyzeConnections(allConnections)

	// Create report file
	// For historic dates: use data date (no timestamp)
	// For current/today: include timestamp (data is still accumulating)
	var reportFile string
	today := time.Now().Format("20060102")
	if analyzeDate != "" && analyzeDate != today {
		// Historic date - use the data date (complete day)
		reportFile = fmt.Sprintf("/tmp/egress-connection-report-%s.txt", analyzeDate)
	} else {
		// Current log or today - include timestamp (ongoing)
		reportFile = fmt.Sprintf("/tmp/egress-connection-report-%s.txt", time.Now().Format("20060102-150405"))
	}

	fmt.Printf("Generating report: %s\n", reportFile)
	fmt.Println()

	// Generate report (to both stdout and file)
	report := generateAnalysisReport(analysis)

	// Display report
	fmt.Print(report)

	// Save report to file
	if err := os.WriteFile(reportFile, []byte(report), 0644); err != nil {
		fmt.Printf("Warning: Failed to save report file: %v\n", err)
	} else {
		fmt.Println()
		fmt.Printf("Report saved to: %s\n", reportFile)
		fmt.Println()
		fmt.Println("To view the report again:")
		fmt.Printf("  cat %s\n", reportFile)
	}

	return nil
}

// Connection represents a parsed connection
type Connection struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	Port      string
}

// AnalysisResult contains all analyzed data
type AnalysisResult struct {
	TotalConnections   int
	FirstTimestamp     time.Time
	LastTimestamp      time.Time
	DaysMonitored      int
	ConnectionsPerDay  int
	DstCounts          map[string]int
	SrcCounts          map[string]int
	PortCounts         map[string]int
	UniqueDestinations int
	UniqueSources      int
}

// parseLogReader parses log entries from a reader (testable with any io.Reader)
// Filters by date range if filterStart/filterEnd are not zero
func parseLogReader(reader io.Reader, filterStart, filterEnd time.Time) ([]Connection, error) {
	var connections []Connection
	scanner := bufio.NewScanner(reader)
	applyFilter := !filterStart.IsZero() && !filterEnd.IsZero()

	// Regex patterns
	srcRe := regexp.MustCompile(`SRC=([0-9.]+)`)
	dstRe := regexp.MustCompile(`DST=([0-9.]+)`)
	portRe := regexp.MustCompile(`DPT=([0-9]+)`)

	// Timestamp regex for syslog format: "Oct  9 10:30:15"
	timestampRe := regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "EGRESS_MONITOR") {
			continue
		}

		var conn Connection

		// Extract timestamp
		if match := timestampRe.FindStringSubmatch(line); len(match) > 1 {
			// Parse timestamp (assumes current year)
			timeStr := match[1] + " " + fmt.Sprintf("%d", time.Now().Year())
			if ts, err := time.Parse("Jan 2 15:04:05 2006", timeStr); err == nil {
				conn.Timestamp = ts
			}
		}

		// Apply date filter if specified
		if applyFilter && !conn.Timestamp.IsZero() {
			if conn.Timestamp.Before(filterStart) || conn.Timestamp.After(filterEnd) {
				continue // Skip entries outside date range
			}
		}

		if match := srcRe.FindStringSubmatch(line); len(match) > 1 {
			conn.SrcIP = match[1]
		}
		if match := dstRe.FindStringSubmatch(line); len(match) > 1 {
			conn.DstIP = match[1]
		}
		if match := portRe.FindStringSubmatch(line); len(match) > 1 {
			conn.Port = match[1]
		}

		if conn.SrcIP != "" && conn.DstIP != "" && conn.Port != "" {
			connections = append(connections, conn)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

// analyzeConnections performs analysis on a slice of connections
func analyzeConnections(connections []Connection) *AnalysisResult {
	analysis := &AnalysisResult{
		TotalConnections: len(connections),
		DstCounts:        make(map[string]int),
		SrcCounts:        make(map[string]int),
		PortCounts:       make(map[string]int),
	}

	if len(connections) == 0 {
		return analysis
	}

	// Find first and last timestamps
	analysis.FirstTimestamp = connections[0].Timestamp
	analysis.LastTimestamp = connections[0].Timestamp

	for _, conn := range connections {
		// Count destinations
		analysis.DstCounts[conn.DstIP]++

		// Count sources
		analysis.SrcCounts[conn.SrcIP]++

		// Count ports
		analysis.PortCounts[conn.Port]++

		// Track timestamp range
		if !conn.Timestamp.IsZero() {
			if conn.Timestamp.Before(analysis.FirstTimestamp) {
				analysis.FirstTimestamp = conn.Timestamp
			}
			if conn.Timestamp.After(analysis.LastTimestamp) {
				analysis.LastTimestamp = conn.Timestamp
			}
		}
	}

	analysis.UniqueDestinations = len(analysis.DstCounts)
	analysis.UniqueSources = len(analysis.SrcCounts)

	// Calculate days monitored
	if !analysis.FirstTimestamp.IsZero() && !analysis.LastTimestamp.IsZero() {
		duration := analysis.LastTimestamp.Sub(analysis.FirstTimestamp)
		analysis.DaysMonitored = int(duration.Hours()/24) + 1 // +1 to include partial days
		if analysis.DaysMonitored > 0 {
			analysis.ConnectionsPerDay = analysis.TotalConnections / analysis.DaysMonitored
		}
	}

	return analysis
}

// generateAnalysisReport generates a formatted report string
func generateAnalysisReport(analysis *AnalysisResult) string {
	var sb strings.Builder

	// Header
	sb.WriteString("╔═══════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║        Outbound Connection Analysis Report                               ║\n")
	sb.WriteString("╚═══════════════════════════════════════════════════════════════════════════╝\n")
	sb.WriteString("\n")

	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Log file: %s\n", LogFile))
	sb.WriteString(fmt.Sprintf("Total connections analyzed: %d\n", analysis.TotalConnections))
	sb.WriteString("\n")

	// Date range
	if !analysis.FirstTimestamp.IsZero() {
		sb.WriteString(fmt.Sprintf("Date range: %s to %s\n",
			analysis.FirstTimestamp.Format("Jan 2 15:04:05"),
			analysis.LastTimestamp.Format("Jan 2 15:04:05")))
		sb.WriteString("\n")
	}

	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("\n")

	// Top destination IPs
	sb.WriteString("TOP 20 DESTINATION IPs (by connection count)\n")
	sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")

	sortedDsts := sortMapByValue(analysis.DstCounts)
	for i, kv := range sortedDsts {
		if i >= 20 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %6d connections → %s\n", kv.Value, kv.Key))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Total unique destination IPs: %d\n", analysis.UniqueDestinations))
	sb.WriteString("\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("\n")

	// Connections by port
	sb.WriteString("CONNECTIONS BY PORT\n")
	sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")
	for _, port := range []string{"80", "443", "22"} {
		if count, ok := analysis.PortCounts[port]; ok {
			proto := map[string]string{"80": "HTTP", "443": "HTTPS", "22": "SSH"}[port]
			sb.WriteString(fmt.Sprintf("  Port %5s (%-6s): %6d connections\n", port, proto, count))
		}
	}
	sb.WriteString("\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("\n")

	// All unique IPs (numbered list)
	sb.WriteString("ALL UNIQUE DESTINATION IPs\n")
	sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("(This list can help plan capacity and understand traffic patterns)\n")
	sb.WriteString("\n")

	allDstIPs := make([]string, 0, len(analysis.DstCounts))
	for ip := range analysis.DstCounts {
		allDstIPs = append(allDstIPs, ip)
	}
	sort.Strings(allDstIPs)

	for i, ip := range allDstIPs {
		sb.WriteString(fmt.Sprintf("%3d. %s\n", i+1, ip))
	}
	sb.WriteString("\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("\n")

	// Top 10 with reverse DNS
	sb.WriteString("TOP 10 DESTINATIONS WITH REVERSE DNS\n")
	sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("(Note: DNS lookups may take a moment...)\n")
	sb.WriteString("\n")

	for i, kv := range sortedDsts {
		if i >= 10 {
			break
		}
		hostname := "(no reverse DNS)"
		if names, err := net.LookupAddr(kv.Key); err == nil && len(names) > 0 {
			hostname = names[0]
		}
		sb.WriteString(fmt.Sprintf("  %6d connections → %-15s %s\n", kv.Value, kv.Key, hostname))
	}
	sb.WriteString("\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("\n")

	// Source IPs (if multiple)
	if analysis.UniqueSources > 1 {
		sb.WriteString("SOURCE IPs (Internal Servers)\n")
		sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")

		sortedSrcs := sortMapByValue(analysis.SrcCounts)
		for _, kv := range sortedSrcs {
			sb.WriteString(fmt.Sprintf("  %6d connections from %s\n", kv.Value, kv.Key))
		}
		sb.WriteString("\n")
		sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")
		sb.WriteString("\n")
	}

	// Summary and recommendations
	sb.WriteString("SUMMARY & RECOMMENDATIONS\n")
	sb.WriteString("────────────────────────────────────────────────────────────────────────────\n")
	sb.WriteString("\n")
	sb.WriteString("Traffic Profile:\n")
	sb.WriteString(fmt.Sprintf("  • Total connections: %d\n", analysis.TotalConnections))
	sb.WriteString(fmt.Sprintf("  • Unique destinations: %d IPs\n", analysis.UniqueDestinations))
	if analysis.UniqueDestinations > 0 {
		sb.WriteString(fmt.Sprintf("  • Average connections per destination: %d\n",
			analysis.TotalConnections/analysis.UniqueDestinations))
	}

	if analysis.DaysMonitored > 0 {
		sb.WriteString(fmt.Sprintf("  • Days monitored: %d\n", analysis.DaysMonitored))
		sb.WriteString(fmt.Sprintf("  • Average connections per day: %d\n", analysis.ConnectionsPerDay))
	}
	sb.WriteString("\n")

	// Egress proxy planning
	sb.WriteString("Egress Proxy Planning:\n")
	sb.WriteString("  • Recommended egress proxy droplet size:\n")
	if analysis.ConnectionsPerDay < 10000 {
		sb.WriteString("    → s-1vcpu-2gb (low traffic)\n")
	} else if analysis.ConnectionsPerDay < 50000 {
		sb.WriteString("    → s-2vcpu-4gb (medium traffic)\n")
	} else {
		sb.WriteString("    → s-4vcpu-8gb or larger (high traffic)\n")
	}
	sb.WriteString("\n")
	sb.WriteString("  • Add this server's IP to egress proxy ACL after configuration\n")
	sb.WriteString("  • Monitor connection patterns for first few days after switching to proxy\n")
	sb.WriteString("\n")

	// Next steps
	sb.WriteString("Next Steps:\n")
	sb.WriteString("  1. Review the destination IPs and hostnames above\n")
	sb.WriteString("  2. Identify any unexpected connections\n")
	sb.WriteString("  3. Configure egress proxy: egressctl server configure <PROXY_IP>\n")
	sb.WriteString("  4. Add this server to proxy ACL: egressctl acl add <THIS_SERVER_IP>\n")
	sb.WriteString("\n")
	sb.WriteString("════════════════════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// KeyValue represents a key-value pair
type KeyValue struct {
	Key   string
	Value int
}

// sortMapByValue sorts a map by value (descending)
func sortMapByValue(m map[string]int) []KeyValue {
	var sorted []KeyValue
	for k, v := range m {
		sorted = append(sorted, KeyValue{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})
	return sorted
}
