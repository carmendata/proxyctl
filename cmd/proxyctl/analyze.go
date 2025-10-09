package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/carmendata/proxyctl/internal/logger"
)

const LogFile = logger.LogFile

// runLoggerAnalyze analyzes connection logs
func runLoggerAnalyze(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("analyze command does not accept arguments")
	}

	fmt.Println("Analyzing Outbound Connection Logs")
	fmt.Println()

	// Check if log file exists
	if _, err := os.Stat(LogFile); os.IsNotExist(err) {
		return fmt.Errorf("log file not found: %s\nHave you installed the connection logger?", LogFile)
	}

	// Check if log file has content
	info, err := os.Stat(LogFile)
	if err != nil {
		return fmt.Errorf("failed to stat log file: %w", err)
	}
	if info.Size() == 0 {
		fmt.Println("Warning: Log file is empty")
		fmt.Println("Either no connections have been made, or the logger just started.")
		return nil
	}

	// Create report file
	reportFile := fmt.Sprintf("/tmp/egress-connection-report-%s.txt", time.Now().Format("20060102-150405"))

	fmt.Printf("Analyzing logs from: %s\n", LogFile)
	fmt.Printf("Generating report: %s\n", reportFile)
	fmt.Println()

	// Parse log file with timestamps
	analysis, err := parseAndAnalyzeLogFile(LogFile)
	if err != nil {
		return fmt.Errorf("failed to parse log file: %w", err)
	}

	if analysis.TotalConnections == 0 {
		fmt.Println("No connection data found in logs")
		return nil
	}

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

// parseAndAnalyzeLogFile parses the log file and performs analysis
func parseAndAnalyzeLogFile(filename string) (*AnalysisResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var connections []Connection
	scanner := bufio.NewScanner(file)

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

	// Analyze connections
	analysis := &AnalysisResult{
		TotalConnections: len(connections),
		DstCounts:        make(map[string]int),
		SrcCounts:        make(map[string]int),
		PortCounts:       make(map[string]int),
	}

	if len(connections) == 0 {
		return analysis, nil
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

	return analysis, nil
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
