# User Stories for proxyctl

This document defines user stories for proxyctl functionality. Each story has a unique ID (S001-S030) that maps to test coverage in our test suite.

## Story Status Legend

**Regression Test Priority:**
- 🔥 **CRITICAL** - Protects production logic, must have regression tests
- ⚠️ **HIGH** - Important functionality, should have regression tests
- 📝 **MEDIUM** - Nice to have, test when stabilized
- 🔮 **FUTURE** - Feature not yet implemented, deferred to v1.1+

**Test Coverage Status:**
- ✅ **Tested** - Has regression test coverage protecting production behavior
- 🚧 **Partial** - Some coverage, needs expansion
- 🔄 **Deferred** - Implemented but tests deferred until feature stabilizes
- ⏳ **Future** - Not implemented, skipped for now (keeps numbering consistent)

---

## Regression Testing Focus

**For "production ready" v1.0, we focus on regression tests for:**
1. Core installation and firewall detection (S001-S004) - 🔥 CRITICAL
2. Connection logging functionality (S008-S011) - 🔥 CRITICAL
3. Clean removal (S018-S019) - 🔥 CRITICAL
4. Cross-platform compatibility (S024-S025) - 🔥 CRITICAL
5. Service continuity (S016) - 🔥 CRITICAL

**Stories marked as 🔮 FUTURE are kept for reference but skipped for now.**

---

## Installation & Environment Detection Stories

### S001: Clean System Installation
**Priority:** 🔥 CRITICAL
**Status:** ✅ Tested
**Regression Test:** Protects production installation logic

**As a** system administrator installing proxyctl on a clean server
**I want** the installer to detect my OS and firewall correctly
**So that** the appropriate installation method is used without manual configuration

**Acceptance Criteria:**
- [x] Detect Linux distribution (Ubuntu, Debian, CentOS)
- [x] Detect firewall type (iptables vs nftables)
- [x] Install appropriate dependencies for detected OS
- [x] Configure firewall using detected backend
- [x] Verify installation completes successfully

**Test Coverage:**
- `test/integration/test-suite-logger.sh::test_firewall_detection`
- `test/integration/test-suite-logger.sh::test_logger_install`

---

### S002: UFW Conflict Detection
**Priority:** 🔥 CRITICAL
**Status:** ✅ Tested
**Regression Test:** Prevents breaking production on Ubuntu systems with UFW

**As a** Ubuntu user with UFW active
**I want** proxyctl installation to detect the conflict and fail gracefully with clear instructions
**So that** I can make an informed decision about firewall management

**Acceptance Criteria:**
- [x] Detect if UFW is active
- [x] Display clear error message explaining the conflict
- [x] Provide options (disable UFW or abort installation)
- [x] Exit with error code if UFW is active
- [x] Error message includes WHY THIS MATTERS section
- [x] Error message includes SOLUTION with steps

**Test Coverage:**
- `internal/firewall/firewall_test.go::TestIsUFWActive`
- `internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`
- `test/integration/test-suite-firewall.sh::test_ufw_conflict`

**Implementation:** `internal/firewall/firewall.go:checkConflictingFirewallManagers()`

---

### S003: firewalld Conflict Detection
**Priority:** 🔥 CRITICAL
**Status:** ✅ Tested
**Regression Test:** Prevents breaking production on RHEL/CentOS systems with firewalld

**As a** RHEL/CentOS user with firewalld active
**I want** proxyctl installation to detect the conflict and provide clear options
**So that** I don't accidentally bypass my firewall manager

**Acceptance Criteria:**
- [x] Detect if firewalld is active
- [x] Display clear error message explaining the conflict
- [x] Provide options (disable firewalld or abort installation)
- [x] Exit with error code if firewalld is active
- [x] Error message includes WHY THIS MATTERS section
- [x] Error message includes SOLUTION with steps

**Test Coverage:**
- `internal/firewall/firewall_test.go::TestIsFirewalldActive`
- `internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`
- `test/integration/test-suite-firewall.sh::test_firewalld_conflict`

**Implementation:** `internal/firewall/firewall.go:checkConflictingFirewallManagers()`

---

### S004: Multiple Firewall Backend Support
**Priority:** 🔥 CRITICAL
**Status:** ✅ Tested
**Regression Test:** Ensures firewall detection works across Ubuntu/Debian/CentOS

**As a** user on different Linux distributions
**I want** proxyctl to correctly choose between iptables and nftables based on my system configuration
**So that** monitoring works regardless of my firewall backend

**Acceptance Criteria:**
- [x] Prefer nftables if available and configured
- [x] Fall back to iptables if nftables not available
- [x] Detect correct config paths for each distro
- [x] Create persistent rules for chosen backend
- [x] Verify rules are active after creation

**Test Coverage:**
- `internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`
- `test/integration/test-suite-firewall.sh::test_firewall_type_detection`
- `test/integration/test-suite-logger.sh::test_logger_install` (verifies rules created)

**Implementation:**
- `internal/firewall/firewall.go:Detect()`
- `internal/logger/logger.go:Install()` (uses detected type)

---

## Upgrade & Migration Stories

### S005: Version Upgrade Preservation
**Priority:** ⚠️ HIGH
**Status:** 🚧 Partial
**Regression Test:** Critical for production deployments with accumulated logs

**As an** existing proxyctl user upgrading versions
**I want** my connection logs to be preserved during the upgrade
**So that** I don't lose historical network data

**Acceptance Criteria:**
- [x] Log files naturally preserved (not deleted during upgrade)
- [x] Preserve log rotation configuration
- [x] Verify logs are still accessible after upgrade
- [ ] Explicit upgrade test (simulate upgrade scenario)
- [ ] Document upgrade procedure clearly

**Test Coverage:**
- `internal/logger/logger.go:Install()` - Idempotent (preserves existing logs)
- `test/integration/test-suite-logger.sh::test_idempotency_install` - Verifies re-install preserves logs
- **Need:** Explicit upgrade scenario test (v0.1.0 → v0.2.0)

**Implementation:**
- `internal/logger/logger.go:Install()` - Does NOT delete /var/log/egress-connections.log
- `internal/logger/logger.go:configureLogrotate()` - Rewrites config (preserves rotation)
- `internal/logger/logger.go:configureRsyslog()` - Rewrites config (preserves log path)

**Notes:**
- **Production Status**: Already deployed on production and staging servers accumulating logs
- **Risk**: Must not lose logs during upgrades
- **Current Behavior**: Logs ARE preserved (verified by idempotency tests)
- **Still Needed**: Explicit upgrade documentation and upgrade scenario tests

---

### S006: Configuration Migration
**Priority:** ⚠️ HIGH
**Status:** 🚧 Partial
**Regression Test:** Critical for production deployments receiving config updates

**As a** user upgrading from an older version with config file changes
**I want** the new version to safely update configurations without breaking existing setups
**So that** I get the latest config templates while preserving functionality

**Acceptance Criteria:**
- [x] Detect existing configuration files (rsyslog, logrotate)
- [x] Safely overwrite with new config templates
- [x] Preserve critical settings (log paths, rotation policies)
- [ ] Backup old configuration before overwriting
- [ ] Validate new config before applying
- [ ] Log migration actions

**Test Coverage:**
- `internal/logger/logger.go:configureRsyslog()` - Overwrites config (safe, preserves log path)
- `internal/logger/logger.go:configureLogrotate()` - Overwrites config (safe, preserves retention)
- `test/integration/test-suite-upgrade.sh` - Verifies config preserved during upgrade
- **Need:** Explicit config backup before overwrite

**Implementation:**
- `internal/logger/logger.go:configureRsyslog()` - Writes /etc/rsyslog.d/99-egress-monitor.conf
- `internal/logger/logger.go:configureLogrotate()` - Writes /etc/logrotate.d/egress-monitor
- Config overwrites are safe (no user-customizable settings currently)

**Notes:**
- **Production Status**: Production servers have rsyslog and logrotate configs that may be overwritten during upgrades
- **Risk**: Config changes between versions could break logging if not handled carefully
- **Current Behavior**: Configs are safely overwritten (log paths and policies preserved)
- **Still Needed**: Config validation before applying, backup old configs

---

### S007: Broken Installation Recovery
**Priority:** ⚠️ HIGH
**Status:** 🚧 Partial
**Regression Test:** Idempotent install already provides recovery - additional tests deferred

**As a** user whose previous installation failed partially
**I want** the new installer to detect and clean up the broken state before proceeding
**So that** I get a fresh, working installation

**Acceptance Criteria:**
- [x] Detect existing firewall rules (partially installed)
- [x] Detect existing config files
- [x] Idempotent installation (can run multiple times)
- [ ] Automatically clean up if `--force` flag provided (future enhancement)
- [ ] Explicit broken-state detection and recovery (future enhancement)

**Test Coverage:**
- `test/integration/test-suite-logger.sh::test_idempotency_install` (protects re-install behavior)
- `internal/logger/logger.go:checkNotInstalled()` (partial detection)

**Notes:** Current idempotent behavior handles most broken-state scenarios. Explicit `--force` cleanup can be added in v1.1+.

---

## Logging & Monitoring Stories

### S008: Connection Capture Accuracy
**Priority:** 🔥 CRITICAL
**Status:** ✅ Tested
**Regression Test:** Protects core logging functionality - TCP/UDP capture logic

**As a** security administrator
**I want** proxyctl to log all NEW outbound TCP and UDP connections to public IPs
**So that** I have complete visibility into external communications

**Acceptance Criteria:**
- [x] Log NEW TCP connections (SYN packets)
- [x] Log NEW UDP connections
- [x] Include source IP, destination IP, port, protocol
- [x] Include timestamp for each connection
- [x] Only log connections to public IPs (exclude private ranges)

**Test Coverage:**
- `internal/logger/logger_test.go::TestIPTablesPrivateRanges`
- `internal/logger/logger_test.go::TestNFTablesConfigGeneration`
- `test/integration/test-suite-logger.sh::test_log_generation`

**Implementation:**
- `internal/logger/logger.go:createIPTablesRules()` (iptables)
- `internal/logger/logger.go:createNFTablesRules()` (nftables)

---

### S009: Private IP Filtering
**Status:** ✅ Implemented & Tested

**As a** network administrator
**I want** proxyctl to exclude connections to private IP ranges from logs
**So that** internal traffic doesn't clutter my external connection analysis

**Acceptance Criteria:**
- [x] Exclude 10.0.0.0/8 (Private Class A)
- [x] Exclude 172.16.0.0/12 (Private Class B)
- [x] Exclude 192.168.0.0/16 (Private Class C)
- [x] Exclude 169.254.0.0/16 (Link-local)
- [x] Exclude 127.0.0.0/8 (Loopback)
- [x] Exclude 224.0.0.0/4 (Multicast)
- [x] Exclude 240.0.0.0/4 (Reserved)

**Test Coverage:**
- `internal/logger/logger_test.go::TestIPTablesPrivateRanges`
- `internal/logger/logger_test.go::TestNFTablesConfigGeneration` (verifies private ranges in config)

**Implementation:**
- `internal/logger/logger.go:createIPTablesRules()` (privateRanges array)
- `internal/logger/logger.go:createNFTablesRules()` (privateRanges array)

---

### S010: Log File Management
**Status:** ✅ Implemented & Tested

**As a** user running proxyctl long-term
**I want** log rotation to work properly
**So that** my disk space doesn't fill up with connection logs over time

**Acceptance Criteria:**
- [x] Rotate logs daily
- [x] Keep 14 days of logs
- [x] Compress old logs
- [x] Create logrotate configuration
- [x] Restart rsyslog after rotation

**Test Coverage:**
- `internal/logger/logger_test.go::TestConfigureLogrotate`
- `test/integration/test-suite-logger.sh::test_logger_install` (verifies logrotate config created)

**Implementation:**
- `internal/logger/logger.go:configureLogrotate()` (creates /etc/logrotate.d/egress-monitor)

---

### S011: Real-time Monitoring
**Status:** ✅ Implemented & Tested

**As an** operations engineer
**I want** to see connection logs in real-time using standard tools (tail -f)
**So that** I can monitor network activity as it happens

**Acceptance Criteria:**
- [x] Logs written to standard file (/var/log/proxyctl/egress.log)
- [x] rsyslog configured to route logs correctly
- [x] Logs appear in real-time (not buffered)
- [x] Standard log format (parseable)
- [x] Log prefix identifies proxyctl logs (EGRESS_MONITOR)

**Test Coverage:**
- `internal/logger/logger_test.go::TestConfigureRsyslog`
- `internal/logger/logger_test.go::TestLogPrefix`
- `test/integration/test-suite-logger.sh::test_log_generation` (verifies actual logs)

**Implementation:**
- `internal/logger/logger.go:configureRsyslog()` (creates /etc/rsyslog.d/99-egress-monitor.conf)

---

## Analysis & Reporting Stories

### S012: Connection Analysis
**Status:** ✅ Implemented

**As a** network analyst
**I want** to run connection analysis reports that show top destinations, ports, and protocols
**So that** I can understand my applications' network dependencies

**Acceptance Criteria:**
- [x] Parse connection logs into structured data
- [x] Aggregate by destination IP
- [x] Aggregate by destination port
- [x] Aggregate by protocol (TCP/UDP)
- [x] Show top N destinations/ports
- [ ] Export results in table format (table output implemented, additional formats planned)

**Test Coverage:** None yet (unit tests needed for cmd/proxyctl/analyze.go)

**Implementation:**
- `cmd/proxyctl/analyze.go` - Pure Go implementation with timestamp-based file selection
- Supports `--date YYYYMMDD` flag for specific date analysis
- Automatically handles gzipped log files
- Multi-file aggregation across log rotations
- Filters by date range during parsing

**Notes:**
- Replaces legacy script `scripts.legacy.reference.only/analyze-connection-logs.sh`
- Uses timestamp-based file selection (no date math assumptions)
- Works with manual log rotations and timezone issues

---

### S013: Historical Data Analysis
**Status:** 🚧 Partial

**As a** compliance officer
**I want** to analyze connection patterns over time periods (days/weeks)
**So that** I can generate network usage reports for audits

**Acceptance Criteria:**
- [x] Parse logs from multiple days
- [ ] Filter by date range (--from/--to flags)
- [ ] Show trends over time
- [ ] Identify anomalies (unusual destinations/ports)
- [ ] Export time-series data

**Test Coverage:** None yet

**Implementation:**
- `cmd/proxyctl/analyze.go` supports single-day analysis via `--date` flag
- Multi-file aggregation infrastructure in place
- Can add `--from`/`--to` flags in future iteration

**Notes:** Basic single-day analysis implemented. Date range filtering planned for future release.

---

### S014: Export Functionality
**Status:** ⏳ Planned

**As a** data analyst
**I want** to export connection data in standard formats
**So that** I can integrate it with other security and monitoring tools

**Acceptance Criteria:**
- [ ] Export to JSON
- [ ] Export to CSV
- [ ] Export to syslog format
- [ ] Stream to external tools (Splunk, ELK)
- [ ] Webhook integration

**Test Coverage:** None (planned feature)

---

## System Stability Stories

### S015: Zero-Impact Monitoring
**Status:** 🚧 Partially Tested

**As a** production system owner
**I want** proxyctl monitoring to have zero impact on my application performance
**So that** monitoring doesn't affect my service levels

**Acceptance Criteria:**
- [x] Firewall rules use RETURN (no blocking)
- [ ] Measure CPU overhead (should be <1%)
- [ ] Measure memory overhead (should be <10MB)
- [ ] No impact on connection latency
- [ ] No packet drops

**Test Coverage:**
- Code review: `internal/logger/logger.go` (rules use RETURN/accept only)
- Integration test verifies services continue running

**Notes:** Need performance benchmarking tests.

---

### S016: Service Continuity
**Status:** ✅ Implemented & Tested

**As a** system administrator
**I want** my existing services to continue running normally during and after proxyctl installation
**So that** there's no downtime

**Acceptance Criteria:**
- [x] No service restarts during installation (except rsyslog)
- [x] No network interruption
- [x] Firewall rules only log (don't block)
- [x] Existing firewall rules preserved
- [x] HAProxy continues running (if already running)

**Test Coverage:**
- `test/integration/test-suite-logger.sh::test_logger_install` (verifies non-destructive)
- Code review: All firewall rules use RETURN/accept policy

**Implementation:**
- `internal/logger/logger.go:createIPTablesRules()` (ends with RETURN)
- `internal/logger/logger.go:createNFTablesRules()` (policy accept)

---

### S017: Resource Usage
**Status:** ⏳ Planned

**As a** capacity planner
**I want** proxyctl to use minimal system resources (CPU, memory, disk)
**So that** it doesn't compete with my primary applications

**Acceptance Criteria:**
- [ ] Binary size < 10MB
- [ ] Memory usage < 20MB
- [ ] CPU usage < 1% average
- [ ] Disk I/O minimal (async logging)
- [ ] Log rotation prevents disk fill

**Test Coverage:** None (need performance benchmarks)

**Notes:** Log rotation is configured (S010), but need explicit resource monitoring.

---

## Removal & Cleanup Stories

### S018: Clean Removal
**Status:** ✅ Implemented & Tested

**As a** system administrator who needs to remove proxyctl
**I want** the removal process to clean up all components
**So that** my system returns to its pre-installation state

**Acceptance Criteria:**
- [x] Remove firewall rules (iptables or nftables)
- [x] Remove rsyslog configuration
- [x] Remove logrotate configuration
- [x] Remove systemd service (if exists)
- [ ] Remove binary (manual step)
- [ ] Option to preserve or remove logs

**Test Coverage:**
- `internal/logger/logger_test.go::TestRemoveRsyslogConfig`
- `internal/logger/logger_test.go::TestRemoveLogrotateConfig`
- `test/integration/test-suite-logger.sh::test_logger_remove`

**Implementation:**
- `internal/logger/logger.go:Remove()`

---

### S019: Firewall Rule Cleanup
**Status:** ✅ Implemented & Tested

**As a** security administrator removing proxyctl
**I want** all firewall rules to be properly removed
**So that** no orphaned rules remain in my firewall configuration

**Acceptance Criteria:**
- [x] Remove iptables EGRESS_LOG chain
- [x] Remove iptables jump rule from OUTPUT chain
- [x] Remove nftables egress_monitor table
- [x] Remove nftables config file
- [x] Remove include directive from main nftables.conf
- [x] Verify no rules remain after removal

**Test Coverage:**
- `test/integration/test-suite-logger.sh::test_logger_remove` (verifies rules removed)

**Implementation:**
- `internal/logger/logger.go:removeIPTablesRules()`
- `internal/logger/logger.go:removeNFTablesRules()`

---

### S020: Log Preservation Option
**Status:** ⏳ Planned

**As a** compliance officer during proxyctl removal
**I want** the option to preserve historical log data
**So that** I can retain network analysis data even after removing the monitoring tool

**Acceptance Criteria:**
- [ ] Prompt user about log preservation
- [ ] Option: `--keep-logs` flag
- [ ] Remove monitoring but keep logs
- [ ] Document log location before removal
- [ ] Warn if logs will be deleted

**Test Coverage:** None (planned feature)

**Notes:** Currently logs are not removed by `egressctl logger remove`. Need explicit handling.

---

## Error Handling & Edge Cases

### S021: Permission Handling
**Status:** 🚧 Partially Tested

**As a** non-root user
**I want** proxyctl to provide clear error messages about required permissions
**So that** I know exactly what access is needed

**Acceptance Criteria:**
- [ ] Detect if running as root
- [ ] Display clear error if not root
- [ ] Explain why root is needed
- [ ] List specific operations requiring root
- [ ] Suggest using sudo

**Test Coverage:** Partial (errors occur but not explicitly tested)

**Notes:** Need explicit permission check tests.

---

### S022: Disk Space Handling
**Status:** ⏳ Planned

**As a** system administrator
**I want** proxyctl to handle low disk space gracefully without crashing
**So that** system stability is maintained even when storage is constrained

**Acceptance Criteria:**
- [ ] Check available disk space before installation
- [ ] Warn if disk space low (<1GB)
- [ ] Handle write failures gracefully
- [ ] Log rotation prevents disk fill
- [ ] Resume logging when space available

**Test Coverage:** None (planned)

**Notes:** Log rotation is configured (helps prevent fill), but need explicit checks.

---

### S023: Network Connectivity Issues
**Status:** ⏳ Planned

**As a** user installing proxyctl on a system with limited internet access
**I want** clear error messages when downloads fail
**So that** I can troubleshoot connectivity issues

**Acceptance Criteria:**
- [ ] Detect network connectivity
- [ ] Provide clear error if downloads fail
- [ ] Support offline installation (local binary)
- [ ] Suggest alternatives (mirror, manual download)
- [ ] Verify checksums when downloading

**Test Coverage:** None (planned)

**Notes:** Installation currently assumes local binary or package manager handles this.

---

## Cross-Platform Compatibility Stories

### S024: CentOS/RHEL Support
**Status:** ✅ Implemented & Tested

**As a** CentOS Stream user
**I want** proxyctl to work with my system's specific paths
**So that** firewall persistence works correctly

**Acceptance Criteria:**
- [x] Detect CentOS/RHEL system
- [x] Use /etc/sysconfig/nftables.conf for nftables
- [x] Support yum/dnf package manager
- [x] Handle SELinux contexts (if needed)
- [x] Verify rules persist across reboots

**Test Coverage:**
- `internal/logger/logger_test.go::TestFindNFTablesMainConf` (tests CentOS path)
- `test/integration/run-integration-tests.sh` (supports centos-9)
- `test/integration/bootstrap-droplet.sh` (CentOS-specific setup)

**Implementation:**
- `internal/logger/logger.go:nftablesMainConfPaths` (includes CentOS path)

---

### S025: Ubuntu/Debian Support
**Status:** ✅ Implemented & Tested

**As an** Ubuntu user
**I want** proxyctl to work with my system's firewall configuration paths
**So that** rules persist across reboots

**Acceptance Criteria:**
- [x] Detect Ubuntu/Debian system
- [x] Use /etc/nftables.conf for nftables
- [x] Support apt package manager
- [x] Handle both iptables and nftables
- [x] Verify rules persist across reboots

**Test Coverage:**
- `internal/logger/logger_test.go::TestFindNFTablesMainConf` (tests Debian path)
- `test/integration/run-integration-tests.sh` (supports ubuntu-22-04, ubuntu-20-04, debian-12)
- `test/integration/bootstrap-droplet.sh` (Ubuntu/Debian-specific setup)

**Implementation:**
- `internal/logger/logger.go:nftablesMainConfPaths` (includes Debian/Ubuntu path)

---

### S026: Architecture Detection
**Priority:** ⚠️ HIGH
**Status:** 🚧 Partial
**Regression Test:** Critical for DigitalOcean deployments on ARM and x86

**As a** user on different hardware (x86_64, ARM64)
**I want** proxyctl to download the correct binary for my architecture
**So that** installation succeeds regardless of my hardware platform

**Acceptance Criteria:**
- [x] Build for linux/amd64
- [x] Build for linux/arm64
- [x] Build for darwin/amd64 (Intel Mac)
- [x] Build for darwin/arm64 (Apple Silicon)
- [ ] Auto-detect architecture during installation
- [ ] Download correct binary for architecture
- [ ] Verify binary compatibility before running
- [ ] Test on ARM droplets in integration tests

**Test Coverage:**
- `Makefile:build-release` (builds multiple architectures)
- Integration tests run on amd64 droplets (ubuntu-22-04, debian-12, centos-9)
- **Need:** Integration tests on ARM droplets

**Implementation:**
- `Makefile:build-release` - Cross-compilation for amd64/arm64
- `install.sh` - Needs architecture detection logic

**Notes:**
- **Production Status**: Deploying on DigitalOcean which offers both amd64 and ARM droplets
- **Risk**: Wrong architecture binary fails to execute
- **Current Behavior**: Build system produces all architectures, but installer doesn't auto-detect
- **Still Needed:**
  - Auto-detect in install script
  - ARM integration testing

---

## Security & Compliance Stories

### S027: Audit Trail
**Status:** 🚧 Partially Tested

**As a** security auditor
**I want** all proxyctl installation and configuration changes to be logged
**So that** I can track what network monitoring capabilities were added to systems

**Acceptance Criteria:**
- [ ] Log installation to syslog
- [ ] Log configuration changes
- [ ] Log firewall rule modifications
- [x] Store all configs in standard locations (/etc)
- [ ] Record who installed (user/timestamp)

**Test Coverage:**
- File creation is tested, but audit logging is not

**Notes:** Configs are created in standard locations (auditable). Need explicit audit logging.

---

### S028: Privilege Separation
**Status:** ⏳ Planned

**As a** security engineer
**I want** proxyctl to operate with minimal required privileges
**So that** the attack surface is minimized

**Acceptance Criteria:**
- [ ] Binary runs with minimal capabilities
- [ ] No setuid/setgid binaries
- [ ] Firewall rules use least privilege
- [ ] Log files have restrictive permissions
- [ ] No world-readable sensitive configs

**Test Coverage:** Partial (file permissions tested)

**Notes:** Need explicit privilege analysis and testing.

---

### S029: Configuration Validation
**Status:** 🚧 Partially Tested

**As a** system administrator
**I want** proxyctl to validate its configuration before activating
**So that** invalid configurations don't cause monitoring failures

**Acceptance Criteria:**
- [x] Validate JSON config syntax (if using config files)
- [ ] Check firewall rules are valid before applying
- [ ] Verify log paths are writable
- [ ] Test rsyslog config before restarting service
- [x] Fail fast with clear error messages

**Test Coverage:**
- `internal/config/config.go:Validate()` (basic validation)
- Need more comprehensive validation tests

**Implementation:**
- `internal/config/config.go:Validate()`

---

## Integration Testing Stories

### S030: Multiple Service Coexistence
**Status:** 🚧 Partially Tested

**As a** system running multiple network services
**I want** proxyctl monitoring to work alongside all services
**So that** I get complete network visibility without conflicts

**Acceptance Criteria:**
- [x] Works with HAProxy running
- [ ] Works with Docker installed
- [ ] Works with custom iptables rules
- [ ] Works with VPN clients
- [x] No interference with application traffic

**Test Coverage:**
- `test/integration/bootstrap-droplet.sh` (sets up HAProxy)
- `test/integration/test-suite-logger.sh` (verifies coexistence)

**Notes:** Need explicit tests with Docker, VPNs, custom firewall rules.

---

## Summary

### Regression Test Coverage (Production-Ready v1.0)

**🔥 CRITICAL Priority Stories (12 stories) - MUST HAVE REGRESSION TESTS:**
- S001: Clean System Installation ✅
- S002: UFW Conflict Detection ✅
- S003: firewalld Conflict Detection ✅
- S004: Multiple Firewall Backend Support ✅
- S008: Connection Capture Accuracy ✅
- S009: Private IP Filtering ✅
- S010: Log File Management ✅
- S011: Real-time Monitoring ✅
- S016: Service Continuity ✅
- S018: Clean Removal ✅
- S019: Firewall Rule Cleanup ✅
- S024: CentOS/RHEL Support ✅
- S025: Ubuntu/Debian Support ✅

**⚠️ HIGH Priority Stories (7 stories) - SHOULD HAVE TESTS:**
- S005: Version Upgrade Preservation 🚧 (logs preserved, needs explicit upgrade tests)
- S006: Configuration Migration 🚧 (configs preserved, needs backup mechanism)
- S007: Broken Installation Recovery 🚧 (idempotency tested)
- S021: Permission Handling 🔄 (deferred to v1.1)
- S026: Architecture Detection 🚧 (builds work, needs install script auto-detect + ARM testing)
- S029: Configuration Validation 🚧 (basic validation tested)
- S030: Multiple Service Coexistence 🚧 (HAProxy tested, Docker/VPN pending)

**📝 MEDIUM Priority Stories (1 story) - NICE TO HAVE:**
- S015: Zero-Impact Monitoring 🔄 (code review confirms, benchmarks deferred)

**🔮 FUTURE Stories (11 stories) - DEFERRED TO v1.1+:**
- S012-S014: Analysis & Reporting ⏳
- S017: Resource Usage ⏳
- S020: Log Preservation Option ⏳
- S022-S023: Error Handling Edge Cases ⏳
- S027-S028: Security & Compliance ⏳

### Test Coverage Status

**By Status:**
- ✅ **Tested (Regression Protected):** 13 stories (43%)
- 🚧 **Partial Coverage:** 7 stories (23%)
- 🔄 **Deferred (v1.1):** 2 stories (7%)
- ⏳ **Future Feature:** 8 stories (27%)
- **Total:** 30 stories

**By Category:**
- **Installation & Detection:** 4/4 ✅ (100% - All CRITICAL)
- **Upgrade & Migration:** 2/3 🚧 (S005-S006 partial, S007 needs work)
- **Logging & Monitoring:** 4/4 ✅ (100% - All CRITICAL)
- **Analysis & Reporting:** 0/3 ⏳ (Feature work for v1.1+)
- **System Stability:** 1/3 ✅ (S016 critical, others deferred)
- **Removal & Cleanup:** 2/3 ✅ (S018-S019 critical, S020 deferred)
- **Error Handling:** 0/3 ⏳ (Deferred to v1.1+)
- **Cross-Platform:** 2/3 🚧 (S024-S025 ✅ critical, S026 🚧 needs ARM testing)
- **Security & Compliance:** 0/3 🔄 (Deferred to v1.1+)
- **Integration:** 0/1 🚧 (S030 partial - needs Docker/VPN tests)

### Regression Test Goal

**For production-ready v1.0, focus on:**
- **13 CRITICAL stories** with full regression test coverage ✅
- **4 HIGH priority stories** with partial coverage 🚧

This protects the core production logic while deferring nice-to-have features and edge cases to future releases.

---

## Contributing

When implementing or testing a story:
1. Update the story status
2. Check off acceptance criteria as completed
3. Add test coverage references
4. Link to implementation code
5. Update the summary counts
