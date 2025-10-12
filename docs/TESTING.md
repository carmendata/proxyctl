# Testing Strategy for proxyctl

This document outlines the complete testing strategy for proxyctl, including unit tests (local) and integration tests (DigitalOcean infrastructure).

## Overview

**Testing Philosophy**: Two-tier testing approach
- **Unit Tests**: Fast, local, no system dependencies (runs in CI/CD)
- **Integration Tests**: Real infrastructure, actual firewall/systemctl commands (runs on DigitalOcean test droplets)

## Current Test Coverage

Run `make coverage` to see overall coverage, or `make coverage-pkg PKG=./internal/<package>` for specific packages.

```bash
# Overall coverage
make coverage

# Specific package
make coverage-pkg PKG=./internal/logger
make coverage-pkg PKG=./internal/acl
make coverage-pkg PKG=./internal/config
```

### Coverage Status (as of latest)

| Package              | Unit Coverage | Integration Coverage | Notes                                    |
|----------------------|---------------|----------------------|------------------------------------------|
| internal/acl         | 79.5%         | N/A                  | Pure file operations, well tested        |
| internal/logger      | 11.5%         | Required             | System calls need integration tests      |
| internal/firewall    | 5.4%          | Required             | Detection logic needs real systems       |
| internal/config      | 0%            | Planned              | Needs unit tests for config loading      |
| cmd/proxyctl         | 0%            | Planned              | Command routing needs tests              |

**Note**: Low coverage in logger/firewall is expected - these packages interact with system tools (iptables, nftables, systemctl) that can't be unit tested without mocking.

## Unit Testing (Local)

### What We Test Locally

✅ **File Operations**
- ACL file read/write/modify
- Config file generation (rsyslog, logrotate, nftables)
- File permissions and ownership validation

✅ **Configuration Parsing**
- JSON config loading
- Environment variable overrides
- Default value application
- Validation logic

✅ **Helper Functions**
- String utilities (containsString, etc.)
- Path resolution (findNFTablesMainConf)
- Config content generation

✅ **Error Handling**
- Invalid inputs
- Missing files
- Permission errors (simulated)

### What We DON'T Test Locally

❌ **System Commands**
- `systemctl` (start/stop/reload services)
- `iptables` / `nft` (firewall rule manipulation)
- `haproxy -c` (config validation)
- SSH connections to remote servers

❌ **Integration Scenarios**
- Actual firewall rule creation
- Service restarts
- Multi-server coordination
- HAProxy reload behavior

### Running Unit Tests

```bash
# All tests with race detector (recommended)
make test

# With coverage report
make coverage

# Specific package with detailed coverage
make coverage-pkg PKG=./internal/logger

# Fast tests only (skip integration markers)
go test -short ./...

# CI pipeline (race detector + coverage)
make ci
```

### Writing New Unit Tests

Follow the pattern in `internal/acl/acl_test.go` and `internal/logger/logger_test.go`:

```go
func TestFeature(t *testing.T) {
    tests := []struct {
        name      string
        input     string
        wantErr   bool
        validate  func(*testing.T, result)
    }{
        // Test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Use t.TempDir() for file operations
            tmpDir := t.TempDir()

            // Test logic

            // Use testutil helpers
            testutil.AssertFileExists(t, path)
            testutil.AssertFileContains(t, path, expected)
        })
    }
}
```

**Test Utilities**: Use `internal/testutil` package for common test operations.

## Integration Testing (DigitalOcean)

**For complete integration testing documentation, see [`test/integration/README.md`](../test/integration/README.md)** (single source of truth).

### Quick Overview

We use ephemeral DigitalOcean droplets to test real system interactions:

**Test Environment**:
- **Droplet Size**: s-1vcpu-1gb ($6/month, hourly billing)
- **OS Images**: Ubuntu 24.04/22.04 LTS, Debian 12, Rocky Linux 8, CentOS Stream 9
- **Firewall Coverage**: iptables (Rocky 8) and nftables (Ubuntu, Debian, CentOS 9)
- **Lifecycle**: Create SSH Key → Create Droplet → Test → Destroy All (< 30 minutes)
- **Cost**: ~$0.01 per test run
- **SSH Keys**: Automatically created and cleaned up (no manual setup required)

### Quick Start

**One-time setup:**

```bash
# Create .env file with your DigitalOcean credentials
cd test/integration
cp .env.example .env
vim .env  # Add your DO_API_TOKEN
```

**Running tests:**

```bash
# Commit your changes first (required!)
git add .
git commit -m "Your changes"

# Run tests (credentials loaded from .env automatically)
cd test/integration
./run-integration-tests.sh --all
./run-integration-tests.sh --os ubuntu-22-04
./run-integration-tests.sh --os debian-12 --suite logger
```

**Important Notes**:
- **Use `.env` file for credentials** (set once, never committed to git)
- **Clean git working tree required** - ensures reproducibility and release tracking
- See [test/integration/README.md](../test/integration/README.md) for complete documentation

**See [`test/integration/README.md`](../test/integration/README.md) for:**
- Complete setup instructions
- Available test suites
- Debugging failed tests
- Writing new integration tests

### What We Test on Real Infrastructure

Integration tests verify:
- ✅ Firewall detection (iptables vs nftables)
- ✅ **Dual firewall support** (iptables on Rocky 8, nftables on Ubuntu/Debian/CentOS 9)
- ✅ UFW/firewalld conflict detection
- ✅ Logger installation and actual log generation
- ✅ Service restarts (rsyslog)
- ✅ Firewall rule persistence
- ✅ Cross-distro compatibility (Ubuntu, Debian, Rocky, CentOS)
- ✅ Idempotency (install/remove multiple times)
- ✅ Clean removal (no orphaned configs)
- ✅ **Upgrade scenarios (log preservation)** - NEW for production
- ✅ **Configuration migration (safe config updates)** - NEW for production
- ✅ **Architecture detection (x86_64/amd64)** - Verified on major distros

**Note on iptables support**: We currently test both iptables (Rocky 8) and nftables to support legacy production servers. Once all servers are migrated to nftables-based distributions (Ubuntu 22.04+, Debian 12+, RHEL 9+), we can drop iptables support entirely. See `internal/firewall/firewall.go` for migration checklist.

**For detailed test descriptions, see [`test/integration/README.md`](../test/integration/README.md)**

## CI/CD Integration

### GitHub Actions (or similar)

**.github/workflows/test.yml**:
```yaml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
      - run: make ci  # lint + test with race detector

  integration-tests:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'  # Only on main branch
    steps:
      - uses: actions/checkout@v3
      - name: Install doctl
        run: |
          wget https://github.com/digitalocean/doctl/releases/download/v1.98.1/doctl-1.98.1-linux-amd64.tar.gz
          tar xf doctl-*.tar.gz
          sudo mv doctl /usr/local/bin
          doctl auth init --access-token ${{ secrets.DO_API_TOKEN }}
      - name: Run integration tests
        run: |
          cd test/integration
          ./run-integration-tests.sh --all
        env:
          DO_API_TOKEN: ${{ secrets.DO_API_TOKEN }}
```

**Note**: SSH keys are created automatically - only `DO_API_TOKEN` secret is required.

## Release Safety Mechanism

**Automated Integration Test Verification**: To prevent releasing untested code, `make release` automatically verifies that integration tests have passed on the current commit.

### How It Works

1. **Integration tests write status file**: When `test/integration/run-integration-tests.sh` completes, it writes `.integration-test-status` with:
   - Git commit SHA
   - Test result (passed/failed)
   - Timestamp
   - Tested distributions

2. **Release checks status file**: Before creating a release, `make release` verifies:
   - ✅ Status file exists
   - ✅ Commit SHA matches current HEAD
   - ✅ Tests passed (not failed)

3. **Release blocked if tests not run**: If verification fails, you'll see a clear error with instructions.

### Override (Emergency Use Only)

If you **must** release without integration tests:
```bash
FORCE_RELEASE=true make release
```

**⚠️ Warning**: This should only be used for documentation-only changes or emergency hotfixes.

### Example Workflow

```bash
# 1. Make code changes
# ... edit files ...

# 2. Commit changes (required for integration tests!)
git add .
git commit -m "Add new feature"

# 3. Run integration tests
cd test/integration
./run-integration-tests.sh --all

# 4. Tests pass → .integration-test-status written automatically

# 5. Create release (will verify tests passed on current commit)
cd ../..
make release
```

See [`test/integration/README.md#integration-test-status-tracking`](../test/integration/README.md#integration-test-status-tracking) for details.

## Manual Testing Checklist (Before Production Release)

Before deploying to production servers:

- [ ] Unit tests pass (`make ci`)
- [ ] **Integration tests pass on all target distros** (enforced by `make release`)
- [ ] Idempotency verified (install/remove multiple times)
- [ ] Logger generates actual logs from real traffic
- [ ] Firewall rules persist after reboot
- [ ] Error messages are clear and actionable
- [ ] Config validation catches invalid inputs
- [ ] Documentation is up-to-date

## Test Data & Fixtures

**Test Configs**: `test/fixtures/configs/`
- `egress-valid.json` - Valid egress config
- `egress-invalid.json` - Invalid config (for error testing)
- `ingress-valid.json` - Valid ingress config

**Test ACLs**: `test/fixtures/acls/`
- `acl-simple.lst` - Basic IP list
- `acl-with-cidrs.lst` - Mix of IPs and CIDRs
- `acl-comments.lst` - With comments and empty lines

## Debugging Failed Tests

### Local Unit Test Failures
```bash
# Run specific test with verbose output
go test -v -run TestSpecificTest ./internal/logger

# Check which tests are failing
make test 2>&1 | grep FAIL

# Generate coverage to see what's not tested
make coverage-pkg PKG=./internal/logger
```

### Integration Test Failures

See [`test/integration/README.md#debugging-failed-tests`](../test/integration/README.md#debugging-failed-tests) for detailed debugging instructions.

## Performance Benchmarks

Add benchmarks for critical paths:

```go
func BenchmarkACLAdd(b *testing.B) {
    mgr := acl.NewManager("/tmp/benchmark-acl.lst")
    for i := 0; i < b.N; i++ {
        mgr.Add(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
    }
}
```

Run with:
```bash
go test -bench=. -benchmem ./internal/acl
```

## Story Traceability Matrix

This matrix maps user stories (see [STORIES.md](STORIES.md)) to test coverage. Focus is on **regression testing** for production-ready v1.0.

### Critical Stories (🔥 Priority) - Full Coverage Required

| Story | Title | Status | Test Coverage |
|-------|-------|--------|---------------|
| S001  | Clean System Installation | ✅ | `test/integration/test-suite-logger.sh::test_firewall_detection`<br>`test/integration/test-suite-logger.sh::test_logger_install` |
| S002  | UFW Conflict Detection | ✅ | `internal/firewall/firewall_test.go::TestIsUFWActive`<br>`internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`<br>`test/integration/test-suite-firewall.sh::test_ufw_conflict` |
| S003  | firewalld Conflict Detection | ✅ | `internal/firewall/firewall_test.go::TestIsFirewalldActive`<br>`internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`<br>`test/integration/test-suite-firewall.sh::test_firewalld_conflict` |
| S004  | Multiple Firewall Backend Support | ✅ | `internal/firewall/firewall_test.go::TestDetectWithConflictingManagers`<br>`test/integration/test-suite-firewall.sh::test_firewall_type_detection`<br>`test/integration/test-suite-logger.sh::test_firewall_detection` |
| S008  | Connection Capture Accuracy | ✅ | `internal/logger/logger_test.go::TestIPTablesPrivateRanges`<br>`internal/logger/logger_test.go::TestNFTablesConfigGeneration`<br>`test/integration/test-suite-logger.sh::test_log_generation` |
| S009  | Private IP Filtering | ✅ | `internal/logger/logger_test.go::TestIPTablesPrivateRanges`<br>`internal/logger/logger_test.go::TestNFTablesConfigGeneration`<br>`test/integration/test-suite-logger.sh::test_logger_install` |
| S010  | Log File Management | ✅ | `internal/logger/logger_test.go::TestConfigureLogrotate`<br>`test/integration/test-suite-logger.sh::test_logger_install` |
| S011  | Real-time Monitoring | ✅ | `internal/logger/logger_test.go::TestConfigureRsyslog`<br>`internal/logger/logger_test.go::TestLogPrefix`<br>`test/integration/test-suite-logger.sh::test_log_generation` |
| S016  | Service Continuity | ✅ | Implicit in all installation tests (non-destructive verification) |
| S018  | Clean Removal | ✅ | `internal/logger/logger_test.go::TestRemoveRsyslogConfig`<br>`internal/logger/logger_test.go::TestRemoveLogrotateConfig`<br>`test/integration/test-suite-logger.sh::test_logger_remove`<br>`test/integration/test-suite-logger.sh::test_idempotency_remove` |
| S019  | Firewall Rule Cleanup | ✅ | `test/integration/test-suite-logger.sh::test_logger_remove`<br>`test/integration/test-suite-logger.sh::test_idempotency_remove` |
| S024  | CentOS/RHEL Support | ✅ | `internal/logger/logger_test.go::TestFindNFTablesMainConf`<br>`test/integration/test-suite-firewall.sh::test_nftables_config_path` |
| S025  | Ubuntu/Debian Support | ✅ | `internal/logger/logger_test.go::TestFindNFTablesMainConf`<br>`test/integration/test-suite-firewall.sh::test_nftables_config_path` |

**Result: 13/13 Critical Stories ✅ (100% regression test coverage)**

### High Priority Stories (⚠️) - Partial Coverage

| Story | Title | Status | Test Coverage | Notes |
|-------|-------|--------|---------------|-------|
| S005  | Version Upgrade Preservation | 🚧 | `test/integration/test-suite-upgrade.sh` | Tests log preservation during upgrades - CRITICAL for production |
| S006  | Configuration Migration | 🚧 | `test/integration/test-suite-upgrade.sh` | Config overwrites tested, needs backup mechanism |
| S007  | Broken Installation Recovery | 🚧 | `test/integration/test-suite-logger.sh::test_idempotency_install` | Idempotency tested, explicit `--force` cleanup deferred to v1.1 |
| S021  | Permission Handling | 🔄 | None | Easy win for v1.1 - add root check with clear error messages |
| S026  | Architecture Detection | 🚧 | `test/integration/test-suite-arch.sh`<br>`install.sh:detect_os_arch()` | Install script detects arch, tested on major distros (x86_64) |
| S029  | Configuration Validation | 🚧 | `internal/config/config.go::Validate()` | Basic validation exists, needs expansion |
| S030  | Multiple Service Coexistence | 🚧 | `test/integration/bootstrap-droplet.sh` (HAProxy) | Works with HAProxy, needs Docker/VPN tests |

### Future Stories (🔮) - Deferred to v1.1+

| Stories | Category | Status | Notes |
|---------|----------|--------|-------|
| S005-S006 | Upgrade & Migration | ⏳ | No config changes planned for v1.0 |
| S012-S014 | Analysis & Reporting | ⏳ | Feature work (analyze command) |
| S015, S017 | Performance Monitoring | ⏳ | Benchmarking deferred unless SLA requirements |
| S020 | Log Preservation Options | ⏳ | Logs already preserved, no explicit flag needed |
| S022-S023 | Error Handling | ⏳ | Edge case handling |
| S027-S028 | Security & Compliance | ⏳ | Hardening work |

### Coverage Summary

**Regression Test Coverage for Production-Ready v1.0:**
- 🔥 Critical Stories: 13/13 ✅ (100%)
- ⚠️ High Priority: 4/4 with partial coverage 🚧
- 📝 Medium Priority: 2/2 deferred 🔄
- 🔮 Future Features: 11/11 deferred ⏳

**This provides strong regression protection for all production logic.**

---

## Future Improvements

- [ ] Mock systemctl/iptables/nft for higher unit test coverage
- [ ] Automated integration tests in CI/CD
- [ ] Performance regression testing
- [ ] Load testing (large ACL files, high traffic)
- [ ] Security testing (permission escalation, path traversal)
- [ ] Chaos testing (network failures, disk full, etc.)
- [ ] Docker/VPN coexistence tests (S030)
- [ ] Root permission check (S021 - quick win)

## Questions / Support

For questions about testing:
- Check this document first
- Review existing test patterns in `internal/*/\*_test.go`
- Review [STORIES.md](STORIES.md) for user story details
- Check traceability matrix above for story→test mapping
- Ask in team chat with `@testing` tag
