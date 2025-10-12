# Integration Tests for proxyctl

**This is the single source of truth for integration test instructions.**

This directory contains integration tests that run on real DigitalOcean droplets to test actual system interactions.

For overall testing strategy, see [docs/TESTING.md](../../docs/TESTING.md).

## Prerequisites

1. **DigitalOcean Account** with API access
2. **doctl CLI** installed (no manual authentication needed!)
3. **Clean git working tree** - All changes must be committed before running tests

**Notes**:
- **Automatic authentication**: doctl is authenticated automatically using your `DO_API_TOKEN`
- **Automatic SSH key management**: Ephemeral SSH keys are created and cleaned up automatically
- **Clean working tree required**: Ensures reproducibility and proper release tracking

### Install doctl

```bash
# macOS
brew install doctl

# Linux
cd /usr/local/bin
wget https://github.com/digitalocean/doctl/releases/download/v1.98.1/doctl-1.98.1-linux-amd64.tar.gz
tar xf doctl-*.tar.gz
rm doctl-*.tar.gz
```

**Note**: You do NOT need to manually authenticate doctl. The test runner automatically authenticates using the `DO_API_TOKEN` from your `.env` file or environment.

## Running Integration Tests

### Quick Start

**One-time setup (recommended):**

```bash
# Copy .env.example to .env
cd test/integration
cp .env.example .env

# Edit .env and add your DigitalOcean API token
# DO_API_TOKEN=your-digitalocean-api-token-here
vim .env  # or use your preferred editor
```

**Running tests:**

```bash
# Commit your changes first (required!)
git add .
git commit -m "Your changes"

# Run tests (credentials loaded from .env automatically)
cd test/integration
./run-integration-tests.sh --all

# Run on specific distro
./run-integration-tests.sh --os ubuntu-22-04

# Run specific test suite
./run-integration-tests.sh --os debian-12 --suite logger

# Keep droplet alive for debugging
./run-integration-tests.sh --os ubuntu-22-04 --keep-alive
```

**Alternative: Environment variables (without .env file):**

```bash
# Export variables manually
export DO_API_TOKEN="your-digitalocean-api-token"
./run-integration-tests.sh --all

# Or inline
DO_API_TOKEN="your-token" ./run-integration-tests.sh --os ubuntu-22-04

# Force run with uncommitted changes (not recommended, skips status file)
ALLOW_DIRTY=true ./run-integration-tests.sh --os ubuntu-22-04
```

### Configuration Options

**Using .env file (recommended):**

Create a `.env` file in `test/integration/` directory (copy from `.env.example`):

```bash
# test/integration/.env
DO_API_TOKEN=your-digitalocean-api-token-here
DO_REGION=lon1
DO_DROPLET_SIZE=s-1vcpu-1gb
TEST_TIMEOUT=1800
```

**Configuration Priority (highest to lowest):**

1. **Environment variables** set in your shell (`export DO_API_TOKEN=...`)
2. **.env file** in `test/integration/` directory
3. **Default values** hardcoded in script

**Example: Overriding .env values:**

```bash
# .env file has DO_REGION=lon1
# Override for a single run:
DO_REGION=nyc1 ./run-integration-tests.sh --os ubuntu-22-04
```

### Environment Variables

| Variable           | Required | Default         | Description                           |
|--------------------|----------|-----------------|---------------------------------------|
| DO_API_TOKEN       | **Yes**  | -               | DigitalOcean API token                |
| DO_REGION          | No       | lon1            | DigitalOcean region                   |
| DO_DROPLET_SIZE    | No       | s-1vcpu-1gb     | Droplet size                          |
| TEST_TIMEOUT       | No       | 1800            | Test timeout in seconds (30 min)      |
| ALLOW_DIRTY        | No       | false           | Allow uncommitted changes (skips status file) |

**Important Notes**:
- **Use .env file for credentials** (set and forget, never committed to git)
- SSH keys are created automatically as ephemeral keys and cleaned up after tests
- **Clean working tree required by default** - commit changes before running tests
- Setting `ALLOW_DIRTY=true` bypasses the check but skips writing `.integration-test-status`

## Test Suites

### 1. Logger Test Suite (`test-suite-logger.sh`)

Tests connection logger installation and operation:
- Firewall detection (iptables vs nftables)
- Logger installation
- Config file creation (rsyslog, logrotate)
- Firewall rule creation
- Log generation from actual traffic
- Logger removal (cleanup)

### 2. ACL Test Suite (`test-suite-acl.sh`)

Tests ACL management operations:
- ACL add/remove/list operations
- HAProxy integration
- Config validation and reload
- Idempotency

### 3. Firewall Test Suite (`test-suite-firewall.sh`)

Tests firewall detection and management:
- Firewall type detection
- UFW/firewalld conflict detection
- Rule persistence across reboots

### 4. Upgrade Test Suite (`test-suite-upgrade.sh`)

Tests upgrade scenarios (S005: Version Upgrade Preservation, S006: Configuration Migration):
- Log preservation during reinstallation
- Configuration updates without data loss
- Post-upgrade logging functionality
- Logrotate and rsyslog config preservation

### 5. Architecture Test Suite (`test-suite-arch.sh`)

Tests architecture detection and compatibility (S026: Architecture Detection):
- System architecture detection (x86_64/amd64)
- Binary architecture verification
- Binary execution verification
- Symlink functionality
- Logger installation on x86_64 platforms

## Supported Distributions

| Distribution       | Image Slug          | Arch  | Firewall | Status |
|--------------------|---------------------|-------|----------|--------|
| Ubuntu 24.04 LTS   | ubuntu-24-04-x64    | amd64 | nftables | ✅      |
| Ubuntu 22.04 LTS   | ubuntu-22-04-x64    | amd64 | nftables | ✅      |
| Debian 12          | debian-12-x64       | amd64 | nftables | ✅      |
| Rocky Linux 8      | rockylinux-8-x64    | amd64 | iptables | ✅      |
| CentOS Stream 9    | centos-stream-9-x64 | amd64 | nftables | ✅      |

**Testing Coverage:**
- **All major Linux distributions** (Ubuntu LTS, Debian, RHEL-based)
- **Both legacy and modern firewalls** (iptables on Rocky 8, nftables on newer distros)
- **Architecture detection** verified on x86_64/amd64 platforms (S026)

**Firewall Coverage:**
- **iptables**: Rocky Linux 8 (RHEL 8 clone, widely used in production)
- **nftables**: Ubuntu 24.04, Ubuntu 22.04, Debian 12, CentOS Stream 9

**Notes:**
- Ubuntu 20.04 was removed from DigitalOcean's base images in late 2024 as its LTS support nears end-of-life (April 2025)
- We now test Ubuntu 24.04 LTS (latest) and Ubuntu 22.04 LTS for Ubuntu coverage
- Rocky Linux 8 provides iptables coverage for our dual firewall support

**Migration Plan (Future):**
Once all production servers are migrated to nftables-based distributions (Ubuntu 22.04+, Debian 12+, RHEL 9+), we can simplify the codebase by:
- Removing Rocky Linux 8 from the test matrix
- Dropping iptables support from `internal/firewall/firewall.go`
- Simplifying logger code to only support nftables

See `internal/firewall/firewall.go` for detailed migration checklist. Search codebase for "MIGRATION PLAN" when ready to remove iptables support.

## Clean Working Tree Requirement

**Why is this required?**

Integration tests create the `.integration-test-status` file that tracks which git commit was tested. This file is used by `make release` to prevent releasing untested code.

**The requirement ensures:**
1. **Reproducibility**: Tested code can be checked out and retested by anyone
2. **Release Safety**: `make release` verifies the exact commit was integration tested
3. **Audit Trail**: Clear connection between test results and code state

**What happens if I have uncommitted changes?**

The test runner will:
1. Detect uncommitted changes using `git diff-index`
2. Display a clear error message with instructions
3. Show what files have uncommitted changes
4. Suggest committing changes or using `ALLOW_DIRTY=true`

**Using ALLOW_DIRTY=true (not recommended):**

```bash
ALLOW_DIRTY=true ./run-integration-tests.sh --os ubuntu-22-04
```

This allows testing with uncommitted changes, but:
- ⚠️ **Skips writing `.integration-test-status`** (commit SHA would be meaningless)
- ⚠️ Results cannot be used for release verification
- ✅ Useful for local experimentation during development

## Integration Test Status Tracking

**Release Safety Mechanism**: Integration test results are tracked in `.integration-test-status` at the project root.

When tests complete successfully **with a clean working tree**, this file records:
- **COMMIT**: Git commit SHA that was tested
- **TIMESTAMP**: When tests were run
- **STATUS**: `passed` or `failed`
- **DISTROS**: Which distributions were tested
- **SUITE**: Which test suite was run

**This file is committed to git** and used by `make release` to verify that:
1. The current commit has been integration tested
2. The tests passed
3. No code changes were made after testing

**Note**: If tests are run with `ALLOW_DIRTY=true`, this file is NOT written or updated.

**Example `.integration-test-status`**:
```bash
# Integration Test Status
# This file is automatically generated by test/integration/run-integration-tests.sh
# It is used by 'make release' to verify integration tests have passed

COMMIT=abc123def456...
TIMESTAMP=2025-10-10T14:30:00Z
STATUS=passed
DISTROS=ubuntu-22-04,ubuntu-20-04,debian-12,centos-9
SUITE=all
```

**If you try to release without testing**, you'll see:
```
Error: Current commit has not been integration tested

Current commit:  abc123def456...
Tested commit:   xyz789abc123...
Test timestamp:  2025-10-09T10:15:00Z

Run integration tests on the current commit:
  cd test/integration && ./run-integration-tests.sh --all

Or force release without tests (NOT recommended):
  FORCE_RELEASE=true make release
```

## Cost Management

**Per Test Run**: ~$0.01 (30 minutes of uptime)

**Safety Features**:
- Automatic cleanup (destroy droplet after tests)
- Tagged droplets (`proxyctl-test`, `ephemeral`)
- 2-hour safety timeout (auto-destroy)
- Cleanup script to destroy orphaned droplets

### Manual Cleanup

```bash
# List all test droplets
doctl compute droplet list --tag-name proxyctl-test

# Destroy specific droplet
doctl compute droplet delete <droplet-id>

# Destroy ALL test droplets (emergency)
./cleanup-test-droplets.sh
```

## Debugging Failed Tests

### SSH into Test Droplet

If you used `--keep-alive`, the droplet won't be destroyed and the SSH command will be displayed:

```bash
# The test output will show the exact SSH command, something like:
# ssh -i /tmp/tmp.abc123/proxyctl-test-key root@<droplet-ip>

# Once connected, you can check logs
tail -f /var/log/egress-connections.log
journalctl -u rsyslog -f

# Check firewall rules
iptables -L -n -v
nft list ruleset

# Check service status
systemctl status rsyslog
```

**Important**: When using `--keep-alive`, remember to manually clean up:
```bash
doctl compute droplet delete <droplet-id>
doctl compute ssh-key delete <ssh-key-id>
```

### View Test Logs

Test logs are saved to `test-results/`:
```bash
ls -la test-results/
cat test-results/ubuntu-22-04-logger-*.log
```

## CI/CD Integration

See `.github/workflows/integration-tests.yml` for GitHub Actions integration.

The integration tests:
- Run manually or on schedule (not on every commit)
- Only on `main` branch
- Use GitHub Secrets for DO credentials
- Generate test reports as artifacts

## Troubleshooting

### "doctl: command not found"
Install doctl (see Prerequisites above)

### "Failed to authenticate with DigitalOcean"
- Verify your `DO_API_TOKEN` in `.env` file is correct
- Ensure the token has not expired
- Check token permissions at https://cloud.digitalocean.com/account/api/tokens

### "SSH connection refused"
- Wait longer for droplet to boot (increase sleep time in scripts)
- Check SSH key is properly added to DigitalOcean
- Verify SSH key path is correct

### "API rate limit exceeded"
- Wait a few minutes and retry
- Reduce concurrent test runs
- Spread test runs over time

### "Droplet creation failed"
- Check DO_API_TOKEN is valid
- Verify account has available droplet capacity
- Check region availability

## Writing New Integration Tests

1. Create test suite script: `test-suite-<name>.sh`
2. Follow pattern from existing test suites
3. Always check exit codes and provide clear error messages
4. Clean up resources even if tests fail
5. Update this README with new test suite info

Example test structure:
```bash
#!/bin/bash
set -euo pipefail

echo "=== Test Suite: My Feature ==="

# Test 1: Basic functionality
echo "Test 1: Basic functionality..."
./bin/egressctl myfeature || {
    echo "FAIL: Basic functionality test"
    exit 1
}
echo "PASS: Basic functionality"

# Test 2: Error handling
echo "Test 2: Error handling..."
./bin/egressctl myfeature --invalid && {
    echo "FAIL: Should have errored"
    exit 1
}
echo "PASS: Error handling"

echo "=== All tests passed ==="
```

## Future Improvements

- [ ] Parallel test execution (multiple droplets)
- [ ] Test result history tracking
- [ ] Performance benchmarking
- [ ] Automated regression testing
- [ ] Load testing (large ACL files, high traffic)
- [ ] Chaos testing (network failures, disk full)
