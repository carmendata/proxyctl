# BUG REPORT: Firewall Status Command Shows Incorrect State

**Status**: Open
**Priority**: Low
**Severity**: Minor (Cosmetic)
**Affects**: v0.1.10+
**Component**: `cmd/proxyctl/firewall.go`

## Summary

The `egressctl firewall status` command always reports that proxyctl tables/chains exist, even when they have been removed. The command does not actually check the firewall state before displaying information.

## Impact

**User Impact**: Low - Users receive misleading status information but can verify actual state using native firewall commands.

**Functional Impact**: None - Does not affect firewall operations (apply/remove/restore). Only affects status reporting.

**Workaround**: Users can run `iptables -L` or `nft list ruleset` to see actual firewall state.

## Steps to Reproduce

1. Apply firewall rules:
   ```bash
   echo "yes" | egressctl firewall apply --config /path/to/config.json
   ```

2. Remove firewall rules:
   ```bash
   egressctl firewall remove
   ```

3. Check status:
   ```bash
   egressctl firewall status
   ```

4. Verify actual state:
   ```bash
   nft list table inet proxyctl_filter
   ```

## Expected Behavior

After removing firewall rules, `egressctl firewall status` should report:

```
Firewall Type: nftables

Backups: 2 available

INPUT Filtering:
  Status: Not configured

OUTPUT Redirect:
  Status: Not configured
```

## Actual Behavior

After removing firewall rules, `egressctl firewall status` reports:

```
Firewall Type: nftables

Backups: 2 available

INPUT Filtering:
  Table: proxyctl_filter (nftables)

OUTPUT Redirect:
  Table: proxyctl_redirect (nftables)
```

But running `nft list table inet proxyctl_filter` returns:
```
Error: No such file or directory
```

## Root Cause

File: `/workspaces/haproxy-egress-proxy/cmd/proxyctl/firewall.go`
Lines: 210-230

The `runFirewallStatus()` function contains incomplete TODO implementations:

```go
// Show INPUT filtering status
fmt.Println("INPUT Filtering:")
switch fwMgr.Type {
case firewall.TypeIPTables:
    fmt.Println("  Chain: PROXYCTL_INPUT (iptables)")
    // TODO: Check if chain exists and show rules
case firewall.TypeNFTables:
    fmt.Println("  Table: proxyctl_filter (nftables)")
    // TODO: Check if table exists and show rules
}

// Show OUTPUT redirect status
fmt.Println("\nOUTPUT Redirect:")
switch fwMgr.Type {
case firewall.TypeIPTables:
    fmt.Println("  Chain: PROXYCTL_OUTPUT (iptables nat)")
    // TODO: Check if chain exists and show rules
case firewall.TypeNFTables:
    fmt.Println("  Table: proxyctl_redirect (nftables)")
    // TODO: Check if table exists and show rules
}
```

The code prints table/chain names unconditionally without checking if they actually exist in the firewall configuration.

## Affected Distributions

Verified on all supported distributions:
- ✓ Ubuntu 24.04 (nftables)
- ✓ Ubuntu 22.04 (nftables)
- ✓ Debian 12 (nftables)
- ✓ CentOS 9 (nftables)
- ✓ Rocky 8 (nftables)

## Suggested Fix

### Option 1: Check Existence Only (Simple)

```go
// Show INPUT filtering status
fmt.Println("INPUT Filtering:")
switch fwMgr.Type {
case firewall.TypeIPTables:
    if chainExists("iptables", "PROXYCTL_INPUT", "filter") {
        fmt.Println("  Chain: PROXYCTL_INPUT (iptables)")
        fmt.Println("  Status: Active")
    } else {
        fmt.Println("  Status: Not configured")
    }
case firewall.TypeNFTables:
    if tableExists("nft", "inet", "proxyctl_filter") {
        fmt.Println("  Table: proxyctl_filter (nftables)")
        fmt.Println("  Status: Active")
    } else {
        fmt.Println("  Status: Not configured")
    }
}
```

### Option 2: Show Detailed Rules (Comprehensive)

```go
// Show INPUT filtering status with rule details
fmt.Println("INPUT Filtering:")
switch fwMgr.Type {
case firewall.TypeNFTables:
    output, err := exec.Command("nft", "list", "table", "inet", "proxyctl_filter").CombinedOutput()
    if err != nil {
        fmt.Println("  Status: Not configured")
    } else {
        fmt.Println("  Table: proxyctl_filter (nftables)")
        fmt.Println("  Status: Active")
        // Parse and display key rules (SSH allow, policy, etc.)
        rules := parseNFTablesRules(string(output))
        displayInputRules(rules)
    }
}
```

### Helper Functions Needed

Add to `internal/firewall/firewall.go`:

```go
// TableExists checks if an nftables table exists
func (m *Manager) TableExists(family, name string) bool {
    cmd := exec.Command("nft", "list", "table", family, name)
    err := cmd.Run()
    return err == nil
}

// ChainExists checks if an iptables chain exists
func (m *Manager) ChainExists(table, chain string) bool {
    var cmd *exec.Command
    if table == "nat" {
        cmd = exec.Command("iptables", "-t", table, "-L", chain, "-n")
    } else {
        cmd = exec.Command("iptables", "-L", chain, "-n")
    }
    err := cmd.Run()
    return err == nil
}
```

## Testing Requirements

### Unit Tests
- Test `TableExists()` returns true when table exists
- Test `TableExists()` returns false when table doesn't exist
- Test `ChainExists()` returns true when chain exists
- Test `ChainExists()` returns false when chain doesn't exist

### Integration Tests
Add to `test/integration/test-suite-firewall.sh`:

```bash
# Test 13: Status accuracy after removal
test_status_after_removal() {
    echo "Test 13: Status Command Accuracy After Removal"
    echo "---"

    # Remove all rules
    /usr/local/bin/egressctl firewall remove

    # Check status output
    status_output=$(/usr/local/bin/egressctl firewall status)

    # Should show "Not configured" not table names
    if echo "$status_output" | grep -q "Not configured"; then
        echo "✓ PASS: Status correctly shows no configuration"
    else
        echo "✗ FAIL: Status incorrectly shows tables exist"
        return 1
    fi
}
```

## Related Issues

None currently tracked.

## Notes

- Bug discovered during integration test verification (2025-10-15)
- All 5 test distributions show identical behavior
- Does not affect firewall operations - purely a display issue
- The backup functionality works correctly and is shown accurately in status output

## Resolution Plan

1. Implement `TableExists()` and `ChainExists()` helper functions in `internal/firewall/firewall.go`
2. Update `runFirewallStatus()` in `cmd/proxyctl/firewall.go` to check existence before displaying
3. Add unit tests for existence checking functions
4. Add integration test to verify status accuracy
5. Update documentation with accurate status command examples

## Discovered By

Integration testing session - manual verification across all supported distributions

## Date Reported

2025-10-15
