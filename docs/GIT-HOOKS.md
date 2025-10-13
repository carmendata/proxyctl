# Git Hooks

This project uses Git hooks to ensure code quality and prevent CI failures.

## Automated Quality Checks

### Pre-Commit Hook
**When:** Before every commit
**What it does:**
- Automatically formats Go code (`make fmt`)
- Runs static analysis (`make vet`)
- Re-stages formatted files

**Speed:** Fast (< 5 seconds)

### Pre-Push Hook
**When:** Before pushing to remote
**What it does:**
- Verifies dependencies (`make verify`)
- Checks code formatting (`make fmt-check`)
- Runs static analysis (`make vet`)
- Runs full test suite with coverage (`make test-coverage`)

**Speed:** Moderate (< 30 seconds)

**Why:** Prevents pushing code that would fail GitHub Actions CI.

## Installation

Install both hooks with one command:

```bash
make install-hooks
```

This copies:
- `scripts/pre-commit.sh` → `.git/hooks/pre-commit`
- `scripts/pre-push.sh` → `.git/hooks/pre-push`

## Usage

Once installed, hooks run automatically:

```bash
# Pre-commit hook runs automatically
git commit -m "Your message"

# Pre-push hook runs automatically
git push origin main
```

## Skipping Hooks (Not Recommended)

If you need to skip hooks temporarily:

```bash
# Skip pre-commit hook
git commit --no-verify -m "Your message"

# Skip pre-push hook
git push --no-verify origin main
```

**Warning:** Only skip hooks if you know what you're doing. Skipped checks will still fail in CI.

## Manual Testing

Run the same checks manually:

```bash
# Run pre-commit checks
./scripts/pre-commit.sh

# Run pre-push checks (full CI)
./scripts/pre-push.sh

# Or use the convenience command
make check-ci
```

## Troubleshooting

### Hook Not Running

If hooks aren't running, they may not be executable:

```bash
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push
```

Or reinstall:

```bash
make install-hooks
```

### Hook Fails

If a hook fails:

1. **Pre-commit failures:**
   - Format: The hook automatically formats code and re-stages files
   - Vet errors: Fix the issues reported by `go vet`

2. **Pre-push failures:**
   - Run `make check-ci` to see detailed error messages
   - Fix the reported issues
   - Commit the fixes
   - Try pushing again

### Updating Hooks

After pulling changes that modify hook scripts, reinstall:

```bash
make install-hooks
```

## CI Parity

The pre-push hook mirrors GitHub Actions CI exactly:

| Check | Pre-Push Hook | GitHub Actions |
|-------|--------------|----------------|
| Dependencies | ✅ `make verify` | ✅ `make verify` |
| Formatting | ✅ `make fmt-check` | ✅ `make fmt-check` |
| Static Analysis | ✅ `make vet` | ✅ `make vet` |
| Tests | ✅ `make test-coverage` | ✅ `make test-coverage` |
| Build | ❌ (skipped for speed) | ✅ `make build` |

To test the full workflow including build:

```bash
make check-ci
```

## Philosophy

- **Pre-commit:** Fast checks that auto-fix issues (formatting)
- **Pre-push:** Comprehensive checks that prevent CI failures
- **CI (GitHub Actions):** Final verification with build and deployment

This layered approach catches issues early while keeping the developer experience smooth.
