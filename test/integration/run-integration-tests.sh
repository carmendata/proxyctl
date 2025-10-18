#!/bin/bash
#
# Integration Test Runner for proxyctl
# Manages DigitalOcean droplet lifecycle and runs test suites
#
# Usage:
#   ./run-integration-tests.sh --all                        # Test all distros
#   ./run-integration-tests.sh --os ubuntu-22-04            # Test specific distro
#   ./run-integration-tests.sh --os debian-12 --suite logger  # Test specific suite
#   ./run-integration-tests.sh --os ubuntu-22-04 --keep-alive # Don't destroy droplet

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/test-results"
LOGS_DIR="$SCRIPT_DIR/logs"
STATUS_FILE="$PROJECT_ROOT/.integration-test-status"

# Load environment variables from .env file if it exists
# Note: Existing environment variables take precedence over .env values
load_env_file() {
    local env_file="$SCRIPT_DIR/.env"

    if [[ -f "$env_file" ]]; then
        echo -e "${BLUE}Loading configuration from .env file...${NC}"

        # Read .env file, skip comments and empty lines
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            [[ "$key" =~ ^#.*$ ]] && continue
            [[ -z "$key" ]] && continue

            # Remove leading/trailing whitespace
            key=$(echo "$key" | xargs)
            value=$(echo "$value" | xargs)

            # Remove quotes from value if present
            value="${value%\"}"
            value="${value#\"}"
            value="${value%\'}"
            value="${value#\'}"

            # Only set if not already set in environment
            if [[ -z "${!key:-}" ]]; then
                export "$key=$value"
                echo "  Loaded: $key"
            else
                echo "  Skipped: $key (already set in environment)"
            fi
        done < "$env_file"

        echo ""
    fi
}

# Load .env file before checking required variables
load_env_file

# Required environment variables
: "${DO_API_TOKEN:?Error: DO_API_TOKEN environment variable must be set (use .env file or export it)}"

# Optional environment variables
DO_REGION="${DO_REGION:-lon1}"
DO_DROPLET_SIZE="${DO_DROPLET_SIZE:-s-1vcpu-1gb}"
TEST_TIMEOUT="${TEST_TIMEOUT:-1800}"  # 30 minutes
KEEP_LOGS="${KEEP_LOGS:-false}"  # Keep old log files (default: clean up logs older than 7 days)
CLEANUP="${CLEANUP:-true}"  # Cleanup droplets after tests (false = keep for manual inspection)

# Ephemeral SSH key (created automatically)
SSH_KEY_NAME="proxyctl-test-$(date +%s)-$$"
SSH_KEY_PATH=""
SSH_KEY_ID=""

# Supported distributions
declare -A DISTROS=(
    ["ubuntu-24-04"]="ubuntu-24-04-x64"
    ["ubuntu-22-04"]="ubuntu-22-04-x64"
    ["debian-12"]="debian-12-x64"
    ["rocky-8"]="rockylinux-8-x64"
    ["centos-9"]="centos-stream-9-x64"
)

# Default values
RUN_ALL=false
KEEP_ALIVE=false
ALLOW_DIRTY="${ALLOW_DIRTY:-false}"  # Allow uncommitted changes (not recommended)
OS=""
SUITE="all"
DROPLET_ID=""
DROPLET_IP=""

# Usage message
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    --all               Run tests on all supported distros
    --os <distro>       Run tests on specific distro (ubuntu-24-04, ubuntu-22-04, debian-12, rocky-8, centos-9)
    --suite <suite>     Run specific test suite (logger, acl, firewall, upgrade, or 'all')
    --keep-alive        Don't destroy droplet after tests (for debugging)
    -h, --help          Show this help message

Environment Variables (can be set via .env file):
    DO_API_TOKEN        DigitalOcean API token (required)
    DO_REGION           DigitalOcean region (default: lon1)
    DO_DROPLET_SIZE     Droplet size (default: s-1vcpu-1gb)
    TEST_TIMEOUT        Test timeout in seconds (default: 1800)
    ALLOW_DIRTY         Allow running tests with uncommitted changes (not recommended)
    KEEP_LOGS           Keep old log files (default: false, cleans up logs older than 7 days)
    CLEANUP             Cleanup droplets after tests (default: true, set to false for debugging)

Configuration:
    Create test/integration/.env file (copy from .env.example) to set credentials
    Environment variables in your shell override .env file values

Note: SSH keys are created automatically and cleaned up after tests.
Note: Integration tests require a clean git working tree by default.

Examples:
    # One-time setup: Create .env file
    cp .env.example .env
    vim .env  # Add your DO_API_TOKEN

    # Run all test suites on all distros
    $0 --all

    # Run on Ubuntu 22.04
    $0 --os ubuntu-22-04

    # Run logger test suite on Debian 12
    $0 --os debian-12 --suite logger

    # Keep droplet alive for debugging
    $0 --os ubuntu-22-04 --keep-alive

    # Override .env settings for one run
    DO_REGION=nyc1 $0 --os ubuntu-22-04
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            RUN_ALL=true
            shift
            ;;
        --os)
            OS="$2"
            shift 2
            ;;
        --suite)
            SUITE="$2"
            shift 2
            ;;
        --keep-alive)
            KEEP_ALIVE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Validate arguments
if [[ "$RUN_ALL" = false && -z "$OS" ]]; then
    echo -e "${RED}Error: Must specify either --all or --os <distro>${NC}"
    usage
    exit 1
fi

if [[ -n "$OS" && -z "${DISTROS[$OS]:-}" ]]; then
    echo -e "${RED}Error: Unsupported distro: $OS${NC}"
    echo "Supported distros: ${!DISTROS[@]}"
    exit 1
fi

# Check dependencies
check_dependencies() {
    local missing=()

    for cmd in doctl ssh scp ssh-keygen; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required commands: ${missing[*]}${NC}"
        echo "Install doctl: https://docs.digitalocean.com/reference/doctl/how-to/install/"
        exit 1
    fi

    # Always authenticate with the provided token to ensure we're using the correct credentials
    echo -e "${BLUE}Authenticating with DigitalOcean...${NC}"
    if ! doctl auth init --access-token "$DO_API_TOKEN" >/dev/null 2>&1; then
        echo -e "${RED}Error: Failed to authenticate with DigitalOcean${NC}"
        echo "Please verify your DO_API_TOKEN is correct"
        exit 1
    fi

    # Verify authentication worked
    local account_email=$(doctl account get --format Email --no-header 2>/dev/null)
    if [[ -n "$account_email" ]]; then
        echo -e "${GREEN}Authenticated as: $account_email${NC}"
    else
        echo -e "${RED}Error: Authentication verification failed${NC}"
        exit 1
    fi
    echo ""
}

# Check git status (require clean working tree)
check_git_status() {
    echo -e "${BLUE}Checking git status...${NC}"

    cd "$PROJECT_ROOT"

    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        echo -e "${RED}Error: Not a git repository${NC}"
        exit 1
    fi

    # Check for uncommitted changes (both staged and unstaged)
    if ! git diff-index --quiet HEAD --; then
        echo -e "${RED}Error: You have uncommitted changes${NC}"
        echo ""
        echo "Integration tests require all changes to be committed because:"
        echo "  - Test results are tracked by commit SHA in .integration-test-status"
        echo "  - 'make release' verifies the exact commit was tested"
        echo "  - Ensures reproducibility of test results"
        echo ""
        echo "Uncommitted changes detected:"
        git status --short
        echo ""
        echo "Please commit your changes first:"
        echo "  git add ..."
        echo "  git commit -m 'Your changes'"
        echo ""
        echo "Or force run with uncommitted changes (not recommended):"
        echo "  ALLOW_DIRTY=true $0 $(printf '%q ' "$@")"
        echo ""
        echo -e "${YELLOW}Note: Status file will only be written if working tree is clean${NC}"
        exit 1
    fi

    local current_commit=$(git rev-parse HEAD)
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    echo -e "${GREEN}Working tree is clean${NC}"
    echo "  Branch: $current_branch"
    echo "  Commit: ${current_commit:0:12}"
}

# Clean up old log files (unless KEEP_LOGS=true)
cleanup_old_logs() {
    if [[ "$KEEP_LOGS" = "true" ]]; then
        echo -e "${YELLOW}Keeping old log files (KEEP_LOGS=true)${NC}"
        echo ""
        return 0
    fi

    echo -e "${BLUE}Cleaning up old log files...${NC}"

    local total_removed=0

    # Clean LOGS_DIR
    if [[ -d "$LOGS_DIR" ]]; then
        local logs_count=$(find "$LOGS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
        if [[ $logs_count -gt 0 ]]; then
            local removed=$(find "$LOGS_DIR" -name "*.log" -type f -delete -print 2>/dev/null | wc -l)
            total_removed=$((total_removed + removed))
        fi
    fi

    # Clean RESULTS_DIR
    if [[ -d "$RESULTS_DIR" ]]; then
        local results_count=$(find "$RESULTS_DIR" -name "*.log" -type f 2>/dev/null | wc -l)
        if [[ $results_count -gt 0 ]]; then
            local removed=$(find "$RESULTS_DIR" -name "*.log" -type f -delete -print 2>/dev/null | wc -l)
            total_removed=$((total_removed + removed))
        fi
    fi

    if [[ $total_removed -gt 0 ]]; then
        echo -e "${GREEN}  Total removed: $total_removed files from previous runs${NC}"
    else
        echo "  No old log files to remove"
    fi
    echo ""
}

# Create ephemeral SSH key
create_ssh_key() {
    echo -e "${BLUE}Creating ephemeral SSH key...${NC}"

    # Create temporary directory for SSH keys
    local key_dir=$(mktemp -d)
    SSH_KEY_PATH="$key_dir/proxyctl-test-key"

    # Generate SSH key pair (no passphrase)
    ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "$SSH_KEY_NAME" >/dev/null 2>&1

    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        echo -e "${RED}Error: Failed to generate SSH key${NC}"
        exit 1
    fi

    echo -e "${GREEN}SSH key generated: $SSH_KEY_PATH${NC}"

    # Upload to DigitalOcean
    echo "Uploading SSH key to DigitalOcean..."
    SSH_KEY_ID=$(doctl compute ssh-key import "$SSH_KEY_NAME" \
        --public-key-file "${SSH_KEY_PATH}.pub" \
        --format ID \
        --no-header 2>/dev/null)

    if [[ -z "$SSH_KEY_ID" ]]; then
        echo -e "${RED}Error: Failed to upload SSH key to DigitalOcean${NC}"
        exit 1
    fi

    echo -e "${GREEN}SSH key uploaded (ID: $SSH_KEY_ID)${NC}"
}

# Cleanup function (called on exit)
cleanup() {
    local exit_code=$?

    # Check if cleanup should be skipped
    if [[ "$CLEANUP" != "true" ]]; then
        echo -e "${YELLOW}CLEANUP=false - Keeping droplet AND SSH key for manual inspection${NC}"
        if [[ -n "$DROPLET_ID" ]]; then
            echo "  Droplet ID: $DROPLET_ID"
            echo "  Droplet IP: $DROPLET_IP"
            echo "  SSH Key ID: $SSH_KEY_ID"
            echo "  SSH: ssh -i $SSH_KEY_PATH root@$DROPLET_IP"
            echo ""
            echo "Manual cleanup commands:"
            echo "  doctl compute droplet delete $DROPLET_ID"
            echo "  doctl compute ssh-key delete $SSH_KEY_ID"
        fi
        exit $exit_code
    fi

    # Cleanup droplet
    if [[ -n "$DROPLET_ID" && "$KEEP_ALIVE" = false ]]; then
        echo -e "${YELLOW}Cleaning up droplet $DROPLET_ID...${NC}"
        doctl compute droplet delete "$DROPLET_ID" --force 2>/dev/null || true
    elif [[ -n "$DROPLET_ID" && "$KEEP_ALIVE" = true ]]; then
        echo -e "${YELLOW}Droplet kept alive for debugging:${NC}"
        echo "  ID: $DROPLET_ID"
        echo "  IP: $DROPLET_IP"
        echo "  SSH Key ID: $SSH_KEY_ID"
        echo "  SSH: ssh -i $SSH_KEY_PATH root@$DROPLET_IP"
        echo ""
        echo -e "${RED}Remember to clean up when done:${NC}"
        echo "  doctl compute droplet delete $DROPLET_ID"
        echo "  doctl compute ssh-key delete $SSH_KEY_ID"
    fi

    # Cleanup SSH key from DigitalOcean (only if droplet was also cleaned up)
    if [[ -n "$SSH_KEY_ID" && "$KEEP_ALIVE" = false ]]; then
        echo -e "${YELLOW}Cleaning up SSH key $SSH_KEY_ID...${NC}"
        doctl compute ssh-key delete "$SSH_KEY_ID" --force 2>/dev/null || true
    fi

    # Cleanup local SSH key files
    if [[ -n "$SSH_KEY_PATH" && -f "$SSH_KEY_PATH" ]]; then
        local key_dir=$(dirname "$SSH_KEY_PATH")
        rm -rf "$key_dir" 2>/dev/null || true
    fi

    exit $exit_code
}

# Cleanup all background test processes
cleanup_all() {
    local exit_code=$?

    # Kill any remaining background jobs
    jobs -p | xargs -r kill 2>/dev/null || true

    # Give jobs time to cleanup
    sleep 2

    exit $exit_code
}

trap cleanup EXIT INT TERM

# Create droplet
create_droplet() {
    local os=$1
    local image=${DISTROS[$os]}
    local name="proxyctl-test-$os-$(date +%s)"

    echo -e "${BLUE}Creating droplet: $name${NC}"
    echo "  Image: $image"
    echo "  Region: $DO_REGION"
    echo "  Size: $DO_DROPLET_SIZE"

    # Create droplet
    DROPLET_ID=$(doctl compute droplet create "$name" \
        --image "$image" \
        --region "$DO_REGION" \
        --size "$DO_DROPLET_SIZE" \
        --ssh-keys "$SSH_KEY_ID" \
        --tag-names "proxyctl-test,ephemeral" \
        --wait \
        --format ID \
        --no-header)

    if [[ -z "$DROPLET_ID" ]]; then
        echo -e "${RED}Error: Failed to create droplet${NC}"
        exit 1
    fi

    echo -e "${GREEN}Droplet created: $DROPLET_ID${NC}"

    # Get droplet IP
    DROPLET_IP=$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)
    echo "  IP: $DROPLET_IP"

    # Wait for SSH
    echo "Waiting for SSH to be ready..."
    local attempts=0
    local max_attempts=30

    while ! ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        root@"$DROPLET_IP" "echo SSH ready" >/dev/null 2>&1; do

        attempts=$((attempts + 1))
        if [[ $attempts -ge $max_attempts ]]; then
            echo -e "${RED}Error: SSH not ready after $max_attempts attempts${NC}"
            exit 1
        fi

        echo -n "."
        sleep 10
    done

    echo ""
    echo -e "${GREEN}SSH is ready${NC}"
}

# Bootstrap droplet (install dependencies)
bootstrap_droplet() {
    echo -e "${BLUE}Bootstrapping droplet...${NC}"

    # Upload bootstrap script
    scp -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$SCRIPT_DIR/bootstrap-droplet.sh" \
        root@"$DROPLET_IP":/tmp/bootstrap.sh

    # Run bootstrap
    ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        root@"$DROPLET_IP" "bash /tmp/bootstrap.sh"

    echo -e "${GREEN}Bootstrap complete${NC}"
}

# Upload binary
upload_binary() {
    echo -e "${BLUE}Uploading proxyctl binary...${NC}"

    # Binary should already be built by main()
    # Upload
    scp -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$PROJECT_ROOT/bin/proxyctl" \
        root@"$DROPLET_IP":/usr/local/bin/proxyctl

    # Create symlinks
    ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        root@"$DROPLET_IP" \
        "cd /usr/local/bin && ln -sf proxyctl egressctl && ln -sf proxyctl ingressctl && chmod +x proxyctl"

    echo -e "${GREEN}Binary uploaded${NC}"
}

# Run test suite
run_tests() {
    local suite=$1

    echo -e "${BLUE}Running test suite: $suite${NC}"

    # Upload test scripts
    scp -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$SCRIPT_DIR"/test-suite-*.sh "$SCRIPT_DIR"/common-*.sh \
        root@"$DROPLET_IP":/tmp/

    # Run tests
    local test_script=""
    case $suite in
        logger)
            test_script="/tmp/test-suite-logger.sh"
            ;;
        acl)
            test_script="/tmp/test-suite-acl.sh"
            ;;
        firewall)
            test_script="/tmp/test-suite-firewall.sh"
            ;;
        firewall-dry-run)
            test_script="/tmp/test-suite-firewall-dry-run.sh"
            ;;
        upgrade)
            test_script="/tmp/test-suite-upgrade.sh"
            ;;
        arch)
            test_script="/tmp/test-suite-arch.sh"
            ;;
        status)
            test_script="/tmp/test-suite-status.sh"
            ;;
        all)
            test_script="/tmp/test-suite-logger.sh && /tmp/test-suite-firewall.sh && /tmp/test-suite-firewall-dry-run.sh && /tmp/test-suite-status.sh && /tmp/test-suite-upgrade.sh && /tmp/test-suite-arch.sh"
            ;;
        *)
            echo -e "${RED}Error: Unknown test suite: $suite${NC}"
            return 1
            ;;
    esac

    if ssh -i "$SSH_KEY_PATH" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        root@"$DROPLET_IP" \
        "bash -c 'chmod +x /tmp/test-suite-*.sh && $test_script'"; then

        echo -e "${GREEN}✓ Tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ Tests failed${NC}"
        return 1
    fi
}

# Save test results
save_results() {
    local os=$1
    local suite=$2
    local status=$3

    mkdir -p "$RESULTS_DIR"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local result_file="$RESULTS_DIR/$os-$suite-$timestamp.log"

    cat > "$result_file" <<EOF
Test Results
============
OS: $os
Suite: $suite
Status: $status
Timestamp: $(date)
Droplet ID: $DROPLET_ID
Droplet IP: $DROPLET_IP

Test Output:
$(ssh -i "$SSH_KEY_PATH" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR root@"$DROPLET_IP" "cat /tmp/test-output.log" 2>/dev/null || echo "No test output available")
EOF

    echo "Results saved to: $result_file"
}

# Run tests on a single distro (used for non-parallel mode)
run_single_test() {
    local os=$1
    local suite=$2

    echo ""
    echo "========================================"
    echo "Testing: $os (suite: $suite)"
    echo "========================================"
    echo ""

    # Create and setup droplet
    create_droplet "$os"
    bootstrap_droplet
    upload_binary

    # Run tests
    local status="FAIL"
    if run_tests "$suite"; then
        status="PASS"
    fi

    # Save results
    save_results "$os" "$suite" "$status"

    # Cleanup (handled by trap)
    return $([ "$status" = "PASS" ] && echo 0 || echo 1)
}

# Run tests on a single distro in parallel (self-contained, no shared state)
run_parallel_test() {
    local os=$1
    local suite=$2
    local log_file=$3

    # Local variables (not shared with parent process)
    local ssh_key_path=""
    local ssh_key_id=""
    local droplet_id=""
    local droplet_ip=""
    local status="FAIL"

    # Redirect all output to log file
    exec > "$log_file" 2>&1

    echo "========================================"
    echo "Testing: $os (suite: $suite)"
    echo "Started: $(date)"
    echo "========================================"
    echo ""

    # Create ephemeral SSH key for this test
    echo "[$(date +%H:%M:%S)] Creating SSH key..."
    local key_dir=$(mktemp -d)
    ssh_key_path="$key_dir/proxyctl-test-key-$os"
    ssh-keygen -t ed25519 -f "$ssh_key_path" -N "" -C "proxyctl-test-$os-$$" >/dev/null 2>&1

    # Upload SSH key
    ssh_key_id=$(doctl compute ssh-key import "proxyctl-test-$os-$(date +%s)-$$" \
        --public-key-file "${ssh_key_path}.pub" \
        --format ID \
        --no-header 2>/dev/null)

    if [[ -z "$ssh_key_id" ]]; then
        echo "[$(date +%H:%M:%S)] ERROR: Failed to upload SSH key"
        return 1
    fi

    echo "[$(date +%H:%M:%S)] SSH key uploaded (ID: $ssh_key_id)"

    # Cleanup function for this parallel test
    cleanup_parallel() {
        echo ""
        echo "[$(date +%H:%M:%S)] Cleaning up..."

        if [[ "$CLEANUP" != "true" ]]; then
            echo "[$(date +%H:%M:%S)] CLEANUP=false - Keeping droplet for manual inspection"
            echo "  Droplet ID: $droplet_id"
            echo "  Droplet IP: $droplet_ip"
            echo "  SSH: ssh -i $ssh_key_path root@$droplet_ip"
            echo "  Manual cleanup: doctl compute droplet delete $droplet_id"
            echo "  Manual cleanup SSH key: doctl compute ssh-key delete $ssh_key_id"
            return
        fi

        if [[ -n "$droplet_id" ]]; then
            doctl compute droplet delete "$droplet_id" --force 2>/dev/null || true
        fi
        if [[ -n "$ssh_key_id" ]]; then
            doctl compute ssh-key delete "$ssh_key_id" --force 2>/dev/null || true
        fi
        if [[ -n "$ssh_key_path" && -f "$ssh_key_path" ]]; then
            rm -rf "$(dirname "$ssh_key_path")" 2>/dev/null || true
        fi
    }

    trap cleanup_parallel EXIT

    # Create droplet
    echo "[$(date +%H:%M:%S)] Creating droplet..."
    local name="proxyctl-test-$os-$(date +%s)-$$"
    local image=${DISTROS[$os]}

    droplet_id=$(doctl compute droplet create "$name" \
        --image "$image" \
        --region "$DO_REGION" \
        --size "$DO_DROPLET_SIZE" \
        --ssh-keys "$ssh_key_id" \
        --tag-names "proxyctl-test,ephemeral" \
        --wait \
        --format ID \
        --no-header 2>/dev/null)

    if [[ -z "$droplet_id" ]]; then
        echo "[$(date +%H:%M:%S)] ERROR: Failed to create droplet"
        return 1
    fi

    echo "[$(date +%H:%M:%S)] Droplet created (ID: $droplet_id)"

    # Get droplet IP
    droplet_ip=$(doctl compute droplet get "$droplet_id" --format PublicIPv4 --no-header)
    echo "[$(date +%H:%M:%S)] Droplet IP: $droplet_ip"

    # Wait for SSH
    echo "[$(date +%H:%M:%S)] Waiting for SSH..."
    local attempts=0
    while ! ssh -i "$ssh_key_path" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        root@"$droplet_ip" "echo SSH ready" >/dev/null 2>&1; do

        attempts=$((attempts + 1))
        if [[ $attempts -ge 30 ]]; then
            echo "[$(date +%H:%M:%S)] ERROR: SSH timeout"
            return 1
        fi
        sleep 10
    done

    echo "[$(date +%H:%M:%S)] SSH ready"

    # Bootstrap
    echo "[$(date +%H:%M:%S)] Bootstrapping..."
    scp -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$SCRIPT_DIR/bootstrap-droplet.sh" root@"$droplet_ip":/tmp/bootstrap.sh
    ssh -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        root@"$droplet_ip" "bash /tmp/bootstrap.sh"

    # Upload binary
    echo "[$(date +%H:%M:%S)] Uploading binary..."
    scp -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$PROJECT_ROOT/bin/proxyctl" root@"$droplet_ip":/usr/local/bin/proxyctl
    ssh -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        root@"$droplet_ip" \
        "cd /usr/local/bin && ln -sf proxyctl egressctl && ln -sf proxyctl ingressctl && chmod +x proxyctl"

    # Upload test scripts
    echo "[$(date +%H:%M:%S)] Uploading test scripts..."
    scp -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$SCRIPT_DIR"/test-suite-*.sh "$SCRIPT_DIR"/common-*.sh root@"$droplet_ip":/tmp/

    # Run tests
    echo "[$(date +%H:%M:%S)] Running tests..."
    echo "----------------------------------------"

    local test_script=""
    case $suite in
        all)
            test_script="/tmp/test-suite-logger.sh && /tmp/test-suite-firewall.sh && /tmp/test-suite-firewall-dry-run.sh && /tmp/test-suite-status.sh && /tmp/test-suite-upgrade.sh && /tmp/test-suite-arch.sh"
            ;;
        *)
            test_script="/tmp/test-suite-$suite.sh"
            ;;
    esac

    if ssh -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        root@"$droplet_ip" "bash -c 'chmod +x /tmp/test-suite-*.sh && $test_script'"; then
        status="PASS"
        echo "----------------------------------------"
        echo "[$(date +%H:%M:%S)] ✓ Tests PASSED"
    else
        status="FAIL"
        echo "----------------------------------------"
        echo "[$(date +%H:%M:%S)] ✗ Tests FAILED"
    fi

    echo ""
    echo "========================================"
    echo "Result: $status"
    echo "Completed: $(date)"
    echo "========================================"

    # Save result file
    mkdir -p "$RESULTS_DIR"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local result_file="$RESULTS_DIR/$os-$suite-$timestamp.log"
    ssh -i "$ssh_key_path" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        root@"$droplet_ip" "cat /tmp/test-output.log" 2>/dev/null > "$result_file" || true

    # Cleanup handled by trap
    return $([ "$status" = "PASS" ] && echo 0 || echo 1)
}

# Write integration test status file
write_status_file() {
    local status=$1
    local distros_tested=$2

    # Get git commit SHA
    local commit_sha=$(cd "$PROJECT_ROOT" && git rev-parse HEAD 2>/dev/null || echo "unknown")
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    cat > "$STATUS_FILE" <<EOF
# Integration Test Status
# This file is automatically generated by test/integration/run-integration-tests.sh
# It is used by 'make release' to verify integration tests have passed

COMMIT=$commit_sha
TIMESTAMP=$timestamp
STATUS=$status
DISTROS=$distros_tested
SUITE=$SUITE
EOF

    echo -e "${BLUE}Integration test status written to: $STATUS_FILE${NC}"
    echo "  Commit: $commit_sha"
    echo "  Status: $status"
    echo "  Distros: $distros_tested"
}

# Check if a test actually passed by parsing its log file
# Returns 0 if PASS, 1 if FAIL
check_log_result() {
    local log_file=$1

    # Check if log file exists and is not empty
    if [[ ! -f "$log_file" || ! -s "$log_file" ]]; then
        return 1  # No log or empty log = fail
    fi

    # Look for "Result: PASS" or "Result: FAIL" at end of log
    if grep -q "Result: PASS" "$log_file"; then
        return 0  # Pass
    elif grep -q "Result: FAIL" "$log_file"; then
        return 1  # Fail
    else
        # No result marker found - check for other failure indicators
        if grep -qE "(FAIL:|✗ Tests FAILED)" "$log_file"; then
            return 1  # Fail
        fi
        # If no clear result, consider it a pass (backward compatibility)
        return 0
    fi
}

# Monitor progress of parallel tests
# Returns exit codes via nameref array
monitor_progress() {
    local -n pids_ref=$1
    local -n log_files_ref=$2
    local -n os_names_ref=$3
    local -n exit_codes_ref=$4  # NEW: Return exit codes to caller

    local total=${#pids_ref[@]}
    local completed=0

    # Initialize exit codes array with -1 (not finished)
    for i in "${!pids_ref[@]}"; do
        exit_codes_ref[$i]=-1
    done

    echo -e "${BLUE}Running $total tests in parallel...${NC}"
    echo ""

    # Create logs directory
    mkdir -p "$LOGS_DIR"

    # Show initial status
    for os in "${os_names_ref[@]}"; do
        echo -e "  ${YELLOW}⏳${NC} $os: Starting..."
    done

    # Monitor until all complete
    while [ $completed -lt $total ]; do
        sleep 5
        completed=0

        # Move cursor up to overwrite status lines
        echo -ne "\033[${total}A"

        for i in "${!pids_ref[@]}"; do
            local pid=${pids_ref[$i]}
            local os=${os_names_ref[$i]}
            local log=${log_files_ref[$i]}

            # Skip if already processed
            if [ "${exit_codes_ref[$i]}" -ne -1 ]; then
                completed=$((completed + 1))
                # Check log file for actual result
                if check_log_result "$log"; then
                    echo -e "  ${GREEN}✓${NC} $os: Passed                    "
                else
                    echo -e "  ${RED}✗${NC} $os: Failed                    "
                fi
                continue
            fi

            if ! kill -0 "$pid" 2>/dev/null; then
                # Process finished - capture exit code
                wait "$pid"
                exit_codes_ref[$i]=$?

                # Check log file for actual result (more reliable than exit code)
                if check_log_result "$log"; then
                    echo -e "  ${GREEN}✓${NC} $os: Passed                    "
                else
                    echo -e "  ${RED}✗${NC} $os: Failed                    "
                fi
                completed=$((completed + 1))
            else
                # Still running - show last log line
                local last_line=$(tail -n 1 "$log" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-50 || echo "Running...")
                echo -e "  ${YELLOW}⏳${NC} $os: $last_line..."
            fi
        done
    done

    echo ""
}

# Main execution
main() {
    echo -e "${BLUE}proxyctl Integration Test Runner${NC}"
    echo ""

    # Check dependencies
    check_dependencies

    # Check git status (unless ALLOW_DIRTY=true)
    if [[ "$ALLOW_DIRTY" != "true" ]]; then
        check_git_status
    else
        echo -e "${YELLOW}Warning: Running with ALLOW_DIRTY=true${NC}"
        echo -e "${YELLOW}Status file will only be written if working tree is clean${NC}"
        echo ""
    fi

    # Clean up old logs (unless KEEP_LOGS=true)
    cleanup_old_logs

    # Build binary once for all tests (both parallel and single mode)
    echo -e "${BLUE}Building proxyctl binary...${NC}"
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=amd64 make build
    echo ""

    # Run tests
    if [[ "$RUN_ALL" = true ]]; then
        # Parallel execution mode

        # Create logs directory
        mkdir -p "$LOGS_DIR"
        local timestamp=$(date +%Y%m%d-%H%M%S)

        # Start all tests in background
        local pids=()
        local log_files=()
        local os_names=()
        local exit_codes=()

        for os in "${!DISTROS[@]}"; do
            local log_file="$LOGS_DIR/$os-$SUITE-$timestamp.log"
            os_names+=("$os")
            log_files+=("$log_file")

            # Run in background
            run_parallel_test "$os" "$SUITE" "$log_file" &
            pids+=($!)
        done

        # Monitor progress (exit codes are captured here)
        monitor_progress pids log_files os_names exit_codes

        # Collect results by parsing log files (more reliable than exit codes)
        local failed=()
        for i in "${!log_files[@]}"; do
            if ! check_log_result "${log_files[$i]}"; then
                failed+=("${os_names[$i]}")
            fi
        done

        # Show summary
        echo ""
        echo "========================================"
        echo "Summary"
        echo "========================================"
        echo ""
        echo "Logs saved in: $LOGS_DIR"
        for i in "${!os_names[@]}"; do
            echo "  ${os_names[$i]}: ${log_files[$i]}"
        done
        echo ""

        # Show cleanup status
        if [[ "$CLEANUP" != "true" ]]; then
            echo -e "${YELLOW}CLEANUP=false - Droplets kept for manual inspection${NC}"
            echo ""
            echo "Active test droplets:"
            echo "  List all: doctl compute droplet list --tag-name proxyctl-test"
            echo ""

            # Extract SSH connection details from log files
            echo "SSH Connection Instructions:"
            echo "========================================"
            for i in "${!os_names[@]}"; do
                local log="${log_files[$i]}"
                local os="${os_names[$i]}"

                # Extract droplet IP, SSH key path, and droplet ID from log file
                local droplet_ip=$(grep -o "Droplet IP: [0-9.]*" "$log" | head -1 | cut -d' ' -f3)
                local ssh_key=$(grep -o "SSH: ssh -i [^ ]* root@" "$log" | head -1 | sed 's|SSH: ssh -i ||; s| root@||')
                local droplet_id=$(grep -o "Droplet ID: [0-9]*" "$log" | head -1 | cut -d' ' -f3)

                if [[ -n "$droplet_ip" && -n "$ssh_key" ]]; then
                    echo ""
                    echo "${os}:"
                    echo "  ssh -i $ssh_key root@$droplet_ip"
                    echo "  Droplet ID: $droplet_id"
                    echo "  Log: ${log}"
                fi
            done
            echo ""
            echo "========================================"
            echo ""
            echo "Manual cleanup commands:"
            echo "  # List all test droplets"
            echo "  doctl compute droplet list --tag-name proxyctl-test"
            echo ""
            echo "  # Delete all test droplets"
            echo "  doctl compute droplet delete \$(doctl compute droplet list --tag-name proxyctl-test --format ID --no-header)"
            echo ""
            echo "  # List test SSH keys"
            echo "  doctl compute ssh-key list --format ID,Name | grep proxyctl-test"
            echo ""
            echo "  # Delete all test SSH keys"
            echo "  doctl compute ssh-key delete \$(doctl compute ssh-key list --format ID,Name --no-header | grep proxyctl-test | awk '{print \$1}')"
            echo ""
            echo "Or use the Makefile target:"
            echo "  ${YELLOW}make test-cleanup${NC}"
            echo ""
        fi

        # Write status file (only if clean working tree)
        local distros_list=$(IFS=,; echo "${os_names[*]}")

        # Check if working tree is actually clean (regardless of ALLOW_DIRTY setting)
        local can_write_status=false
        cd "$PROJECT_ROOT"
        if git diff-index --quiet HEAD -- 2>/dev/null; then
            can_write_status=true
        fi

        if [[ ${#failed[@]} -eq 0 ]]; then
            echo -e "${GREEN}✓ All tests passed!${NC}"
            if [[ "$can_write_status" = true ]]; then
                write_status_file "passed" "$distros_list"
            else
                echo -e "${YELLOW}Skipping status file (working tree is dirty)${NC}"
            fi
            exit 0
        else
            echo -e "${RED}✗ Tests failed on: ${failed[*]}${NC}"
            echo ""
            if [[ "$can_write_status" = true ]]; then
                write_status_file "failed" "$distros_list"
            else
                echo -e "${YELLOW}Skipping status file (working tree is dirty)${NC}"
            fi
            exit 1
        fi
    else
        # Single test run (non-parallel)
        create_ssh_key

        # Check if working tree is actually clean (regardless of ALLOW_DIRTY setting)
        local can_write_status=false
        cd "$PROJECT_ROOT"
        if git diff-index --quiet HEAD -- 2>/dev/null; then
            can_write_status=true
        fi

        if run_single_test "$OS" "$SUITE"; then
            if [[ "$can_write_status" = true ]]; then
                write_status_file "passed" "$OS"
            else
                echo -e "${YELLOW}Skipping status file (working tree is dirty)${NC}"
            fi
            exit 0
        else
            if [[ "$can_write_status" = true ]]; then
                write_status_file "failed" "$OS"
            else
                echo -e "${YELLOW}Skipping status file (working tree is dirty)${NC}"
            fi
            exit 1
        fi
    fi
}

# Run main
main
