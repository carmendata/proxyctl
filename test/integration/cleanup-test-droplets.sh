#!/bin/bash
#
# Cleanup orphaned proxyctl test droplets
# Use this to destroy test droplets that weren't automatically cleaned up
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Proxyctl Test Droplet Cleanup${NC}"
echo ""

# Check if doctl is installed
if ! command -v doctl >/dev/null 2>&1; then
    echo -e "${RED}Error: doctl not installed${NC}"
    echo "Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
    exit 1
fi

# Check if authenticated
if ! doctl account get >/dev/null 2>&1; then
    echo -e "${RED}Error: doctl not authenticated${NC}"
    echo "Run: doctl auth init"
    exit 1
fi

# Find all test droplets
echo "Finding test droplets..."
droplets=$(doctl compute droplet list --tag-name proxyctl-test --format ID,Name,PublicIPv4,Created --no-header)

if [ -z "$droplets" ]; then
    echo -e "${GREEN}No test droplets found${NC}"
    exit 0
fi

echo ""
echo "Found test droplets:"
echo "===================="
echo "$droplets"
echo ""

# Parse droplet IDs
droplet_ids=$(echo "$droplets" | awk '{print $1}')
droplet_count=$(echo "$droplet_ids" | wc -w)

echo -e "${YELLOW}Found $droplet_count test droplets${NC}"
echo ""

# Confirm destruction
echo -e "${RED}WARNING: This will destroy all test droplets listed above!${NC}"
echo -n "Type 'yes' to confirm: "
read -r confirmation

if [ "$confirmation" != "yes" ]; then
    echo "Cancelled"
    exit 0
fi

echo ""
echo "Destroying droplets..."
for id in $droplet_ids; do
    echo -n "  Destroying droplet $id... "
    if doctl compute droplet delete "$id" --force >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗ failed${NC}"
    fi
done

echo ""
echo -e "${GREEN}Cleanup complete${NC}"
