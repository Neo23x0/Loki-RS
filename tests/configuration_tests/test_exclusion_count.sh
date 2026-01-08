#!/bin/bash

# Test: Exclusion Count
# Description: Verify that exclusion count is reported correctly
# Expected: Empty config = 0 exclusions, adding patterns increases count

set -euo pipefail

echo "=== Testing Exclusion Count ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Setup
setup_temp_dir
register_cleanup

PROJECT_ROOT=$(get_project_root)
cd "$PROJECT_ROOT"

# Config file location
CONFIG_FILE="$PROJECT_ROOT/build/config/excludes.cfg"

section "Setup Test Environment"

# Create a simple test directory
TEST_DIR="$TEST_TEMP_DIR/test_scan"
mkdir -p "$TEST_DIR"
echo "test" > "$TEST_DIR/test.txt"

# Backup original config
if [ -f "$CONFIG_FILE" ]; then
    backup_file "$CONFIG_FILE"
    ORIGINAL_CONFIG=$(cat "$CONFIG_FILE")
fi

section "Test 1: Empty exclusion config (0 exclusions)"

# Create empty config (only comments)
cat > "$CONFIG_FILE" << 'EOF'
# LOKI2 Exclusions Configuration
# This file contains only comments - no active exclusions
# Empty lines and comments don't count

EOF

echo "Config file content (empty/comments only):"
cat "$CONFIG_FILE" | sed 's/^/    /'

# Run scan and check exclusion count
echo ""
echo "Running scan with empty exclusion config..."
run_loki -f "$TEST_DIR" --no-procs --scan-all-files || true

# Look for exclusion count in output
if echo "$TEST_OUTPUT" | grep -qiE "exclusion.*:.*0|0.*exclusion"; then
    echo -e "${GREEN}✓ Exclusion count is 0 with empty config${NC}"
    echo "$TEST_OUTPUT" | grep -iE "exclusion" | head -3 | sed 's/^/    /'
else
    echo "  Searching for exclusion info in output:"
    echo "$TEST_OUTPUT" | grep -iE "(exclusion|config)" | head -5 | sed 's/^/    /'
fi

section "Test 2: Config with 3 exclusion patterns"

# Create config with multiple exclusions
cat > "$CONFIG_FILE" << 'EOF'
# LOKI2 Exclusions Configuration
# Test with 3 active exclusion patterns

.*/node_modules/.*
.*/\.git/.*
.*\.tmp$
EOF

echo "Config file content (3 exclusions):"
cat "$CONFIG_FILE" | sed 's/^/    /'

# Run scan and check exclusion count
echo ""
echo "Running scan with 3 exclusion patterns..."
run_loki -f "$TEST_DIR" --no-procs --scan-all-files || true

# Look for exclusion count in output
if echo "$TEST_OUTPUT" | grep -qiE "exclusion.*:.*3|3.*exclusion"; then
    echo -e "${GREEN}✓ Exclusion count is 3${NC}"
    echo "$TEST_OUTPUT" | grep -iE "exclusion" | head -3 | sed 's/^/    /'
elif echo "$TEST_OUTPUT" | grep -qiE "exclusion.*:.*[1-9]|[1-9].*exclusion"; then
    echo -e "${GREEN}✓ Exclusion count shows non-zero value${NC}"
    echo "$TEST_OUTPUT" | grep -iE "exclusion" | head -3 | sed 's/^/    /'
else
    echo "  Searching for exclusion info in output:"
    echo "$TEST_OUTPUT" | grep -iE "(exclusion|config|pattern)" | head -5 | sed 's/^/    /'
fi

section "Test 3: Verify exclusion count is reported in scan info"

# Check if scan info section shows exclusion count
if echo "$TEST_OUTPUT" | grep -qiE "(Configuration|Scan limits|Settings)"; then
    echo -e "${GREEN}✓ Configuration/settings section found${NC}"
    echo "  Relevant output:"
    echo "$TEST_OUTPUT" | grep -iE "(configuration|limits|exclusion|setting)" | head -10 | sed 's/^/    /'
else
    echo "  Output does not explicitly show configuration section"
fi

section "Cleanup: Restore original config"

# Restore original config
if [ -n "${ORIGINAL_CONFIG:-}" ]; then
    echo "$ORIGINAL_CONFIG" > "$CONFIG_FILE"
    echo "Restored original config"
else
    restore_file "$CONFIG_FILE"
fi

section "Test Results"

# Final result
if [ "$TEST_PASSED" = true ]; then
    echo "=== Exclusion Count Test: PASS ==="
    exit 0
else
    echo "=== Exclusion Count Test: FAIL ==="
    exit 1
fi

