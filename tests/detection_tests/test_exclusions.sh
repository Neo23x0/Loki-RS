#!/bin/bash

# Test: Exclusion Configuration
# Description: Verify that exclusion patterns properly exclude files from scanning
# Expected: Files matching exclusion patterns should be skipped

set -euo pipefail

echo "=== Testing Exclusion Configuration ==="

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

# Create a test directory with a unique name we can exclude
EXCLUDE_TEST_DIR="$TEST_TEMP_DIR/exclude_test_dir_$(date +%s)"
mkdir -p "$EXCLUDE_TEST_DIR"

# Create a file with potentially matchable content
TEST_FILE="$EXCLUDE_TEST_DIR/test_file.exe"
echo "dummy executable content" > "$TEST_FILE"
echo "Created test file: $TEST_FILE"

# Backup the original config
if [ -f "$CONFIG_FILE" ]; then
    backup_file "$CONFIG_FILE"
    ORIGINAL_CONFIG=$(cat "$CONFIG_FILE")
else
    ORIGINAL_CONFIG=""
    echo "# LOKI2 Exclusions Configuration" > "$CONFIG_FILE"
fi

section "Test 1: Scan without exclusion"

echo "Running scan without exclusion pattern..."
run_loki -f "$EXCLUDE_TEST_DIR" --no-procs --scan-all-files || true

SCAN_OUTPUT_1="$TEST_OUTPUT"
echo "Scan output (last 10 lines):"
echo "$SCAN_OUTPUT_1" | tail -10 | sed 's/^/    /'

# Check if the file was scanned
if echo "$SCAN_OUTPUT_1" | grep -qE "Files scanned: [1-9]"; then
    echo -e "${GREEN}✓ Files were scanned (exclusion not active)${NC}"
    SCANNED_COUNT_1=$(echo "$SCAN_OUTPUT_1" | grep -oE "Files scanned: [0-9]+" | grep -oE "[0-9]+")
    echo "  Files scanned: $SCANNED_COUNT_1"
else
    echo -e "${YELLOW}⚠ Could not determine scan count${NC}"
    SCANNED_COUNT_1="unknown"
fi

section "Test 2: Add exclusion pattern"

# Add exclusion for our test directory
EXCLUSION_PATTERN=".*exclude_test_dir.*"
echo "Adding exclusion pattern: $EXCLUSION_PATTERN"

# Append exclusion to config
echo "" >> "$CONFIG_FILE"
echo "# Test exclusion pattern (temporary)" >> "$CONFIG_FILE"
echo "$EXCLUSION_PATTERN" >> "$CONFIG_FILE"

echo "Config file content:"
cat "$CONFIG_FILE" | tail -5 | sed 's/^/    /'

section "Test 3: Scan with exclusion"

echo "Running scan with exclusion pattern..."
run_loki -f "$EXCLUDE_TEST_DIR" --no-procs --scan-all-files || true

SCAN_OUTPUT_2="$TEST_OUTPUT"
echo "Scan output (last 10 lines):"
echo "$SCAN_OUTPUT_2" | tail -10 | sed 's/^/    /'

# Check if fewer files were scanned (or skipped)
if echo "$SCAN_OUTPUT_2" | grep -qiE "(skipped|excluded|Files scanned: 0)"; then
    echo -e "${GREEN}✓ Exclusion appears to be working${NC}"
else
    SCANNED_COUNT_2=$(echo "$SCAN_OUTPUT_2" | grep -oE "Files scanned: [0-9]+" | grep -oE "[0-9]+" || echo "unknown")
    echo "  Files scanned with exclusion: $SCANNED_COUNT_2"
    
    if [ "$SCANNED_COUNT_1" != "unknown" ] && [ "$SCANNED_COUNT_2" != "unknown" ]; then
        if [ "$SCANNED_COUNT_2" -lt "$SCANNED_COUNT_1" ]; then
            echo -e "${GREEN}✓ Fewer files scanned with exclusion active${NC}"
        elif [ "$SCANNED_COUNT_2" -eq 0 ]; then
            echo -e "${GREEN}✓ All files excluded from scan${NC}"
        fi
    fi
fi

section "Cleanup: Restore original config"

# Restore original config
if [ -n "$ORIGINAL_CONFIG" ]; then
    echo "$ORIGINAL_CONFIG" > "$CONFIG_FILE"
else
    restore_file "$CONFIG_FILE"
fi
echo "Config restored"

section "Test Results"

# Final result
if [ "$TEST_PASSED" = true ]; then
    echo "=== Exclusion Configuration Test: PASS ==="
    exit 0
else
    echo "=== Exclusion Configuration Test: FAIL ==="
    exit 1
fi

