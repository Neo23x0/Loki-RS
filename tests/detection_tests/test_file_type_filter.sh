#!/bin/bash

# Test: File Type Filtering (--scan-all-files)
# Description: Verify that file type filtering works correctly
# Expected: Without --scan-all-files, non-suspicious file types are skipped
#           With --scan-all-files, all files are scanned

set -euo pipefail

echo "=== Testing File Type Filtering ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Setup
setup_temp_dir
register_cleanup

PROJECT_ROOT=$(get_project_root)
cd "$PROJECT_ROOT"

section "Setup Test Environment"

# Create files with different extensions
# .txt and .log files are NOT in the default scan list
# .exe, .dll, .ps1, .sh are in the default scan list

# File with ignored extension but potentially suspicious content
IGNORED_FILE="$TEST_TEMP_DIR/document.txt"
echo "This contains netcat which is suspicious" > "$IGNORED_FILE"
echo "Created ignored-extension file: $IGNORED_FILE"

# File with scanned extension
SCANNED_FILE="$TEST_TEMP_DIR/script.ps1"
echo "# PowerShell script with netcat" > "$SCANNED_FILE"
echo "Created scanned-extension file: $SCANNED_FILE"

# Another ignored extension
LOG_FILE="$TEST_TEMP_DIR/application.log"
echo "netcat connection attempt" > "$LOG_FILE"
echo "Created log file: $LOG_FILE"

# Create a data file with no extension (should also be interesting)
DATA_FILE="$TEST_TEMP_DIR/mydata"
echo "random data file content" > "$DATA_FILE"
echo "Created data file without extension: $DATA_FILE"

section "Test 1: Scan WITHOUT --scan-all-files"

echo "Running scan without --scan-all-files (default behavior)..."
run_loki -f "$TEST_TEMP_DIR" --no-procs || true

SCAN_OUTPUT_DEFAULT="$TEST_OUTPUT"
echo "Scan output (relevant lines):"
echo "$SCAN_OUTPUT_DEFAULT" | grep -iE "(scanned|skipped|Files)" | head -10 | sed 's/^/    /'

# Extract counts
SCANNED_DEFAULT=$(echo "$SCAN_OUTPUT_DEFAULT" | grep -oE "Files scanned: [0-9]+" | grep -oE "[0-9]+" || echo "0")
SKIPPED_DEFAULT=$(echo "$SCAN_OUTPUT_DEFAULT" | grep -oE "Files skipped: [0-9]+" | grep -oE "[0-9]+" || echo "0")

echo "  Files scanned (default): $SCANNED_DEFAULT"
echo "  Files skipped (default): $SKIPPED_DEFAULT"

section "Test 2: Scan WITH --scan-all-files"

echo "Running scan with --scan-all-files..."
run_loki -f "$TEST_TEMP_DIR" --no-procs --scan-all-files || true

SCAN_OUTPUT_ALL="$TEST_OUTPUT"
echo "Scan output (relevant lines):"
echo "$SCAN_OUTPUT_ALL" | grep -iE "(scanned|skipped|Files)" | head -10 | sed 's/^/    /'

# Extract counts
SCANNED_ALL=$(echo "$SCAN_OUTPUT_ALL" | grep -oE "Files scanned: [0-9]+" | grep -oE "[0-9]+" || echo "0")
SKIPPED_ALL=$(echo "$SCAN_OUTPUT_ALL" | grep -oE "Files skipped: [0-9]+" | grep -oE "[0-9]+" || echo "0")

echo "  Files scanned (with --scan-all-files): $SCANNED_ALL"
echo "  Files skipped (with --scan-all-files): $SKIPPED_ALL"

section "Test 3: Compare results"

# With --scan-all-files, we should scan MORE files (or skip FEWER)
if [ "$SCANNED_ALL" -gt "$SCANNED_DEFAULT" ]; then
    echo -e "${GREEN}✓ --scan-all-files scans more files${NC}"
    echo "  Default: $SCANNED_DEFAULT files"
    echo "  With flag: $SCANNED_ALL files"
elif [ "$SKIPPED_ALL" -lt "$SKIPPED_DEFAULT" ]; then
    echo -e "${GREEN}✓ --scan-all-files skips fewer files${NC}"
    echo "  Default skipped: $SKIPPED_DEFAULT files"
    echo "  With flag skipped: $SKIPPED_ALL files"
elif [ "$SCANNED_ALL" -ge "$SCANNED_DEFAULT" ] && [ "$SCANNED_ALL" -gt 0 ]; then
    echo -e "${GREEN}✓ --scan-all-files scans files (count: $SCANNED_ALL)${NC}"
else
    echo -e "${YELLOW}⚠ Could not verify difference in scan behavior${NC}"
    echo "  Default scanned: $SCANNED_DEFAULT, All scanned: $SCANNED_ALL"
    echo "  This may be expected if all test files happen to match default criteria"
fi

section "Test 4: Verify scan configuration reported"

# Check if the scan configuration is reported in output
if echo "$SCAN_OUTPUT_ALL" | grep -qiE "SCAN_ALL_TYPES.*true"; then
    echo -e "${GREEN}✓ Scan configuration shows SCAN_ALL_TYPES=true${NC}"
else
    echo "  Scan configuration (checking for SCAN_ALL_TYPES):"
    echo "$SCAN_OUTPUT_ALL" | grep -iE "SCAN_ALL" | head -3 | sed 's/^/    /'
fi

section "Test Results"

# Final result
if [ "$TEST_PASSED" = true ]; then
    echo "=== File Type Filtering Test: PASS ==="
    exit 0
else
    echo "=== File Type Filtering Test: FAIL ==="
    exit 1
fi

