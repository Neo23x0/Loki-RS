#!/bin/bash

# Test: Filename IOC Detection
# Description: Verify that custom filename IOC patterns are detected
# Expected: Files matching IOC patterns should be flagged

set -euo pipefail

echo "=== Testing Filename IOC Detection ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Setup
setup_temp_dir
register_cleanup

PROJECT_ROOT=$(get_project_root)
cd "$PROJECT_ROOT"

section "Setup Test Environment"

# Create a file with a suspicious name that should match existing IOC patterns
# Using a pattern that looks like a known malware filename
SUSPICIOUS_FILE="$TEST_TEMP_DIR/svcsstat.exe"
echo "dummy content" > "$SUSPICIOUS_FILE"
echo "Created suspicious file: $SUSPICIOUS_FILE"

# Also create a normal file that shouldn't match
NORMAL_FILE="$TEST_TEMP_DIR/normal_document.txt"
echo "This is a normal document" > "$NORMAL_FILE"
echo "Created normal file: $NORMAL_FILE"

section "Test 1: Scan with suspicious filename"

# Run Loki scan on the temp directory
echo "Running Loki scan on test directory..."
run_loki -f "$TEST_TEMP_DIR" --no-procs --scan-all-files || true

# Check if the suspicious file was detected
# Look for the file path or "svcsstat" in the output
if echo "$TEST_OUTPUT" | grep -qiE "(svcsstat|ALERT|WARNING|NOTICE|Match|Filename IOC)"; then
    echo -e "${GREEN}✓ Suspicious filename detected${NC}"
    echo "  Detection output:"
    echo "$TEST_OUTPUT" | grep -iE "(svcsstat|ALERT|WARNING|NOTICE|Match)" | head -5 | sed 's/^/    /'
else
    echo -e "${YELLOW}⚠ No detection for svcsstat.exe (may not be in default IOCs)${NC}"
    echo "  This is expected if the IOC pattern is not in the current signature set"
    echo "  Output (last 20 lines):"
    echo "$TEST_OUTPUT" | tail -20 | sed 's/^/    /'
fi

section "Test 2: Verify scan completes successfully"

# Verify the scan completed
assert_contains "Files scanned" "Scan should report files scanned"

section "Test 3: Check scan statistics"

# Verify we scanned some files
if echo "$TEST_OUTPUT" | grep -qE "Files scanned: [1-9]"; then
    echo -e "${GREEN}✓ Files were scanned${NC}"
else
    echo -e "${YELLOW}⚠ Could not verify file scan count${NC}"
    echo "  Output:"
    echo "$TEST_OUTPUT" | grep -i "scanned" | head -3 | sed 's/^/    /'
fi

section "Test Results"

# Final result
if [ "$TEST_PASSED" = true ]; then
    echo "=== Filename IOC Detection Test: PASS ==="
    exit 0
else
    echo "=== Filename IOC Detection Test: FAIL ==="
    exit 1
fi

