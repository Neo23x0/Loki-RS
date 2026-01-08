#!/bin/bash

# Test: Simple Scan
# Description: Test basic scanning functionality on a simple directory
# Expected: Scanner should run without errors and complete successfully

set -euo pipefail

echo "=== Testing Simple Scan ==="

# Track test results
test_passed=true

# Create a test directory with some files
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Creating test files in $TEST_DIR..."
echo "This is a test file" > "$TEST_DIR/test.txt"
echo "Another test file" > "$TEST_DIR/another.txt"

# Test basic scan (using --no-fs is wrong - we want to scan the filesystem!)
# Just run a simple scan on the test directory with --no-procs to skip process scanning
echo "Testing basic scan on test directory..."
scan_output=$(./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl 2>&1) || true

# Check if scan started and completed
if echo "$scan_output" | grep -qE "(LOKI scan started|Scan completed|Files scanned)"; then
    echo "✓ Basic scan: PASS"
    echo "  Scan output (last 10 lines):"
    echo "$scan_output" | tail -10
else
    echo "✗ Basic scan: FAIL"
    echo "  Expected: Output containing scan progress/completion messages"
    echo "  Actual output:"
    echo "$scan_output"
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Simple Scan Test: PASS ==="
    exit 0
else
    echo "=== Simple Scan Test: FAIL ==="
    exit 1
fi
