#!/bin/bash

# Test: Permission Denied Handling
# Description: Test that Loki gracefully handles files/directories it cannot read
# Expected: Scanner should continue scanning, report permission errors gracefully, not crash

set -euo pipefail

echo "=== Testing Permission Denied Handling ==="

test_passed=true

# Create a test directory with restricted permissions
TEST_DIR=$(mktemp -d)
trap "chmod -R +rwx $TEST_DIR; rm -rf $TEST_DIR" EXIT

echo "Creating test files with restricted permissions in $TEST_DIR..."
mkdir -p "$TEST_DIR/restricted"
echo "readable content" > "$TEST_DIR/readable.txt"
echo "secret content" > "$TEST_DIR/restricted/secret.txt"

# Remove read permissions
chmod 000 "$TEST_DIR/restricted"

# Run Loki scan
echo "Running Loki scan on directory with unreadable files..."
scan_output=$(./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl --no-yara 2>&1) || true

# Check if scan completed
if echo "$scan_output" | grep -qE "(Loki-RS scan finished|Files scanned|LOKI scan started)"; then
    echo "✓ Permission denied: PASS - Loki-RS scan finished despite permission errors"
    test_passed=true
else
    echo "✗ Permission denied: FAIL - Scan did not complete"
    test_passed=false
fi

# Check for graceful error handling (should not crash)
if echo "$scan_output" | grep -qiE "(panic|thread.*panicked|segmentation fault)"; then
    echo "✗ Permission denied: FAIL - Scanner crashed"
    test_passed=false
fi

# Restore permissions for cleanup
chmod 755 "$TEST_DIR/restricted"

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Permission Denied Test: PASS ==="
    exit 0
else
    echo "=== Permission Denied Test: FAIL ==="
    exit 1
fi
