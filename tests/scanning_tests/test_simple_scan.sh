#!/bin/bash

# Test: Simple Scan
# Description: Test basic scanning functionality on a simple directory
# Expected: Scanner should run without errors and complete successfully

echo "=== Testing Simple Scan ==="

# Create a test directory with some files
TEST_DIR="./test_scan_dir"
mkdir -p "$TEST_DIR"
echo "This is a test file" > "$TEST_DIR/test.txt"
echo "Another test file" > "$TEST_DIR/another.txt"

# Test basic scan
echo "Testing basic scan on test directory..."
if ./build/loki -f "$TEST_DIR" --nofs 2>&1 | grep -q "LOKI scan started"; then
    echo "✓ Basic scan: PASS"
    scan_exit=0
else
    echo "✗ Basic scan: FAIL"
    scan_exit=1
fi

# Cleanup
rm -rf "$TEST_DIR"

# Overall test result
if [ $scan_exit -eq 0 ]; then
    echo "=== Simple Scan Test: PASS ==="
    exit 0
else
    echo "=== Simple Scan Test: FAIL ==="
    exit 1
fi
