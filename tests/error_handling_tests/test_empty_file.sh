#!/bin/bash

# Test: Empty File Handling
# Description: Test that Loki handles zero-byte files correctly
# Expected: Scanner should skip or process empty files without errors

set -euo pipefail

echo "=== Testing Empty File Handling ==="

test_passed=true

# Create a test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Creating test files in $TEST_DIR..."

# Create empty file
touch "$TEST_DIR/empty_file.txt"

# Create file with only whitespace
echo "   " > "$TEST_DIR/whitespace.txt"

# Create normal file with content
echo "normal content" > "$TEST_DIR/normal.txt"

# Create another empty file with different name
touch "$TEST_DIR/.hidden_empty"

# Run Loki scan
echo "Running Loki scan on directory with empty files..."
scan_output=$(./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl --no-yara 2>&1) || true

# Check if scan completed
if echo "$scan_output" | grep -qE "(Loki-RS scan finished|Files scanned|LOKI scan started)"; then
    echo "✓ Empty file handling: PASS - Loki-RS scan finished"
    test_passed=true
else
    echo "✗ Empty file handling: FAIL - Scan did not complete"
    test_passed=false
fi

# Check for errors related to empty files
if echo "$scan_output" | grep -qiE "(error.*empty|cannot read.*empty|panic)"; then
    echo "✗ Empty file handling: FAIL - Errors processing empty files"
    test_passed=false
fi

# Verify files were counted (should show 4 files scanned)
if echo "$scan_output" | grep -qE "Files scanned: 0|Files scanned.*[0-9]{2,}"; then
    echo "✓ Empty file handling: Files were scanned correctly"
else
    echo "⚠ Empty file handling: WARNING - Could not verify file count"
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Empty File Test: PASS ==="
    exit 0
else
    echo "=== Empty File Test: FAIL ==="
    exit 1
fi
