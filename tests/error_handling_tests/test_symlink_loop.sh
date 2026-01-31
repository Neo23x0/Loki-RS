#!/bin/bash

# Test: Symlink Loop Detection
# Description: Test that Loki handles circular symlinks gracefully without infinite loops
# Expected: Scanner should detect symlink loops and skip them, not hang or crash

set -euo pipefail

echo "=== Testing Symlink Loop Detection ==="

test_passed=true

# Create a test directory with circular symlinks
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Creating circular symlink structure in $TEST_DIR..."
mkdir -p "$TEST_DIR/a/b/c"
ln -s "../../a" "$TEST_DIR/a/b/c/loop"
echo "test" > "$TEST_DIR/a/normal.txt"

# Run Loki scan with timeout
echo "Running Loki scan (with 30s timeout)..."
if timeout 30 ./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl > /tmp/symlink_output.txt 2>&1; then
    echo "✓ Symlink loop: PASS - Scan completed within timeout"
    test_passed=true
elif [ $? -eq 124 ]; then
    echo "✗ Symlink loop: FAIL - Timeout reached (possible infinite loop)"
    test_passed=false
else
    # Check if it completed despite non-zero exit
    if grep -q "Loki-RS scan finished" /tmp/symlink_output.txt; then
        echo "✓ Symlink loop: PASS - Scan finished"
        test_passed=true
    else
        echo "✗ Symlink loop: FAIL - Scan did not complete normally"
        test_passed=false
    fi
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Symlink Loop Test: PASS ==="
    exit 0
else
    echo "=== Symlink Loop Test: FAIL ==="
    exit 1
fi
