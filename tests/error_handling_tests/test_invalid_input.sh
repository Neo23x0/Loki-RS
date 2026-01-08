#!/bin/bash

# Test: Invalid Input Handling
# Description: Test how the scanner handles invalid input and edge cases
# Expected: Scanner should handle errors gracefully and provide meaningful error messages
#
# IMPORTANT: All tests must use -f flag or non-scanning commands to prevent full system scans

set -euo pipefail

echo "=== Testing Invalid Input Handling ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../lib/test_helpers.sh" ]; then
    source "$SCRIPT_DIR/../lib/test_helpers.sh"
fi

# Track test results
test_passed=true

# Create a temp directory for safe testing
TEST_DIR=$(mktemp -d -t loki_test_XXXXXX)
trap "rm -rf $TEST_DIR" EXIT
echo "Using temp directory: $TEST_DIR"

# Test 1: Non-existent directory (with -f flag - safe)
echo ""
echo "Test 1: Testing non-existent directory..."
nonexistent_output=$(./build/loki -f "/nonexistent/directory/path/that/does/not/exist" --no-procs --no-tui --no-html --no-log --no-jsonl 2>&1) || true
if echo "$nonexistent_output" | grep -qE "(Files scanned: 0|No files found|error|Error|cannot|not found)"; then
    echo "✓ Non-existent directory: PASS (handles gracefully)"
else
    echo "✗ Non-existent directory: FAIL"
    echo "  Expected: Graceful handling with 0 files scanned or error message"
    echo "  Actual output:"
    echo "$nonexistent_output" | head -20 | sed 's/^/    /'
    test_passed=false
fi

# Test 2: Invalid option (this should fail immediately without scanning)
# We include a valid -f just to be safe, but --invalid-option should cause immediate exit
echo ""
echo "Test 2: Testing invalid option..."
invalid_option_output=$(./build/loki -f "$TEST_DIR" --invalid-option-that-does-not-exist 2>&1) || true
if echo "$invalid_option_output" | grep -qiE "(error|unknown|unexpected|invalid|unrecognized)"; then
    echo "✓ Invalid option: PASS (error handled)"
else
    echo "✗ Invalid option: FAIL (no error detected)"
    echo "  Expected: Error message about invalid option"
    echo "  Actual output:"
    echo "$invalid_option_output" | head -20 | sed 's/^/    /'
    test_passed=false
fi

# Test 3: Help flag (safe - just prints help and exits)
echo ""
echo "Test 3: Testing --help flag..."
help_output=$(./build/loki --help 2>&1) || true
if echo "$help_output" | grep -qE "(YARA|Scanner|Loki|Usage|help|Options)"; then
    echo "✓ Help flag: PASS (shows help)"
else
    echo "✗ Help flag: FAIL"
    echo "  Expected: Help or usage output"
    echo "  Actual output:"
    echo "$help_output" | head -20 | sed 's/^/    /'
    test_passed=false
fi

# Test 4: Version flag (safe - just prints version and exits)
echo ""
echo "Test 4: Testing --version flag..."
version_output=$(./build/loki --version 2>&1) || true
if echo "$version_output" | grep -qE "(Version|version|[0-9]+\.[0-9]+)"; then
    echo "✓ Version flag: PASS (shows version)"
else
    echo "✗ Version flag: FAIL"
    echo "  Expected: Version information"
    echo "  Actual output:"
    echo "$version_output" | head -20 | sed 's/^/    /'
    test_passed=false
fi

# Test 5: Empty directory scan (safe with -f flag)
echo ""
echo "Test 5: Testing empty directory..."
empty_output=$(./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl 2>&1) || true
if echo "$empty_output" | grep -qE "(Files scanned: 0|scanned|completed)"; then
    echo "✓ Empty directory: PASS (scans with 0 files)"
else
    echo "✗ Empty directory: FAIL"
    echo "  Expected: Scan completion with 0 files"
    echo "  Actual output:"
    echo "$empty_output" | head -20 | sed 's/^/    /'
    test_passed=false
fi

# Overall test result
echo ""
if [ "$test_passed" = true ]; then
    echo "=== Invalid Input Handling Test: PASS ==="
    exit 0
else
    echo "=== Invalid Input Handling Test: FAIL ==="
    exit 1
fi
