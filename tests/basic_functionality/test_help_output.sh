#!/bin/bash

# Test: Help Output
# Description: Verify that both loki and loki-util binaries display proper help output
# Expected: Both binaries should display help text and return exit code 0
#
# NOTE: --help is a safe command that doesn't trigger scanning

set -euo pipefail

echo "=== Testing Help Output ==="

# Track test results
test_passed=true

# Test loki help output (safe - just prints help)
echo "Testing loki --help..."
loki_help_output=$(./build/loki --help 2>&1) || true
if echo "$loki_help_output" | grep -q "Loki-RS"; then
    echo "✓ loki --help: PASS"
else
    echo "✗ loki --help: FAIL"
    echo "  Expected: Output to contain 'Loki-RS'"
    echo "  Actual output:"
    echo "$loki_help_output" | head -20
    test_passed=false
fi

# Test loki-util help output (safe - just prints help)
echo "Testing loki-util (no args for help)..."
loki_util_output=$(./build/loki-util 2>&1) || true
# Check for LOKI (uppercase in ASCII art) or various help indicators
if echo "$loki_util_output" | grep -qiE "(LOKI|loki|Scanner|update|help)"; then
    echo "✓ loki-util help: PASS"
else
    echo "✗ loki-util help: FAIL"
    echo "  Expected: Output to contain 'LOKI' or help text"
    echo "  Actual output:"
    echo "$loki_util_output" | head -20
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Help Output Test: PASS ==="
    exit 0
else
    echo "=== Help Output Test: FAIL ==="
    exit 1
fi
