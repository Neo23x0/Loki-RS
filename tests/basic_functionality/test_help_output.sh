#!/bin/bash

# Test: Help Output
# Description: Verify that both loki and loki-util binaries display proper help output
# Expected: Both binaries should display help text and return exit code 0

echo "=== Testing Help Output ==="

# Test loki help output
echo "Testing loki --help..."
if ./build/loki --help > /dev/null 2>&1; then
    echo "✓ loki --help: PASS"
    loki_help_exit=0
else
    echo "✗ loki --help: FAIL"
    loki_help_exit=1
fi

# Test loki-util help output (note: loki-util uses different syntax)
echo "Testing loki-util (no args for help)..."
if ./build/loki-util 2>&1 | grep -q "Loki-RS Utility Tool"; then
    echo "✓ loki-util help: PASS"
    loki_util_help_exit=0
else
    echo "✗ loki-util help: FAIL"
    loki_util_help_exit=1
fi

# Overall test result
if [ $loki_help_exit -eq 0 ] && [ $loki_util_help_exit -eq 0 ]; then
    echo "=== Help Output Test: PASS ==="
    exit 0
else
    echo "=== Help Output Test: FAIL ==="
    exit 1
fi
