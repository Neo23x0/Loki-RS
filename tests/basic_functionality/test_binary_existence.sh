#!/bin/bash

# Test: Binary Existence
# Description: Verify that both loki and loki-util binaries exist and are executable
# Expected: Both binaries should exist in build/ directory and be executable

echo "=== Testing Binary Existence ==="

# Test loki binary existence
echo "Testing loki binary..."
if [ -f "./build/loki" ] && [ -x "./build/loki" ]; then
    echo "✓ loki binary: PASS (exists and executable)"
    loki_exit=0
else
    echo "✗ loki binary: FAIL (missing or not executable)"
    loki_exit=1
fi

# Test loki-util binary existence
echo "Testing loki-util binary..."
if [ -f "./build/loki-util" ] && [ -x "./build/loki-util" ]; then
    echo "✓ loki-util binary: PASS (exists and executable)"
    loki_util_exit=0
else
    echo "✗ loki-util binary: FAIL (missing or not executable)"
    loki_util_exit=1
fi

# Overall test result
if [ $loki_exit -eq 0 ] && [ $loki_util_exit -eq 0 ]; then
    echo "=== Binary Existence Test: PASS ==="
    exit 0
else
    echo "=== Binary Existence Test: FAIL ==="
    exit 1
fi
