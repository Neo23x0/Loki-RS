#!/bin/bash

# Test: Binary Existence
# Description: Verify that both loki and loki-util binaries exist and are executable
# Expected: Both binaries should exist in build/ directory and be executable

set -euo pipefail

echo "=== Testing Binary Existence ==="

# Track test results
test_passed=true

# Test loki binary existence
echo "Testing loki binary..."
if [ -f "./build/loki" ] && [ -x "./build/loki" ]; then
    echo "✓ loki binary: PASS (exists and executable)"
else
    echo "✗ loki binary: FAIL (missing or not executable)"
    echo "  Expected: ./build/loki to exist and be executable"
    if [ -f "./build/loki" ]; then
        echo "  Actual: File exists but is not executable"
        ls -la ./build/loki
    else
        echo "  Actual: File does not exist"
        echo "  Contents of ./build/:"
        ls -la ./build/ 2>&1 || echo "  Directory does not exist"
    fi
    test_passed=false
fi

# Test loki-util binary existence
echo "Testing loki-util binary..."
if [ -f "./build/loki-util" ] && [ -x "./build/loki-util" ]; then
    echo "✓ loki-util binary: PASS (exists and executable)"
else
    echo "✗ loki-util binary: FAIL (missing or not executable)"
    echo "  Expected: ./build/loki-util to exist and be executable"
    if [ -f "./build/loki-util" ]; then
        echo "  Actual: File exists but is not executable"
        ls -la ./build/loki-util
    else
        echo "  Actual: File does not exist"
    fi
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Binary Existence Test: PASS ==="
    exit 0
else
    echo "=== Binary Existence Test: FAIL ==="
    exit 1
fi
