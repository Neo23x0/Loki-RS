#!/bin/bash

# Test: Version Output
# Description: Verify that loki binary displays correct version information
# Expected: Version should match expected format and return exit code 0

echo "=== Testing Version Output ==="

# Test loki version output
echo "Testing loki --version..."
version_output=$(./build/loki --version 2>&1)

if echo "$version_output" | grep -q "Version 2.0.2-alpha"; then
    echo "✓ loki --version: PASS"
    echo "  Version: $version_output"
    exit 0
else
    echo "✗ loki --version: FAIL"
    echo "  Expected version format not found"
    echo "  Actual output: $version_output"
    exit 1
fi
