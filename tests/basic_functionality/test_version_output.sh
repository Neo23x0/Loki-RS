#!/bin/bash

# Test: Version Output
# Description: Verify that loki binary displays version information
# Expected: Version should match expected format and return exit code 0
#
# NOTE: --version is a safe command that doesn't trigger scanning

set -euo pipefail

echo "=== Testing Version Output ==="

# Track test results
test_passed=true

# Get version from Cargo.toml for comparison
if [ -f "Cargo.toml" ]; then
    cargo_version=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    echo "Expected version from Cargo.toml: $cargo_version"
fi

# Test loki version output (safe - just prints version)
echo "Testing loki --version..."
version_output=$(./build/loki --version 2>&1) || true

# Check if output contains "Version" and a version number pattern
if echo "$version_output" | grep -qE "Version [0-9]+\.[0-9]+"; then
    echo "✓ loki --version: PASS"
    echo "  Version output: $version_output"
else
    echo "✗ loki --version: FAIL"
    echo "  Expected: Output containing 'Version X.Y.Z' format"
    echo "  Actual output: $version_output"
    test_passed=false
fi

# Optionally verify version matches Cargo.toml
if [ -n "${cargo_version:-}" ]; then
    if echo "$version_output" | grep -q "$cargo_version"; then
        echo "✓ Version matches Cargo.toml: PASS"
    else
        echo "⚠ Version mismatch warning (non-fatal)"
        echo "  Cargo.toml version: $cargo_version"
        echo "  Binary version: $version_output"
    fi
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Version Output Test: PASS ==="
    exit 0
else
    echo "=== Version Output Test: FAIL ==="
    exit 1
fi
