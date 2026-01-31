#!/bin/bash

# Test: Corrupted Binary Parsing
# Description: Test that Loki handles corrupted/invalid PE/ELF files without crashing
# Expected: Scanner should skip or gracefully handle corrupted binaries, not panic

set -euo pipefail

echo "=== Testing Corrupted Binary Parsing ==="

test_passed=true

# Create a test directory
cd ~/clawd/loki-rs
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Creating corrupted binary files in $TEST_DIR..."

# Create a fake PE header that starts correctly but is truncated
printf 'MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$TEST_DIR/fake_pe.exe"

# Create a fake ELF header that is invalid
printf '\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$TEST_DIR/fake_elf"

# Create random garbage that might be mistaken for binary
head -c 100 /dev/urandom > "$TEST_DIR/garbage.bin"

# Create a normal file for reference
echo "normal text file" > "$TEST_DIR/normal.txt"

# Run Loki scan
echo "Running Loki scan on directory with corrupted binaries..."
scan_output=$(./build/loki -f "$TEST_DIR" --no-procs --no-tui --no-html --no-log --no-jsonl --no-yara 2>&1) || true

# Check if scan completed without crashing
if echo "$scan_output" | grep -qE "(Loki-RS scan finished|Files scanned|LOKI scan started)"; then
    echo "✓ Corrupted binary: PASS - Loki-RS scan finished without crash"
    test_passed=true
else
    echo "✗ Corrupted binary: FAIL - Scan did not complete"
    test_passed=false
fi

# Check for crashes
if echo "$scan_output" | grep -qiE "(panic|thread.*panicked|segmentation fault|SIGSEGV)"; then
    echo "✗ Corrupted binary: FAIL - Scanner crashed on corrupted files"
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Corrupted Binary Test: PASS ==="
    exit 0
else
    echo "=== Corrupted Binary Test: FAIL ==="
    exit 1
fi
