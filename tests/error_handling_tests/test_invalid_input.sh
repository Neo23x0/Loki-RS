#!/bin/bash

# Test: Invalid Input Handling
# Description: Test how the scanner handles invalid input and edge cases
# Expected: Scanner should handle errors gracefully and provide meaningful error messages

echo "=== Testing Invalid Input Handling ==="

# Test 1: Non-existent directory
echo "Testing non-existent directory..."
if ./build/loki -f "/nonexistent/directory/path" --nofs 2>&1 | grep -q "Files scanned: 0"; then
    echo "✓ Non-existent directory: PASS (handles gracefully)"
    test1_exit=0
else
    echo "✗ Non-existent directory: FAIL"
    test1_exit=1
fi

# Test 2: Invalid option
echo "Testing invalid option..."
if ./build/loki --invalid-option 2>&1 | grep -q "Error"; then
    echo "✓ Invalid option: PASS (error handled)"
    test2_exit=0
else
    echo "✗ Invalid option: FAIL (no error detected)"
    test2_exit=1
fi

# Test 3: No arguments
echo "Testing no arguments..."
if ./build/loki 2>&1 | grep -q "LOKI YARA and IOC Scanner"; then
    echo "✓ No arguments: PASS (shows help)"
    test3_exit=0
else
    echo "✗ No arguments: FAIL"
    test3_exit=1
fi

# Overall test result
if [ $test1_exit -eq 0 ] && [ $test2_exit -eq 0 ] && [ $test3_exit -eq 0 ]; then
    echo "=== Invalid Input Handling Test: PASS ==="
    exit 0
else
    echo "=== Invalid Input Handling Test: FAIL ==="
    exit 1
fi
