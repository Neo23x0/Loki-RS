#!/bin/bash

# Test Runner: Run All Beta Tests
# Description: Run all test suites and provide a comprehensive report
# Expected: All tests should pass, providing confidence in the scanner's functionality

echo "=== Running All Beta Tests ==="

# Initialize counters
total_tests=0
passed_tests=0
failed_tests=0

# Function to run a test and track results
run_test() {
    test_name=$1
    test_script=$2

    echo "Running $test_name..."
    if [ -f "$test_script" ]; then
        if bash "$test_script"; then
            echo "✓ $test_name: PASS"
            ((passed_tests++))
        else
            echo "✗ $test_name: FAIL"
            ((failed_tests++))
        fi
        ((total_tests++))
    else
        echo "⚠ $test_name: SKIPPED (test script not found)"
    fi
}

# Run basic functionality tests
echo "--- Basic Functionality Tests ---"
run_test "Binary Existence Test" "./tests/basic_functionality/test_binary_existence.sh"
run_test "Help Output Test" "./tests/basic_functionality/test_help_output.sh"
run_test "Version Output Test" "./tests/basic_functionality/test_version_output.sh"

# Run scanning tests
echo "--- Scanning Tests ---"
run_test "Simple Scan Test" "./tests/scanning_tests/test_simple_scan.sh"

# Run error handling tests
echo "--- Error Handling Tests ---"
run_test "Invalid Input Test" "./tests/error_handling_tests/test_invalid_input.sh"

# Summary
echo "=== Test Summary ==="
echo "Total tests: $total_tests"
echo "Passed: $passed_tests"
echo "Failed: $failed_tests"

if [ $failed_tests -eq 0 ]; then
    echo "=== All Tests: PASS ==="
    exit 0
else
    echo "=== Some Tests: FAIL ==="
    exit 1
fi
