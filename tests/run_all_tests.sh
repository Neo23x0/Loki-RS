#!/bin/bash

# Test Runner: Run All Loki-RS Tests
# Description: Run all test suites and provide a comprehensive report with verbose output
# Expected: All tests should pass, providing confidence in the scanner's functionality

# Note: We use 'set -uo pipefail' but NOT 'set -e' because:
# 1. We handle test failures ourselves (tracking exit codes)
# 2. Arithmetic operations like ((var++)) return exit code 1 when var is 0
set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Running All Loki-RS Tests ===${NC}"
echo ""

# Initialize counters
total_tests=0
passed_tests=0
failed_tests=0
skipped_tests=0

# Arrays to track failed tests
declare -a failed_test_names=()

# Determine script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Change to project root
cd "$PROJECT_ROOT"

echo "Project root: $PROJECT_ROOT"
echo "Tests directory: $SCRIPT_DIR"
echo ""

# Source helper library if available
if [ -f "$SCRIPT_DIR/lib/test_helpers.sh" ]; then
    source "$SCRIPT_DIR/lib/test_helpers.sh"
fi

# Function to run a test and track results
run_test() {
    local test_name=$1
    local test_script=$2

    echo -e "${BLUE}----------------------------------------${NC}"
    echo -e "${BLUE}Running: $test_name${NC}"
    echo "Script: $test_script"
    echo ""

    if [ ! -f "$test_script" ]; then
        echo -e "${YELLOW}⚠ $test_name: SKIPPED (test script not found)${NC}"
        skipped_tests=$((skipped_tests + 1))
        total_tests=$((total_tests + 1))
        return
    fi

    # Run the test and capture output
    local start_time=$(date +%s)
    local test_output
    local exit_code=0
    
    test_output=$(bash "$test_script" 2>&1) || exit_code=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Show test output
    echo "$test_output"
    echo ""

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ $test_name: PASS${NC} (${duration}s)"
        passed_tests=$((passed_tests + 1))
    else
        echo -e "${RED}✗ $test_name: FAIL (exit code: $exit_code)${NC}"
        failed_test_names+=("$test_name")
        failed_tests=$((failed_tests + 1))
    fi
    total_tests=$((total_tests + 1))
    echo ""
}

# Check prerequisites
echo -e "${BLUE}=== Checking Prerequisites ===${NC}"
if [ ! -f "./build/loki" ]; then
    echo -e "${RED}ERROR: build/loki not found. Please run 'make package' first.${NC}"
    exit 1
fi
if [ ! -f "./build/loki-util" ]; then
    echo -e "${RED}ERROR: build/loki-util not found. Please run 'make package' first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Prerequisites satisfied${NC}"
echo ""

# Run basic functionality tests
echo -e "${BLUE}=== Basic Functionality Tests ===${NC}"
run_test "Binary Existence Test" "./tests/basic_functionality/test_binary_existence.sh"
run_test "Help Output Test" "./tests/basic_functionality/test_help_output.sh"
run_test "Version Output Test" "./tests/basic_functionality/test_version_output.sh"

# Run scanning tests
echo -e "${BLUE}=== Scanning Tests ===${NC}"
run_test "Simple Scan Test" "./tests/scanning_tests/test_simple_scan.sh"

# Run error handling tests
echo -e "${BLUE}=== Error Handling Tests ===${NC}"
run_test "Invalid Input Test" "./tests/error_handling_tests/test_invalid_input.sh"

# Run detection tests if they exist
if [ -d "./tests/detection_tests" ]; then
    echo -e "${BLUE}=== Detection Tests ===${NC}"
    for test_script in ./tests/detection_tests/test_*.sh; do
        if [ -f "$test_script" ]; then
            test_name=$(basename "$test_script" .sh | sed 's/test_//' | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')
            run_test "$test_name" "$test_script"
        fi
    done
fi

# Run configuration tests if they exist
if [ -d "./tests/configuration_tests" ]; then
    echo -e "${BLUE}=== Configuration Tests ===${NC}"
    for test_script in ./tests/configuration_tests/test_*.sh; do
        if [ -f "$test_script" ]; then
            test_name=$(basename "$test_script" .sh | sed 's/test_//' | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')
            run_test "$test_name" "$test_script"
        fi
    done
fi

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Total tests:   $total_tests"
echo -e "Passed:        ${GREEN}$passed_tests${NC}"
echo -e "Failed:        ${RED}$failed_tests${NC}"
echo -e "Skipped:       ${YELLOW}$skipped_tests${NC}"
echo ""

if [ $failed_tests -gt 0 ]; then
    echo -e "${RED}Failed tests:${NC}"
    for failed_test in "${failed_test_names[@]}"; do
        echo -e "  ${RED}✗ $failed_test${NC}"
    done
    echo ""
    echo -e "${RED}=== TESTS FAILED ===${NC}"
    exit 1
else
    echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
    exit 0
fi
