#!/bin/bash
# Tests for loki-util HTML report generation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
BUILD_DIR="$PROJECT_ROOT/target/release"
TEST_OUTPUT_DIR="$SCRIPT_DIR/html_test_output"

# Source test helpers
source "$SCRIPT_DIR/lib/test_helpers.sh"

# Clean up test output directory
rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

# Find loki-util binary
if [ -f "$BUILD_DIR/loki-util" ]; then
    LOKI_UTIL="$BUILD_DIR/loki-util"
elif [ -f "$PROJECT_ROOT/target/debug/loki-util" ]; then
    LOKI_UTIL="$PROJECT_ROOT/target/debug/loki-util"
else
    echo "Error: loki-util binary not found. Please build it first."
    exit 1
fi

echo "Using loki-util: $LOKI_UTIL"

# Test 1: Single JSONL file -> HTML report
test_single_jsonl_to_html() {
    echo "[TEST] Single JSONL file -> HTML report"
    
    local input="$FIXTURES_DIR/minimal.jsonl"
    local output="$TEST_OUTPUT_DIR/minimal_report.html"
    
    if ! "$LOKI_UTIL" html --input "$input" --output "$output"; then
        echo "FAIL: Command failed"
        return 1
    fi
    
    if [ ! -f "$output" ]; then
        echo "FAIL: Output file not created"
        return 1
    fi
    
    # Check that HTML contains expected elements
    if ! grep -q "Loki-RS Scan Report" "$output"; then
        echo "FAIL: HTML missing title"
        return 1
    fi
    
    if ! grep -q "test-host" "$output"; then
        echo "FAIL: HTML missing hostname"
        return 1
    fi
    
    if ! grep -q "ALERT" "$output"; then
        echo "FAIL: HTML missing alert finding"
        return 1
    fi
    
    echo "PASS: Single JSONL -> HTML report generated successfully"
    return 0
}

# Test 2: Multiple severities in HTML report
test_multiple_severities() {
    echo "[TEST] Multiple severities in HTML report"
    
    local input="$FIXTURES_DIR/multiple_severities.jsonl"
    local output="$TEST_OUTPUT_DIR/multiple_severities_report.html"
    
    if ! "$LOKI_UTIL" html --input "$input" --output "$output"; then
        echo "FAIL: Command failed"
        return 1
    fi
    
    if [ ! -f "$output" ]; then
        echo "FAIL: Output file not created"
        return 1
    fi
    
    # Check for all severity levels
    if ! grep -q "ALERT" "$output"; then
        echo "FAIL: HTML missing ALERT"
        return 1
    fi
    
    if ! grep -q "WARNING" "$output"; then
        echo "FAIL: HTML missing WARNING"
        return 1
    fi
    
    if ! grep -q "NOTICE" "$output"; then
        echo "FAIL: HTML missing NOTICE"
        return 1
    fi
    
    echo "PASS: Multiple severities report generated successfully"
    return 0
}

# Test 3: Malformed JSONL lines are skipped
test_malformed_jsonl() {
    echo "[TEST] Malformed JSONL lines are skipped gracefully"
    
    local input="$FIXTURES_DIR/malformed.jsonl"
    local output="$TEST_OUTPUT_DIR/malformed_report.html"
    
    if ! "$LOKI_UTIL" html --input "$input" --output "$output"; then
        echo "FAIL: Command failed (should handle malformed lines)"
        return 1
    fi
    
    if [ ! -f "$output" ]; then
        echo "FAIL: Output file not created"
        return 1
    fi
    
    # Should still have valid findings
    if ! grep -q "ALERT" "$output"; then
        echo "FAIL: HTML missing valid findings"
        return 1
    fi
    
    echo "PASS: Malformed JSONL handled gracefully"
    return 0
}

# Test 4: Combined report from multiple JSONL files
test_combined_report() {
    echo "[TEST] Combined report from multiple JSONL files"
    
    local input1="$FIXTURES_DIR/host1.jsonl"
    local input2="$FIXTURES_DIR/host2.jsonl"
    local output="$TEST_OUTPUT_DIR/combined_report.html"
    
    # Use glob pattern to match both files
    local input_pattern="$FIXTURES_DIR/host*.jsonl"
    
    if ! "$LOKI_UTIL" html --input "$input_pattern" --combine --output "$output"; then
        echo "FAIL: Command failed"
        return 1
    fi
    
    if [ ! -f "$output" ]; then
        echo "FAIL: Output file not created"
        return 1
    fi
    
    # Check for combined report elements
    if ! grep -q "Combined Scan Report" "$output"; then
        echo "FAIL: HTML missing combined report title"
        return 1
    fi
    
    if ! grep -q "host1.example.com" "$output"; then
        echo "FAIL: HTML missing host1"
        return 1
    fi
    
    if ! grep -q "host2.example.com" "$output"; then
        echo "FAIL: HTML missing host2"
        return 1
    fi
    
    # Check for summary table
    if ! grep -q "Summary" "$output"; then
        echo "FAIL: HTML missing summary section"
        return 1
    fi
    
    echo "PASS: Combined report generated successfully"
    return 0
}

# Test 5: Default output path (input.html)
test_default_output_path() {
    echo "[TEST] Default output path (input.html)"
    
    local input="$FIXTURES_DIR/minimal.jsonl"
    local expected_output="$FIXTURES_DIR/minimal.html"
    
    # Remove if exists from previous test
    rm -f "$expected_output"
    
    if ! "$LOKI_UTIL" html --input "$input"; then
        echo "FAIL: Command failed"
        return 1
    fi
    
    if [ ! -f "$expected_output" ]; then
        echo "FAIL: Default output file not created at $expected_output"
        return 1
    fi
    
    # Clean up
    rm -f "$expected_output"
    
    echo "PASS: Default output path works correctly"
    return 0
}

# Run all tests
run_tests() {
    local failed=0
    
    test_single_jsonl_to_html || failed=$((failed + 1))
    test_multiple_severities || failed=$((failed + 1))
    test_malformed_jsonl || failed=$((failed + 1))
    test_combined_report || failed=$((failed + 1))
    test_default_output_path || failed=$((failed + 1))
    
    if [ $failed -eq 0 ]; then
        echo ""
        echo "All tests passed!"
        return 0
    else
        echo ""
        echo "$failed test(s) failed"
        return 1
    fi
}

# Main
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    run_tests
fi
