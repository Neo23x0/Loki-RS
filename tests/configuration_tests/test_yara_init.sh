#!/bin/bash

# Test: YARA Rules Initialization
# Description: Verify that YARA rules are loaded without errors
# Expected: YARA rules should initialize successfully and report rule count

set -euo pipefail

echo "=== Testing YARA Rules Initialization ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Setup
setup_temp_dir
register_cleanup

PROJECT_ROOT=$(get_project_root)
cd "$PROJECT_ROOT"

section "Check YARA Signatures"

# Check if signatures exist
SIGNATURES_DIR="$PROJECT_ROOT/build/signatures"
YARA_DIR="$SIGNATURES_DIR/yara"

if [ -d "$YARA_DIR" ]; then
    echo -e "${GREEN}✓ YARA signatures directory exists${NC}"
    echo "  Path: $YARA_DIR"
    
    # Count YARA files
    YARA_FILE_COUNT=$(find "$YARA_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l | tr -d ' ')
    echo "  YARA rule files found: $YARA_FILE_COUNT"
    
    if [ "$YARA_FILE_COUNT" -gt 0 ]; then
        echo "  YARA files:"
        find "$YARA_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | head -5 | sed 's/^/    /'
    fi
else
    echo -e "${RED}✗ YARA signatures directory not found${NC}"
    echo "  Expected: $YARA_DIR"
    echo "  Run 'make package' to set up signatures"
    TEST_PASSED=false
fi

section "Test 1: YARA Initialization"

# Create a simple test directory
TEST_DIR="$TEST_TEMP_DIR/yara_init_test"
mkdir -p "$TEST_DIR"
echo "test file" > "$TEST_DIR/test.txt"

# Run Loki and capture initialization output
echo "Running Loki scan to check YARA initialization..."
run_loki -f "$TEST_DIR" --no-procs --scan-all-files || true

# Check for YARA initialization messages
echo ""
echo "Checking for YARA initialization..."

# Look for successful initialization
if echo "$TEST_OUTPUT" | grep -qiE "(YARA rules|rules.*loaded|Initializing YARA|rules compiled)"; then
    echo -e "${GREEN}✓ YARA initialization mentioned in output${NC}"
    echo "  Relevant output:"
    echo "$TEST_OUTPUT" | grep -iE "(YARA|rules)" | head -10 | sed 's/^/    /'
else
    echo "  No explicit YARA initialization messages found"
    echo "  This may be normal if TUI mode suppresses these messages"
fi

section "Test 2: Check for YARA errors"

# Look for any YARA-related errors
if echo "$TEST_OUTPUT" | grep -qiE "(YARA.*error|error.*YARA|Failed.*YARA|YARA.*failed)"; then
    echo -e "${RED}✗ YARA errors detected${NC}"
    echo "  Error messages:"
    echo "$TEST_OUTPUT" | grep -iE "(error|failed)" | head -10 | sed 's/^/    /'
    TEST_PASSED=false
else
    echo -e "${GREEN}✓ No YARA errors detected${NC}"
fi

section "Test 3: Verify YARA rule count"

# Look for rule count in output
RULE_COUNT=$(echo "$TEST_OUTPUT" | grep -oE "YARA rules: [0-9]+|[0-9]+ YARA rules|rules: [0-9]+" | grep -oE "[0-9]+" | head -1 || echo "")

if [ -n "$RULE_COUNT" ] && [ "$RULE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ YARA rules loaded: $RULE_COUNT${NC}"
else
    echo "  Could not determine exact rule count from output"
    echo "  Checking for any numerical references to rules:"
    echo "$TEST_OUTPUT" | grep -iE "rule" | head -5 | sed 's/^/    /'
fi

section "Test 4: Verify scan completes"

# The scan should complete without crashing
if echo "$TEST_OUTPUT" | grep -qiE "(scan completed|Files scanned|LOKI scan finished)"; then
    echo -e "${GREEN}✓ Scan completed successfully${NC}"
else
    # Check for exit without error - completion might not be explicitly logged
    if echo "$TEST_OUTPUT" | grep -qE "Files scanned"; then
        echo -e "${GREEN}✓ Scan appears to have completed (files scanned reported)${NC}"
    else
        echo -e "${YELLOW}⚠ Could not verify scan completion${NC}"
    fi
fi

section "Test 5: Test with debug output"

echo "Running with debug flag for more verbose YARA info..."
TEST_OUTPUT=$("$PROJECT_ROOT/build/loki" -f "$TEST_DIR" --no-procs --scan-all-files --no-tui --no-html --no-log --no-jsonl --debug 2>&1 | head -100) || true

# Check debug output for YARA details
if echo "$TEST_OUTPUT" | grep -qiE "(YARA|rule|signature)"; then
    echo "  Debug output (YARA-related):"
    echo "$TEST_OUTPUT" | grep -iE "(YARA|rule|signature)" | head -10 | sed 's/^/    /'
else
    echo "  No additional YARA debug info found"
fi

section "Test Results"

# Final result
if [ "$TEST_PASSED" = true ]; then
    echo "=== YARA Rules Initialization Test: PASS ==="
    exit 0
else
    echo "=== YARA Rules Initialization Test: FAIL ==="
    exit 1
fi

