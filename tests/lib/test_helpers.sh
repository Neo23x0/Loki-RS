#!/bin/bash

# Test Helpers Library
# Common functions for Loki-RS test suite
# 
# IMPORTANT: All scans MUST be scoped to a specific folder to prevent
# accidentally scanning the entire filesystem.

# Colors
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export NC='\033[0m' # No Color

# Global test state
TEST_TEMP_DIR=""
TEST_PASSED=true
TEST_OUTPUT=""

# Determine project root
get_project_root() {
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    echo "$(cd "$script_dir/../.." && pwd)"
}

# Setup a temporary directory for tests
# Usage: setup_temp_dir
# Returns: Sets TEST_TEMP_DIR to the path
setup_temp_dir() {
    TEST_TEMP_DIR=$(mktemp -d -t loki_test_XXXXXX)
    echo "Created temp directory: $TEST_TEMP_DIR"
    export TEST_TEMP_DIR
}

# Cleanup temporary directory
# Usage: teardown_temp_dir
teardown_temp_dir() {
    if [ -n "$TEST_TEMP_DIR" ] && [ -d "$TEST_TEMP_DIR" ]; then
        rm -rf "$TEST_TEMP_DIR"
        echo "Cleaned up temp directory: $TEST_TEMP_DIR"
    fi
    TEST_TEMP_DIR=""
}

# Register cleanup on exit
register_cleanup() {
    trap teardown_temp_dir EXIT
}

# Run loki with common test flags
# IMPORTANT: This function REQUIRES a -f flag to be passed to prevent full system scans
# Usage: run_loki -f "$TEST_DIR" [other args...]
# Returns: Sets TEST_OUTPUT and returns exit code
run_loki() {
    local project_root=$(get_project_root)
    
    # Safety check: Ensure -f flag is present to prevent full system scans
    local has_folder_flag=false
    for arg in "$@"; do
        if [ "$arg" = "-f" ] || [ "$arg" = "--folder" ]; then
            has_folder_flag=true
            break
        fi
    done
    
    if [ "$has_folder_flag" = false ]; then
        echo -e "${RED}ERROR: run_loki MUST include -f <folder> to prevent full system scans${NC}" >&2
        echo "Usage: run_loki -f \"\$TEST_TEMP_DIR\" [other args...]" >&2
        TEST_OUTPUT="ERROR: Missing -f flag"
        return 1
    fi
    
    TEST_OUTPUT=$("$project_root/build/loki" --no-tui --no-html --no-log --no-jsonl "$@" 2>&1) || return $?
    return 0
}

# Run loki for info/help commands only (no scanning)
# Usage: run_loki_info --help | --version
# Returns: Sets TEST_OUTPUT and returns exit code
run_loki_info() {
    local project_root=$(get_project_root)
    
    # Safety check: Only allow info commands that don't trigger scanning
    local is_safe=false
    for arg in "$@"; do
        if [ "$arg" = "--help" ] || [ "$arg" = "-h" ] || [ "$arg" = "--version" ]; then
            is_safe=true
            break
        fi
    done
    
    if [ "$is_safe" = false ]; then
        echo -e "${RED}ERROR: run_loki_info only allows --help or --version${NC}" >&2
        echo "For scanning, use: run_loki -f \"\$TEST_TEMP_DIR\" [args...]" >&2
        TEST_OUTPUT="ERROR: Invalid command for run_loki_info"
        return 1
    fi
    
    TEST_OUTPUT=$("$project_root/build/loki" "$@" 2>&1) || return $?
    return 0
}

# Run loki-util
# Usage: run_loki_util [args...]
run_loki_util() {
    local project_root=$(get_project_root)
    TEST_OUTPUT=$("$project_root/build/loki-util" "$@" 2>&1) || return $?
    return 0
}

# Assert that output contains a string
# Usage: assert_contains "expected string" ["error message"]
assert_contains() {
    local expected="$1"
    local message="${2:-Output should contain '$expected'}"
    
    if echo "$TEST_OUTPUT" | grep -qE "$expected"; then
        echo -e "${GREEN}✓ PASS:${NC} $message"
        return 0
    else
        echo -e "${RED}✗ FAIL:${NC} $message"
        echo "  Expected to find: $expected"
        echo "  Actual output:"
        echo "$TEST_OUTPUT" | head -30 | sed 's/^/    /'
        if [ $(echo "$TEST_OUTPUT" | wc -l) -gt 30 ]; then
            echo "    ... (output truncated)"
        fi
        TEST_PASSED=false
        return 1
    fi
}

# Assert that output does NOT contain a string
# Usage: assert_not_contains "unexpected string" ["error message"]
assert_not_contains() {
    local unexpected="$1"
    local message="${2:-Output should not contain '$unexpected'}"
    
    if ! echo "$TEST_OUTPUT" | grep -qE "$unexpected"; then
        echo -e "${GREEN}✓ PASS:${NC} $message"
        return 0
    else
        echo -e "${RED}✗ FAIL:${NC} $message"
        echo "  Should NOT contain: $unexpected"
        echo "  But found in output:"
        echo "$TEST_OUTPUT" | grep -E "$unexpected" | head -5 | sed 's/^/    /'
        TEST_PASSED=false
        return 1
    fi
}

# Assert exit code
# Usage: assert_exit_code expected_code actual_code ["error message"]
assert_exit_code() {
    local expected=$1
    local actual=$2
    local message="${3:-Exit code should be $expected}"
    
    if [ "$actual" -eq "$expected" ]; then
        echo -e "${GREEN}✓ PASS:${NC} $message"
        return 0
    else
        echo -e "${RED}✗ FAIL:${NC} $message"
        echo "  Expected exit code: $expected"
        echo "  Actual exit code: $actual"
        TEST_PASSED=false
        return 1
    fi
}

# Assert that a file exists
# Usage: assert_file_exists "path" ["error message"]
assert_file_exists() {
    local filepath="$1"
    local message="${2:-File should exist: $filepath}"
    
    if [ -f "$filepath" ]; then
        echo -e "${GREEN}✓ PASS:${NC} $message"
        return 0
    else
        echo -e "${RED}✗ FAIL:${NC} $message"
        echo "  File does not exist: $filepath"
        TEST_PASSED=false
        return 1
    fi
}

# Assert that a file does NOT exist
# Usage: assert_file_not_exists "path" ["error message"]
assert_file_not_exists() {
    local filepath="$1"
    local message="${2:-File should not exist: $filepath}"
    
    if [ ! -f "$filepath" ]; then
        echo -e "${GREEN}✓ PASS:${NC} $message"
        return 0
    else
        echo -e "${RED}✗ FAIL:${NC} $message"
        echo "  File unexpectedly exists: $filepath"
        TEST_PASSED=false
        return 1
    fi
}

# Create a test file with specific content
# Usage: create_test_file "filename" "content"
create_test_file() {
    local filename="$1"
    local content="$2"
    local filepath="$TEST_TEMP_DIR/$filename"
    
    echo "$content" > "$filepath"
    echo "Created test file: $filepath"
    echo "$filepath"
}

# Create a custom YARA rule for testing
# Usage: create_test_yara_rule "rule_name" "string_to_match" "score"
# Returns: Path to the created rule file
create_test_yara_rule() {
    local rule_name="$1"
    local match_string="$2"
    local score="${3:-80}"
    local rule_file="$TEST_TEMP_DIR/${rule_name}.yar"
    
    cat > "$rule_file" << EOF
rule $rule_name {
    meta:
        description = "Test rule for $rule_name"
        score = $score
    strings:
        \$test_string = "$match_string" ascii
    condition:
        \$test_string
}
EOF
    
    echo "Created YARA rule: $rule_file"
    echo "$rule_file"
}

# Create a custom filename IOC for testing
# Usage: create_test_filename_ioc "pattern" "score"
# Returns: Path to the IOC file
create_test_filename_ioc() {
    local pattern="$1"
    local score="${2:-80}"
    local ioc_file="$TEST_TEMP_DIR/test-filename-iocs.txt"
    
    cat > "$ioc_file" << EOF
# Test Filename IOC
$pattern;$score
EOF
    
    echo "Created filename IOC: $ioc_file"
    echo "$ioc_file"
}

# Backup a file before modifying
# Usage: backup_file "filepath"
backup_file() {
    local filepath="$1"
    if [ -f "$filepath" ]; then
        cp "$filepath" "${filepath}.test_backup"
        echo "Backed up: $filepath"
    fi
}

# Restore a backed up file
# Usage: restore_file "filepath"
restore_file() {
    local filepath="$1"
    if [ -f "${filepath}.test_backup" ]; then
        mv "${filepath}.test_backup" "$filepath"
        echo "Restored: $filepath"
    fi
}

# Check if test passed and return appropriate exit code
# Usage: finish_test
finish_test() {
    if [ "$TEST_PASSED" = true ]; then
        return 0
    else
        return 1
    fi
}

# Print a section header
# Usage: section "Section Name"
section() {
    echo ""
    echo -e "${BLUE}--- $1 ---${NC}"
    echo ""
}
