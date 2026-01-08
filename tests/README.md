# Loki-RS Test Suite

This directory contains comprehensive tests for Loki-RS, a high-performance, multi-threaded YARA & IOC scanner.

## IMPORTANT: Test Safety

**All tests MUST be scoped to a specific folder using `-f <folder>`** to prevent accidentally scanning the entire filesystem. The `run_loki` helper function enforces this requirement and will fail if `-f` is not provided.

Safe commands that don't require `-f`:
- `--help` / `-h` - Shows help and exits
- `--version` - Shows version and exits

Use `run_loki_info` for these safe commands.

## Test Structure

```
tests/
├── README.md                       # This file
├── run_all_tests.sh               # Main test runner with verbose output
├── lib/
│   └── test_helpers.sh            # Common functions (setup, teardown, assertions)
├── basic_functionality/           # Basic functionality tests
│   ├── test_binary_existence.sh   # Verify binaries exist and are executable
│   ├── test_help_output.sh        # Verify help output
│   └── test_version_output.sh     # Verify version output
├── scanning_tests/                # Filesystem scanning tests
│   └── test_simple_scan.sh        # Basic scan functionality
├── detection_tests/               # Detection and matching tests
│   ├── test_filename_ioc.sh       # Filename IOC pattern matching
│   ├── test_yara_rule.sh          # YARA rule detection
│   ├── test_exclusions.sh         # Exclusion pattern testing
│   └── test_file_type_filter.sh   # File type filtering (--scan-all-files)
├── configuration_tests/           # Configuration and initialization tests
│   ├── test_exclusion_count.sh    # Exclusion count validation
│   └── test_yara_init.sh          # YARA rules initialization
└── error_handling_tests/          # Error condition tests
    └── test_invalid_input.sh      # Invalid input handling
```

## Running Tests

### Prerequisites

Before running tests, ensure the build package is ready:

```bash
# Build and package Loki-RS
make package
```

This creates the `build/` directory with:
- `loki` binary
- `loki-util` binary
- `signatures/` directory with YARA rules and IOCs
- `config/` directory with configuration files

### Run All Tests

```bash
./tests/run_all_tests.sh
```

### Run Specific Tests

```bash
# Run a specific test
./tests/basic_functionality/test_binary_existence.sh

# Run all tests in a category
for test in tests/detection_tests/*.sh; do 
    echo "Running $test"
    bash "$test"
done
```

## Test Categories

### 1. Basic Functionality Tests
Tests for core command-line functionality:
- Binary existence and executability
- Help output (`--help`)
- Version output (`--version`)

### 2. Scanning Tests
Tests for filesystem scanning:
- Basic directory scanning
- Scan completion and statistics

### 3. Detection Tests
Tests for detection capabilities:
- **Filename IOC**: Matches files based on filename patterns
- **YARA Rule**: Matches files based on YARA rule patterns
- **Exclusions**: Verifies exclusion patterns skip matching files
- **File Type Filter**: Tests `--scan-all-files` behavior

### 4. Configuration Tests
Tests for configuration and initialization:
- **Exclusion Count**: Verifies exclusion count reporting
- **YARA Init**: Verifies YARA rules load without errors

### 5. Error Handling Tests
Tests for error conditions:
- Non-existent directories
- Invalid command-line options
- Missing arguments

## Test Helper Library

The `lib/test_helpers.sh` provides common functions:

```bash
# Source the helper library
source "./tests/lib/test_helpers.sh"

# Setup temporary directory
setup_temp_dir
register_cleanup  # Auto-cleanup on exit

# Run Loki with common test flags (MUST include -f flag!)
run_loki -f "$TEST_TEMP_DIR" --no-procs --scan-all-files

# For safe info commands only (--help, --version)
run_loki_info --help
run_loki_info --version

# Assertions
assert_contains "expected string" "Optional message"
assert_not_contains "unexpected string" "Optional message"
assert_exit_code 0 $? "Command should succeed"
assert_file_exists "/path/to/file"

# Finish test and return appropriate exit code
finish_test
```

## Test Output

Tests provide verbose output including:
- Clear PASS/FAIL indicators with colors
- Expected vs actual values on failure
- Captured command output for debugging
- Test duration

Example output:
```
=== Running All Loki-RS Tests ===

----------------------------------------
Running: Binary Existence Test
Script: ./tests/basic_functionality/test_binary_existence.sh

✓ loki binary: PASS (exists and executable)
✓ loki-util binary: PASS (exists and executable)
=== Binary Existence Test: PASS ===

✓ Binary Existence Test: PASS (0s)
```

## CI/CD Integration

Tests are automatically run in GitHub Actions:

- **On push/PR to master**: `.github/workflows/test.yml`
- **Before releases**: `.github/workflows/release.yml` (tests must pass before build)

## Writing New Tests

1. Create a new test file in the appropriate category directory
2. Use the naming convention: `test_<description>.sh`
3. Source the helper library for common functions
4. Use `set -euo pipefail` for strict error handling
5. Provide clear output with PASS/FAIL indicators
6. Return exit code 0 on success, 1 on failure

Example template:
```bash
#!/bin/bash

# Test: My New Test
# Description: What this test verifies
# Expected: What should happen

set -euo pipefail

echo "=== Testing My Feature ==="

# Source helper library
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

# Setup
setup_temp_dir
register_cleanup

PROJECT_ROOT=$(get_project_root)
cd "$PROJECT_ROOT"

# Test logic here - ALWAYS use -f to scope the scan!
run_loki -f "$TEST_TEMP_DIR" --no-procs

# Assertions
assert_contains "expected output"

# Result
if [ "$TEST_PASSED" = true ]; then
    echo "=== My Feature Test: PASS ==="
    exit 0
else
    echo "=== My Feature Test: FAIL ==="
    exit 1
fi
```
