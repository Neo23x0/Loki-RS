# Loki-RS Beta Test Suite

This directory contains comprehensive beta tests for Loki-RS, a high-performance, multi-threaded YARA & IOC scanner.

## Test Structure

```
tests/
├── README.md                  # This file
├── basic_functionality/       # Basic functionality tests
├── signature_management/      # Signature update and management tests
├── scanning_tests/            # Filesystem and process scanning tests
├── performance_tests/         # Performance and resource usage tests
├── output_logging/            # Output format and logging tests
├── error_handling/            # Error condition tests
└── regression_tests/          # Regression and edge case tests
```

## Running Tests

Each test directory contains shell scripts that can be executed individually:

```bash
# Run a specific test
./tests/basic_functionality/test_help_output.sh

# Run all tests in a category
for test in tests/basic_functionality/*.sh; do echo "Running $test"; $test; done
```

## Test Categories

### 1. Basic Functionality Tests
Tests for core command-line functionality, help output, and version information.

### 2. Signature Management Tests
Tests for signature updates, loading, and validation.

### 3. Scanning Tests
Tests for filesystem scanning, file filtering, and exclusion patterns.

### 4. Performance Tests
Tests for resource usage, threading, and performance characteristics.

### 5. Output and Logging Tests
Tests for different output formats and logging levels.

### 6. Error Handling Tests
Tests for error conditions and edge cases.

### 7. Regression Tests
Tests for previously reported issues and edge cases.

## Test Results

Each test script should:
- Return exit code 0 on success
- Return exit code 1 on failure
- Output clear pass/fail messages
- Include any relevant diagnostic information

## Requirements

- Loki-RS binaries must be built and available in `./build/`
- Test scripts assume execution from project root directory
- Some tests may require specific test files or directories
