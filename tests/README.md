# mktorrent Test Suite

This directory contains a comprehensive test suite for mktorrent, designed to verify its functionality and prevent regressions when making code changes.

## Overview

The test suite consists of:

- `test_framework.sh`: Core framework providing common testing functions
- `run_tests.sh`: Main script that runs all test cases
- `torrent_parser.py`: Python script to parse and validate torrent files
- Individual test files: Various test cases covering different aspects of mktorrent

## Running Tests

To run all tests:

```bash
cd tests
./run_tests.sh
```

To run specific test files:

```bash
cd tests
source test_framework.sh
./test_single_file.sh  # Or any other specific test file
print_summary
```

## Available Tests

The test suite includes the following test categories:

1. **Single File Tests** (`test_single_file.sh`)
   - Basic torrent creation with default settings
   - Custom piece length
   - Custom announce URL
   - Private flag

2. **Directory Tests** (`test_directory.sh`)
   - Directory torrent creation with default settings
   - Custom name
   - Comments
   - Multiple announce URLs

3. **Error Cases** (`test_error_cases.sh`)
   - Non-existent files
   - Invalid piece length
   - Missing required parameters
   - Existing output file

4. **Interrupt Handling** (`test_interrupt.sh`)
   - SIGINT handling
   - SIGTERM handling
   - Cleanup of partial files

5. **Performance Tests** (`test_performance.sh`)
   - Tests with different file sizes (small, medium, large)
   - Different thread counts
   - Different piece length settings
   - _Note: These tests are disabled by default. Set `PERFORMANCE_TESTS=1` to enable._

## Configuration

Some tests can be configured with environment variables:

- `PERFORMANCE_TESTS=1`: Enable performance tests
- `PERFORMANCE_LARGE_TESTS=1`: Enable large file tests (200MB+)

## Adding New Tests

To add a new test:

1. Create a new test file named `test_<description>.sh`
2. Source the framework at the top of your file
3. Create test fixtures with `create_test_file` or `create_test_dir`
4. Run tests with `run_test` function
5. Validate results with `validate_torrent` function

Example:
```bash
#!/bin/bash
# Test a new feature

# Create test files
create_test_file "test.dat" 1024

# Run test
run_test "New feature test" \
    "$MKTORRENT -v -o $TEST_RESULTS_DIR/new_feature.torrent $TEST_DATA_DIR/test.dat"

# Validate results
validate_torrent "$TEST_RESULTS_DIR/new_feature.torrent"
```

## Test Framework Functions

- `init_test_env`: Initialize test environment
- `cleanup_test_env`: Clean up test environment
- `create_test_file`: Create a test file of specified size
- `create_test_dir`: Create a directory with multiple test files
- `run_test`: Run a test command and check result
- `validate_torrent`: Validate a torrent file
- `print_summary`: Print test summary 
