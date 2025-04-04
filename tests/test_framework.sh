#!/bin/bash
# Test framework for mktorrent
# This script provides the common functions used by all tests

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Path to mktorrent executable
MKTORRENT="$(realpath ../build/mktorrent)"

# Test data directory
TEST_DATA_DIR="$(realpath ./test_data)"

# Test results directory
TEST_RESULTS_DIR="$(realpath ./test_results)"

# Number of tests and failed tests
TOTAL_TESTS=0
FAILED_TESTS=0
PASSED_TESTS=0

# Initialize test environment
init_test_env() {
    echo -e "${YELLOW}Initializing test environment...${NC}"
    
    # Create test directories if they don't exist
    mkdir -p "$TEST_DATA_DIR"
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Check if mktorrent exists
    if [ ! -f "$MKTORRENT" ]; then
        echo -e "${RED}Error: mktorrent executable not found at $MKTORRENT${NC}"
        echo "Make sure you've built the project before running tests."
        exit 1
    fi
    
    echo -e "${GREEN}Test environment initialized.${NC}"
    echo "Test data directory: $TEST_DATA_DIR"
    echo "Test results directory: $TEST_RESULTS_DIR"
    echo "mktorrent executable: $MKTORRENT"
    echo
}

# Clean up test environment
cleanup_test_env() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    
    # Keep test data but remove results
    if [ -d "$TEST_RESULTS_DIR" ]; then
        rm -rf "$TEST_RESULTS_DIR"/*
    fi
    
    echo -e "${GREEN}Test environment cleaned up.${NC}"
    echo
}

# Create a test file of specified size (in KB)
create_test_file() {
    local filename="$1"
    local size_kb="$2"
    
    dd if=/dev/urandom of="$TEST_DATA_DIR/$filename" bs=1K count="$size_kb" 2>/dev/null
    echo "Created test file: $filename ($size_kb KB)"
}

# Create a directory with multiple test files
create_test_dir() {
    local dirname="$1"
    shift
    
    mkdir -p "$TEST_DATA_DIR/$dirname"
    
    # Process remaining args as filename:size_kb pairs
    while [ "$#" -gt 0 ]; do
        local file_info="$1"
        local filename="${file_info%%:*}"
        local size_kb="${file_info##*:}"
        
        dd if=/dev/urandom of="$TEST_DATA_DIR/$dirname/$filename" bs=1K count="$size_kb" 2>/dev/null
        echo "Created test file: $dirname/$filename ($size_kb KB)"
        
        shift
    done
}

# Run a test and check the result
run_test() {
    local test_name="$1"
    local cmd="$2"
    local expected_exit_code="${3:-0}"  # Default expected exit code is 0
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${YELLOW}Running test: ${test_name}${NC}"
    echo "Command: $cmd"
    
    # Run the command and capture output and exit code
    local output
    output=$(eval "$cmd" 2>&1)
    local exit_code=$?
    
    # Check if exit code matches expected exit code
    if [ "$exit_code" -eq "$expected_exit_code" ]; then
        echo -e "${GREEN}Test passed: ${test_name}${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}Test failed: ${test_name}${NC}"
        echo -e "${RED}Expected exit code: ${expected_exit_code}, got: ${exit_code}${NC}"
        echo -e "${RED}Output:${NC}"
        echo "$output"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo
}

# Validate a torrent file exists and has expected properties
validate_torrent() {
    local torrent_file="$1"
    local expected_piece_length="${2:-0}"  # Default is 0 (auto)
    local expected_file_count="${3:-1}"    # Default is 1 file
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -e "${YELLOW}Validating torrent: ${torrent_file}${NC}"
    
    # Check if torrent file exists
    if [ ! -f "$torrent_file" ]; then
        echo -e "${RED}Test failed: Torrent file not found: ${torrent_file}${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Call our Python parser to validate the torrent file
    local parser_script="$(dirname "$0")/torrent_parser.py"
    
    # Make the script executable if it isn't already
    chmod +x "$parser_script" 2>/dev/null
    
    # Run the validation
    local output
    output=$("$parser_script" "$torrent_file" --validate --json 2>&1)
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Test failed: Torrent validation failed: ${output}${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Extract and check file count if this is a directory torrent
    if [ "$expected_file_count" -gt 1 ]; then
        local file_count
        file_count=$(echo "$output" | grep -o '"file_count": [0-9]*' | grep -o '[0-9]*')
        
        if [ -z "$file_count" ] || [ "$file_count" -ne "$expected_file_count" ]; then
            echo -e "${RED}Test failed: Expected $expected_file_count files, but found ${file_count:-unknown}${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    fi
    
    # Check piece length if specified
    if [ "$expected_piece_length" -ne 0 ]; then
        local piece_length
        piece_length=$(echo "$output" | grep -o '"piece_length": [0-9]*' | grep -o '[0-9]*')
        
        # Calculate expected piece length in bytes (2^expected_piece_length)
        local expected_bytes=$((1 << expected_piece_length))
        
        if [ -z "$piece_length" ] || [ "$piece_length" -ne "$expected_bytes" ]; then
            echo -e "${RED}Test failed: Expected piece length $expected_bytes bytes, but found ${piece_length:-unknown}${NC}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            return 1
        fi
    fi
    
    echo -e "${GREEN}Torrent validation passed: ${torrent_file}${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo
    
    return 0
}

# Print test summary
print_summary() {
    echo -e "${YELLOW}Test Summary:${NC}"
    echo "Total tests: $TOTAL_TESTS"
    echo -e "${GREEN}Passed tests: $PASSED_TESTS${NC}"
    
    if [ "$FAILED_TESTS" -gt 0 ]; then
        echo -e "${RED}Failed tests: $FAILED_TESTS${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
} 
