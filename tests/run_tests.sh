#!/bin/bash
# Main test runner for mktorrent

# Source the test framework
source "$(dirname "$0")/test_framework.sh"

# Create and set up test directories
init_test_env

# Clean up previous test results
cleanup_test_env

# Check if a specific test file was provided
if [ $# -eq 1 ]; then
    # Run only the specified test
    test_file="$(dirname "$0")/$1"
    if [ -f "$test_file" ]; then
        echo -e "${YELLOW}Running test file: $(basename "$test_file")${NC}"
        echo "========================================================="
        source "$test_file"
        echo "========================================================="
        echo
    else
        echo -e "${RED}Test file not found: $1${NC}"
        exit 1
    fi
else
    # Run all test files
    for test_file in $(dirname "$0")/test_*.sh; do
        # Skip the test framework and the test runner
        if [[ "$test_file" != *"test_framework.sh"* && "$test_file" != *"run_tests.sh"* ]]; then
            echo -e "${YELLOW}Running test file: $(basename "$test_file")${NC}"
            echo "========================================================="
            source "$test_file"
            echo "========================================================="
            echo
        fi
    done
fi

# Print test summary
print_summary 
