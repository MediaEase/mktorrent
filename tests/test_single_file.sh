#!/bin/bash
# Test creating a torrent from a single file

# Create test files
create_test_file "single_file_test.dat" 1024   # 1MB test file

# Run tests
echo "Testing single file torrent creation with default settings"
run_test "Default settings" \
    "$MKTORRENT -v -a http://example.com/announce -o $TEST_RESULTS_DIR/single_default.torrent $TEST_DATA_DIR/single_file_test.dat"

# Validate the torrent file
validate_torrent "$TEST_RESULTS_DIR/single_default.torrent"

# Test piece length option
echo "Testing single file torrent creation with custom piece length"
run_test "Custom piece length" \
    "$MKTORRENT -v -a http://example.com/announce -l 18 -o $TEST_RESULTS_DIR/single_piece_length.torrent $TEST_DATA_DIR/single_file_test.dat"

# Validate the torrent file
validate_torrent "$TEST_RESULTS_DIR/single_piece_length.torrent" 18

# Test announce URL option
echo "Testing single file torrent creation with custom announce URL"
run_test "Custom announce URL" \
    "$MKTORRENT -v -a http://example.com/announce -o $TEST_RESULTS_DIR/single_announce.torrent $TEST_DATA_DIR/single_file_test.dat"

# Validate the torrent file
validate_torrent "$TEST_RESULTS_DIR/single_announce.torrent"

# Test private flag
echo "Testing single file torrent creation with private flag"
run_test "Private flag" \
    "$MKTORRENT -v -a http://example.com/announce -p -o $TEST_RESULTS_DIR/single_private.torrent $TEST_DATA_DIR/single_file_test.dat"

# Validate the torrent file
validate_torrent "$TEST_RESULTS_DIR/single_private.torrent" 
