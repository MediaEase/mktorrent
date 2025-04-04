#!/bin/bash
# Test error cases in mktorrent

# Create a test file for the tests that need an existing file
create_test_file "single_file_test.dat" 1024   # 1MB test file

# Test non-existent file
echo "Testing torrent creation with non-existent file"
run_test "Non-existent file" \
    "$MKTORRENT -v -o $TEST_RESULTS_DIR/error_nonexistent.torrent $TEST_DATA_DIR/nonexistent_file.dat" 1

# Test invalid piece length
echo "Testing torrent creation with invalid piece length"
run_test "Invalid piece length" \
    "$MKTORRENT -v -l 5 -o $TEST_RESULTS_DIR/error_piece_length.torrent $TEST_DATA_DIR/single_file_test.dat" 1

# Test with no output file specified
echo "Testing torrent creation with no output file"
run_test "No output file" \
    "$MKTORRENT -v $TEST_DATA_DIR/single_file_test.dat" 1

# Test with invalid announce URL
echo "Testing torrent creation with invalid announce URL"
run_test "Invalid announce URL" \
    "$MKTORRENT -v -a invalid-url -o $TEST_RESULTS_DIR/error_announce.torrent $TEST_DATA_DIR/single_file_test.dat" 1

# Test duplicate output file without force option
# First, create a dummy output file
touch "$TEST_RESULTS_DIR/existing.torrent"

echo "Testing torrent creation with existing output file without force option"
run_test "Existing output file without force" \
    "$MKTORRENT -v -a http://example.com/announce -o $TEST_RESULTS_DIR/existing.torrent $TEST_DATA_DIR/single_file_test.dat" 1

# Test duplicate output file with force option
echo "Testing torrent creation with existing output file with force option"
run_test "Existing output file with force" \
    "$MKTORRENT -v -a http://example.com/announce -f -o $TEST_RESULTS_DIR/existing.torrent $TEST_DATA_DIR/single_file_test.dat" 0

# Validate the torrent file (this one should exist)
validate_torrent "$TEST_RESULTS_DIR/existing.torrent" 
