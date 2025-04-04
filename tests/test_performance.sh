#!/bin/bash
# Test performance of mktorrent with larger files

# Skip these tests by default to keep the test suite fast
# Set PERFORMANCE_TESTS=1 to run these tests
if [ "${PERFORMANCE_TESTS:-0}" != "1" ]; then
    echo "Skipping performance tests. Set PERFORMANCE_TESTS=1 to run them."
    exit 0
fi

# Create larger test files
echo "Creating larger test files for performance testing..."
create_test_file "perf_small.dat" 10240    # 10MB
create_test_file "perf_medium.dat" 51200   # 50MB

# Only create the large file if explicitly requested
if [ "${PERFORMANCE_LARGE_TESTS:-0}" = "1" ]; then
    create_test_file "perf_large.dat" 204800  # 200MB
fi

# Test with different thread counts (when using pthreads)
# First, check if mktorrent is built with pthread support
if $MKTORRENT --help | grep -q -- "-t"; then
    # Small file, single thread
    echo "Testing with small file (10MB), single thread"
    run_test "Small file, single thread" \
        "time $MKTORRENT -v -t 1 -o $TEST_RESULTS_DIR/perf_small_t1.torrent $TEST_DATA_DIR/perf_small.dat"
    
    # Small file, multiple threads
    echo "Testing with small file (10MB), multiple threads"
    run_test "Small file, multiple threads" \
        "time $MKTORRENT -v -t 4 -o $TEST_RESULTS_DIR/perf_small_t4.torrent $TEST_DATA_DIR/perf_small.dat"
    
    # Medium file, single thread
    echo "Testing with medium file (50MB), single thread"
    run_test "Medium file, single thread" \
        "time $MKTORRENT -v -t 1 -o $TEST_RESULTS_DIR/perf_medium_t1.torrent $TEST_DATA_DIR/perf_medium.dat"
    
    # Medium file, multiple threads
    echo "Testing with medium file (50MB), multiple threads"
    run_test "Medium file, multiple threads" \
        "time $MKTORRENT -v -t 4 -o $TEST_RESULTS_DIR/perf_medium_t4.torrent $TEST_DATA_DIR/perf_medium.dat"
    
    # Large file tests
    if [ "${PERFORMANCE_LARGE_TESTS:-0}" = "1" ]; then
        # Large file, single thread
        echo "Testing with large file (200MB), single thread"
        run_test "Large file, single thread" \
            "time $MKTORRENT -v -t 1 -o $TEST_RESULTS_DIR/perf_large_t1.torrent $TEST_DATA_DIR/perf_large.dat"
        
        # Large file, multiple threads
        echo "Testing with large file (200MB), multiple threads"
        run_test "Large file, multiple threads" \
            "time $MKTORRENT -v -t 4 -o $TEST_RESULTS_DIR/perf_large_t4.torrent $TEST_DATA_DIR/perf_large.dat"
    fi
else
    echo "mktorrent not built with pthread support, skipping thread count tests."
    
    # Just test with different file sizes
    echo "Testing with small file (10MB)"
    run_test "Small file" \
        "time $MKTORRENT -v -o $TEST_RESULTS_DIR/perf_small.torrent $TEST_DATA_DIR/perf_small.dat"
    
    echo "Testing with medium file (50MB)"
    run_test "Medium file" \
        "time $MKTORRENT -v -o $TEST_RESULTS_DIR/perf_medium.torrent $TEST_DATA_DIR/perf_medium.dat"
    
    if [ "${PERFORMANCE_LARGE_TESTS:-0}" = "1" ]; then
        echo "Testing with large file (200MB)"
        run_test "Large file" \
            "time $MKTORRENT -v -o $TEST_RESULTS_DIR/perf_large.torrent $TEST_DATA_DIR/perf_large.dat"
    fi
fi

# Test different piece lengths
echo "Testing different piece lengths with medium file"
run_test "Piece length 16 (64KB)" \
    "$MKTORRENT -v -l 16 -o $TEST_RESULTS_DIR/perf_medium_l16.torrent $TEST_DATA_DIR/perf_medium.dat"

run_test "Piece length 18 (256KB)" \
    "$MKTORRENT -v -l 18 -o $TEST_RESULTS_DIR/perf_medium_l18.torrent $TEST_DATA_DIR/perf_medium.dat"

run_test "Piece length 20 (1MB)" \
    "$MKTORRENT -v -l 20 -o $TEST_RESULTS_DIR/perf_medium_l20.torrent $TEST_DATA_DIR/perf_medium.dat"

run_test "Piece length 22 (4MB)" \
    "$MKTORRENT -v -l 22 -o $TEST_RESULTS_DIR/perf_medium_l22.torrent $TEST_DATA_DIR/perf_medium.dat" 
