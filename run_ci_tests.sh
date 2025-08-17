#!/bin/bash

set -e

# Define the name for the Docker image
IMAGE_NAME="panoseti-daq"

echo "--- Building CI Docker Image: $IMAGE_NAME ---"
docker build -t $IMAGE_NAME -f tests/ci_tests/Dockerfile .

echo "--- Running Integration Tests ---"

# Run basic functionality tests first (these are most likely to pass)
echo "=== Running Basic Functionality Tests ==="
docker run --rm --shm-size=2g $IMAGE_NAME \
    python3 -m pytest -s -v --maxfail=1 tests/ci_tests/test_can_hashpipe_init.py

# Run UDS resilience tests (test framework robustness)
echo "=== Running UDS Resilience Tests ==="
docker run --rm --shm-size=2g $IMAGE_NAME \
    python3 -m pytest -s -v --maxfail=1 tests/ci_tests/test_uds_resilience.py

# Run UDS data path tests (test data integrity)
echo "=== Running UDS Data Path Tests ==="
docker run --rm --shm-size=2g $IMAGE_NAME \
    python3 -m pytest -s -v --maxfail=1 tests/ci_tests/test_uds_data_path.py

# Run PFF header consistency tests with longer timeout (filesystem-dependent)
echo "=== Running PFF Header Consistency Tests ==="
docker run --rm --shm-size=2g $IMAGE_NAME \
    python3 -m pytest -s -v --maxfail=1 --timeout=180 tests/ci_tests/test_pff_header_consistency.py

echo "--- CI Test Run Completed Successfully ---"
