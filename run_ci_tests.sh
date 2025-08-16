#!/bin/bash
set -e

# Define the name for the Docker image
IMAGE_NAME="panoseti-daq-ci"

echo "--- Building CI Docker Image: $IMAGE_NAME ---"
docker build -t $IMAGE_NAME -f tests/ci_tests/Dockerfile .

echo "--- Running Integration Tests ---"
# Run the tests inside the container.
# The RUN_REAL_DATA_TESTS=1 environment variable enables the fixture.
# The --rm flag ensures the container is removed after the test run.
docker run --rm \
    --shm-size=2g \
    $IMAGE_NAME \
    python3 -m pytest -v -s --maxfail=2 tests/ci_tests/

echo "--- CI Test Run Completed Successfully ---"
