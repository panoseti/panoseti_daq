#!/usr/bin/env bash
set -euo pipefail

# ─── Local fast check (no Docker) ────────────────────────────────────────────
echo "=== Running unit tests locally ==="
cd tests/unit && make clean && make && ./panoseti_unit_tests --reporter compact
cd ../..

# ─── Build all stages ────────────────────────────────────────────────────────
# The daq-plugin-builder stage compiles hashpipe.so AND runs unit tests inside
# the Linux container.  A unit test failure aborts the build here.
echo "=== Building CI image (unit tests run inside builder stage) ==="
docker build --target daq-plugin-builder -t panoseti-daq-builder \
    -f tests/ci_tests/Dockerfile .

# ─── Integration tests via docker-compose ────────────────────────────────────
# All test suites run in a single pytest session (one Hashpipe process),
# which is faster than the previous serial docker-run loop.
echo "=== Running integration tests ==="
docker compose -f tests/ci_tests/docker-compose.test.yml build
docker compose -f tests/ci_tests/docker-compose.test.yml up \
    --exit-code-from test_runner \
    --abort-on-container-exit

# ─── Cleanup ─────────────────────────────────────────────────────────────────
echo "=== Cleaning up ==="
docker compose -f tests/ci_tests/docker-compose.test.yml down

echo "--- CI completed successfully ---"
