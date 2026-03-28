# ─── Stage 1: base ────────────────────────────────────────────────────────────
# Shared Python venv with all test dependencies installed.
# Requirements layer is cached independently of source changes.
# gcc is required to build the netifaces C extension; it is installed here
# temporarily and the apt cache is cleared afterward.
FROM python:3.14-slim AS base

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

ARG TEST_DIR="tests/ci_tests"
COPY ${TEST_DIR}/requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ─── Stage 2: hashpipe-builder ────────────────────────────────────────────────
# Builds the Hashpipe framework (hashpipe binary + shared libs).
# Reusable across build variants; cached unless Hashpipe source changes.
FROM base AS hashpipe-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    catch2 \
    pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 https://github.com/david-macmahon/hashpipe.git hashpipe
WORKDIR /build/hashpipe/src
RUN autoreconf -is && \
    ./configure --prefix=/usr/local && \
    make && \
    make install

# ─── Stage 3: daq-plugin-builder ──────────────────────────────────────────────
# Compiles hashpipe.so and runs unit tests.
# A unit test failure fails the build here, before the integration test stage.
FROM hashpipe-builder AS daq-plugin-builder

ARG TEST_DIR="tests/ci_tests"

WORKDIR /build
COPY . panoseti_daq
WORKDIR /build/panoseti_daq

# Override Makefile and databuf.h for the CI test build
COPY "${TEST_DIR}/Makefile-TEST" Makefile
COPY "${TEST_DIR}/databuf-TEST.h" databuf.h

# Compile the Hashpipe plugin
RUN make && make install

# Compile and run unit tests.
# 'make clean' is required: COPY above may bring in a locally-compiled macOS
# binary from the developer's machine; we must recompile for Linux/AMD64.
WORKDIR /build/panoseti_daq/tests/unit
RUN make clean && make && ./panoseti_unit_tests --reporter compact

# ─── Stage 4: daq-ssh-test ────────────────────────────────────────────────────
# Minimal integration-test runtime — no build tools, only what's needed to run
# pytest against a live Hashpipe subprocess via tcpreplay.
FROM python:3.14-slim AS daq-ssh-test

LABEL stage="daq-ssh-test"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tcpreplay && \
    rm -rf /var/lib/apt/lists/*

# Hashpipe binary and shared libraries from the builder stage
COPY --from=hashpipe-builder /usr/local/bin/hashpipe /usr/local/bin/
COPY --from=hashpipe-builder /usr/local/lib/libhashpipe.so* /usr/local/lib/
COPY --from=hashpipe-builder /usr/local/lib/libhashpipestatus.so* /usr/local/lib/

# The compiled DAQ Hashpipe plugin
COPY --from=daq-plugin-builder /build/panoseti_daq/hashpipe.so /usr/local/lib/

# Python venv (fully populated in stage 1)
COPY --from=base /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Update shared library cache
RUN ldconfig

# Test data and CI test files
ARG TEST_DIR="tests/ci_tests"
COPY "${TEST_DIR}/PH_onsky_NGC7331_1pixTrig_Anytrig1.5pe__20250801_102213_965_filtered2.pcapng" /app/test_data.pcapng
COPY ./tests/ /app/tests/
COPY ./util/ /app/util/

WORKDIR /app
