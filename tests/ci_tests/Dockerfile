# Stage 1: Build Environment for C/C++ Artifacts
FROM python:3.14-slim AS builder

LABEL stage="builder"
ENV DEBIAN_FRONTEND=noninteractive

# Install build-time dependencies (Python 3.14 is natively included in the base image)
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

# Build and install Hashpipe
WORKDIR /build
RUN git clone --depth 1 https://github.com/david-macmahon/hashpipe.git hashpipe
WORKDIR /build/hashpipe/src
RUN autoreconf -is && \
    ./configure --prefix=/usr/local && \
    make && \
    make install

# Set up the Python Environment
ENV VENV_PATH=/opt/venv
RUN python -m venv $VENV_PATH
ENV PATH="$VENV_PATH/bin:$PATH"

# Install Python dependencies first to maximize layer caching
WORKDIR /app
ARG TEST_DIR="tests/ci_tests"
COPY ${TEST_DIR}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Build panoseti_daq 
WORKDIR /build
# Fixed syntax: Copy current directory into panoseti_daq
COPY . panoseti_daq
WORKDIR /build/panoseti_daq

# Overwrite the Makefile with our Makefile to define small data buffers
COPY "${TEST_DIR}/Makefile-TEST" Makefile
COPY "${TEST_DIR}/databuf-TEST.h" databuf.h

# Combine build steps to save layers
RUN make && make install

# Build and run unit tests (fail the Docker build if any test fails)
# 'make clean' is required because COPY above may bring in a locally-compiled
# macOS binary; we must recompile for the Linux container architecture.
WORKDIR /build/panoseti_daq/tests/unit
RUN make clean && make && ./panoseti_unit_tests --reporter compact

# ==========================================
# Stage 2: Final Runtime and Test Environment
# ==========================================
FROM python:3.14-slim

LABEL stage="runtime"
ENV DEBIAN_FRONTEND=noninteractive

# Install ONLY runtime-critical dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tcpreplay && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled artifacts from the builder stage
COPY --from=builder /usr/local/bin/hashpipe /usr/local/bin/
COPY --from=builder /usr/local/lib/libhashpipe.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libhashpipestatus.so* /usr/local/lib/
COPY --from=builder /build/panoseti_daq/hashpipe.so /usr/local/lib/

# Copy the fully populated Python virtual environment
COPY --from=builder /opt/venv /opt/venv

# Activate the venv
ENV VENV_PATH=/opt/venv
ENV PATH="$VENV_PATH/bin:$PATH"

# Update the shared library cache to ensure the system finds libhashpipe.so
RUN ldconfig

# Copy test data and necessary directories
ARG TEST_DIR="tests/ci_tests"
COPY "${TEST_DIR}/PH_onsky_NGC7331_1pixTrig_Anytrig1.5pe__20250801_102213_965_filtered2.pcapng" /app/test_data.pcapng
COPY ./tests/ /app/tests/
COPY ./util/ /app/util/

# Set a working directory for command execution
WORKDIR /app