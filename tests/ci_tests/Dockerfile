# Stage 1: Build Environment for C/C++ Artifacts
FROM ubuntu:latest AS builder

LABEL stage="builder"

ENV DEBIAN_FRONTEND=noninteractive

# Install build-time dependencies for Hashpipe and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    g++ \
    make && \
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
# Activate the venv by adding its bin directory to the PATH.
ENV VENV_PATH=/opt/venv
RUN python3 -m venv $VENV_PATH
ENV PATH="$VENV_PATH/bin:$PATH"

# Install Python dependencies into a python venv
WORKDIR /app
ARG TEST_DIR="tests/ci_tests"
COPY ${TEST_DIR}/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Build panoseti_daq 
# The compiled .so file will be in the workdir /build/panoseti_daq
WORKDIR /build
COPY . panoseti_daq
# RUN git clone --depth 1 --branch uds-to-grpc https://github.com/panoseti/panoseti_daq.git panoseti_daq
WORKDIR /build/panoseti_daq

# Overwrite the Makefile with our Makefile to define small data buffers
# This is necessary for the github actions CI environments which don't give us storage to work with
COPY "${TEST_DIR}/Makefile-TEST" Makefile
COPY "${TEST_DIR}/databuf-TEST.h" databuf.h

RUN make
RUN make install

# Stage 2: Final Runtime and Test Environment
# This stage creates the small final image.
FROM ubuntu:latest

LABEL stage="runtime"

# Copy compiled artifacts from the builder stage
COPY --from=builder /usr/local/bin/hashpipe /usr/local/bin/
COPY --from=builder /usr/local/lib/libhashpipe.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libhashpipestatus.so* /usr/local/lib/
COPY --from=builder /build/panoseti_daq/hashpipe.so /usr/local/lib/
COPY --from=builder /opt/venv /opt/venv

# Install runtime-only and build-essential dependencies
# build-essential is required for packages that compile C extensions, like netifaces.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tcpreplay \
    python3 \
    python3-venv \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

# Set up the Python Environment 
# Activate the venv by adding its bin directory to the PATH.
ENV VENV_PATH=/opt/venv
RUN python3 -m venv $VENV_PATH
ENV PATH="$VENV_PATH/bin:$PATH"

# Update the shared library cache to ensure the system finds libhashpipe.so
RUN ldconfig
RUN apt-get remove build-essential --autoremove -y

# Copy test data
ARG TEST_DIR="tests/ci_tests"
COPY "${TEST_DIR}/PH_onsky_NGC7331_1pixTrig_Anytrig1.5pe__20250801_102213_965_filtered2.pcapng" /app/test_data.pcapng
COPY ./tests/ /app/tests/
COPY ./util/ /app/util/

# Set a working directory for command execution
WORKDIR /app