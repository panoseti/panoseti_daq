# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Role in the PANOSETI Observatory

This repo (`panoseti_daq_ssh`) is the **critical real-time data acquisition software** that runs on each **DAQ node** during an observing session. It is the fastest, most performance-sensitive component in the entire observatory software stack — responsible for capturing every UDP science packet from the telescope's quabo detector boards and writing them to disk with zero loss.

### Observatory hardware context

A PANOSETI observatory consists of:
- A **head node** — the control computer where scientists run `session_start.py`, `start.py`, etc. (managed in `panoseti-software/control/`)
- One or more **DAQ nodes** — dedicated Linux machines (like `panoseti-gattini`) that run this Hashpipe software
- **Modules** — each has a mobo board + 1–4 **quabos** (quadrant boards, 256-pixel SiPM detector arrays)

Each **module** has 4 quabos with consecutive IPs. Module ID (0–255) is bits 2–9 of the base IP address:
```
module_id = (ip_octet3 * 256 + ip_octet4) >> 2 & 0xFF
```
Each quabo has `BOARDLOC = module_id * 4 + quadrant_index (0–3)`.

Science packets flow from quabos → DAQ nodes on **UDP port 60001**. The head node receives housekeeping packets on port 60002, not science data. Each DAQ node's set of modules is defined in `daq_config.json`.

### Where this fits in the full stack

```
Quabos (UDP science packets on port 60001)
    │
    ▼
DAQ Node running Hashpipe (THIS REPO)
    │   net_thread → compute_thread → output_thread
    │   Writes PFF files to disk
    │
    ├──► Unix Domain Sockets (snapshot data)
    │        │
    │        ▼
    │    panoseti_grpc DaqData gRPC server (panoseti_grpc repo)
    │        │  streams downsampled real-time previews
    │        ▼
    │    Scientists / observers / dashboards
    │
    └──► PFF files (full-resolution archived data)
             │  rsync'd to head node by stop.py
             ▼
         panoseti-software analysis framework
```

Hashpipe status data is accessible via:
- `hashpipe_status_monitor.rb` directly on the DAQ node
- `hashpipe_redis_gateway.rb -s <head_node_ip>` to forward status to the head node's Redis, then viewed with `hashpipe_redis_monitor.rb`

## Build Commands

```bash
# Build the main shared library plugin
make

# Build for ARM64
make -f Makefile.aarch64

# Build test utilities
cd util && make

# Build packet test generator
cd tests/packetTestGenerator && cmake . && make
```

**Key build flags**: `-g -O3 -fPIC -shared`, `N_INPUT_BLOCKS=512`, `N_OUTPUT_BLOCKS=128`

**Dependencies**: `libhashpipe`, `libhiredis`, `librt`, `libm`, `libdl`

## Running Tests

Two test layers are provided: fast Catch2 unit tests and Docker-based integration tests.

```bash
# Unit tests (no Docker, seconds)
cd tests/unit && make clean && make && ./panoseti_unit_tests --reporter compact

# Full CI: unit tests + integration tests (requires Docker)
./run_ci_tests.sh

# Individual integration test files (inside the daq-test container)
pytest tests/ci_tests/test_can_hashpipe_init.py
pytest tests/ci_tests/test_uds_resilience.py
pytest tests/ci_tests/test_uds_data_path.py
pytest tests/ci_tests/test_pff_header_consistency.py
pytest tests/ci_tests/test_packet_sequence_monotonic.py
pytest tests/ci_tests/test_module_id_correctness.py
pytest tests/ci_tests/test_timestamp_sanity.py
pytest tests/ci_tests/test_image_data_nonzero.py
```

CI is defined in `.github/workflows/ci.yml` (triggers on push to `master` / `claude-refactor`, PRs to `master`).

## Pipeline Architecture

The output of `make` is `hashpipe.so`, a shared library plugin for the [Hashpipe](https://github.com/david-macmahon/hashpipe) framework. Hashpipe provides the multi-threaded circular buffer infrastructure; this repo implements the three pipeline threads.

```
UDP packets → [net_thread] → input_buffer → [compute_thread] → output_buffer → [output_thread] → disk
                                                                                      │
                                                                              Unix Domain Sockets
                                                                              (real-time snapshots)
```

### net_thread (`net_thread.c`)
Receives UDP science packets from quabos via a memory-mapped packet socket (`pktsock`). Validates the acquisition mode (`acq_mode`) of each packet, strips the header using `get_header()`, and writes the raw packet + header into the input shared memory buffer. Also serves **real-time snapshot data** to UDS clients (consumed by the `panoseti_grpc` DaqData gRPC server for live previews).

### compute_thread (`compute_thread.c`)
Reads the module config file (passed via the `CONFIG` Hashpipe key) to build an O(1) module index. For each packet: routes it to the correct `module_data` structure, assembles 4 QUABO images (16×16 each) into MODULE images (32×32), and creates PULSE HEIGHT images with optional frame grouping (256→1024 pixel). Applies image rotation corrections via `util/image.cpp`. Tracks per-quabo packet loss (by `BOARDLOC` and `acq_mode`) and records it in the Hashpipe status buffer. Writes assembled module data to the output shared memory buffer.

### output_thread (`output_thread.c`)
Reads the `RUNDIR` key (set per-run, never persisted) to determine the output directory. Creates `FILE_PTRS` objects for all modules in the config. Writes 4 data product types in PanoSETI File Format (`.pff`):
- `DP_BIT16_IMG` — 16-bit 32×32 movie image
- `DP_BIT8_IMG` — 8-bit 32×32 movie image
- `DP_PH_256_IMG` — 16×16 pulse height (single QUABO)
- `DP_PH_1024_IMG` — 32×32 pulse height (4 QUABOs grouped)

Rotates output files when they exceed `MAXFILESIZE` (default 500MB). Also reads from Redis (via `libhiredis`) to flush dynamic metadata to disk.

## Key Data Structures (`databuf.h`)

- **`PACKET_HEADER`**: Raw packet metadata — `acq_mode`, TAI/Unix timestamps (`pkt_tai`, `pkt_nsec`, `tv_sec`, `tv_usec`), module/quabo IDs, `pkt_num` (used for packet loss detection)
- **`MODULE_IMAGE_HEADER`**: Aggregates 4 `PACKET_HEADER`s plus module metadata; this is the JSON header block written to PFF files
- **Input buffer**: 512 blocks × ~16KB ≈ 8MB; holds 16,384 packets per block — kept small intentionally, must be drained fast to avoid loss
- **Output buffer**: 128 blocks; cache-aligned at 256 bytes

## PFF File Format

Each `.pff` file is a sequence of alternating blocks:
- **JSON header block**: starts with `{`, ends with `\n\n`, fixed-size (padded with spaces), contains per-frame metadata
- **Binary image block**: preceded by `*`, then raw pixel data

Files are named: `start_{ISO8601}.dp_{data_product}.bpp_{bytes}.module_{N}.seqno_{N}.pff`

Data products: `img8`, `img16`, `ph256`, `ph1024`

PFF parsing utilities: `util/pff.cpp` (C++), also exposed via `panoseti_grpc`'s `panoseti_util` sub-package.

## Real-Time Snapshot / gRPC Integration

The `output_thread` writes each assembled PFF frame to a **Unix Domain Socket** in addition to disk. The `panoseti_grpc` DaqData gRPC server (`panoseti_grpc` repo) listens on these UDS paths:

```
/tmp/hashpipe_grpc.dp_{dp_name}.sock   (e.g. dp_img16, dp_ph256)
```

The UDS frame format is: `[2-byte big-endian module_id][PFF frame]`

The DaqData gRPC server caches the latest frame per `(module_id, data_product)` and streams them to observers/scientists via `StreamImages` RPC at a configurable `update_interval_seconds`. This provides **downsampled, real-time science data previews** without interfering with the full-resolution disk writes.

`snapshot.c/h` manages the per-module linked list of UDS connections and write logic. `SSINT` (snapshot interval, ms) controls how often the Hashpipe status buffer is refreshed.

## Configuration

- **`module.config`**: List of active module IDs (e.g., `254`, `1`) — passed via `CONFIG` key
- **Hashpipe status buffer keys** (set at runtime via command line or `hashpipe_redis_gateway`):
  - `BINDHOST`, `BINDPORT` — network interface and UDP port to bind
  - `RUNDIR` — output directory for this run (cleared on each start, never auto-persisted)
  - `MAXFILESIZE` — output file rotation size in megabytes
  - `SSINT` — snapshot interval in ms
  - `GROUPPHFRAMES` — enable PH frame aggregation (256→1024 pixel)
  - `NPHEVENT` — status count of PH events received (updated every `SSINT` ms)

**Timing thresholds** (compile-time in `compute_thread.c`):
- `IMG_NANOSEC_THRESHOLD = 100 ns` — window for grouping image packets into one module frame
- `PH_NANOSEC_THRESHOLD = 50 ns` — window for grouping PH packets

**Timing precision**: Science packets carry both `tv_usec` (UNIX, from DAQ node NTP) and `pkt_nsec` (WR/GNSS nanoseconds since last UTC second). When combining: if `|tv_usec/1000 - pkt_nsec/1e6| > 25 ms`, adjust `tv_sec` by ±1 to recover nanosecond-precision event time.

## Utility Libraries

- **`util/pff.cpp/h`**: PanoSETI File Format (`.pff`) read/write
- **`util/image.cpp/h`**: Image rotation and QUABO-to-module assembly logic
- **`snapshot.c/h`**: Unix Domain Socket connection management for real-time data streaming to the gRPC server
