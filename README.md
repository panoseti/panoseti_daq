# PANOSETI DAQ — Hashpipe Data Recorder

This repository contains the real-time data acquisition (DAQ) software for the [PANOSETI](https://github.com/panoseti/panoseti) observatory. It runs on each **DAQ node** during an observing session and is the most performance-sensitive component in the observatory stack: it captures every UDP science packet from the telescope's quabo detector boards, assembles them into calibrated images, writes full-resolution data to disk in PanoSETI File Format (`.pff`), and simultaneously streams downsampled science previews to observers in real time.

The software is implemented as a shared library plugin (`hashpipe.so`) for the [Hashpipe](https://github.com/david-macmahon/hashpipe) framework, which provides multi-threaded circular-buffer infrastructure for high-throughput packet processing.

---

## Observatory Context

A PANOSETI observatory consists of:

- **Head node** — the control computer where scientists manage observing sessions using `session_start.py`, `start.py`, `stop.py`, etc. ([panoseti-software](https://github.com/panoseti/panoseti))
- **DAQ nodes** — dedicated Linux machines that run this Hashpipe plugin, one per dome or group of modules
- **Modules** — each module has a mobo board and up to 4 **quabos** (quadrant boards, 16×16 pixel SiPM detector arrays)

Each quabo streams science data as UDP packets to the DAQ node on **port 60001**. Each DAQ node's set of modules is specified in `daq_config.json` on the head node; the module IDs to process locally are written to `module.config` at run start.

### Data flow

```
Quabos (UDP science packets, port 60001)
    │
    ▼
DAQ Node: Hashpipe (this repo)
    │   net_thread → compute_thread → output_thread
    │
    ├──► PFF files (full-resolution archived data)
    │       Written to RUNDIR/module_N/
    │       rsync'd to head node by stop.py
    │
    └──► Unix Domain Sockets  (/tmp/hashpipe_grpc.dp_*.sock)
             │
             ▼
         panoseti_grpc DaqData gRPC server
             │  streams downsampled real-time previews
             ▼
         Scientists, observers, dashboards
```

---

## Pipeline Architecture

Hashpipe connects the three threads via zero-copy shared memory circular buffers. The input buffer (512 blocks × 16,384 packets each) must be drained continuously — if it fills, packets are lost. The output buffer (128 blocks) passes assembled module images to disk.

```
[net_thread] ──input_buf──▶ [compute_thread] ──output_buf──▶ [output_thread]
      │                                                              │
   raw UDP                                                    PFF files + UDS
   packets
```

### net_thread (`net_thread.c`)

Binds to `BINDHOST:BINDPORT` (default `0.0.0.0:60001`) using a memory-mapped packet socket (`pktsock`) for maximum throughput. For each incoming packet it:

1. Validates the acquisition mode (`acq_mode`) — malformed or unrecognized packets are logged to stderr and skipped
2. Strips the 16-byte packet header via `get_header()` into a `PACKET_HEADER` struct
3. Copies the header and image payload into the next input buffer block
4. Stamps the block with a local `gettimeofday()` timestamp
5. Updates the per-module snapshot buffers and flushes them to UDS when the snapshot interval (`SSINT`, default 100 ms) has elapsed

### compute_thread (`compute_thread.c`)

Reads `module.config` on startup to build an O(1) module index. For each input buffer block it:

1. Routes each packet to the correct `CIRCULAR_MODULE_IMAGE_BUFFER` for that module
2. Waits until all 4 quabo images arrive within `IMG_NANOSEC_THRESHOLD` (100 ns) to assemble a complete 32×32 module frame, using a `quabos_bitmap` to track which of the 4 quabos have arrived. Partial frames are flushed with a warning if the buffer fills.
3. For pulse-height data: writes individual 16×16 quabo frames (`DP_PH_256_IMG`) or, when `GROUPPHFRAMES=1`, waits for all 4 quabos within `PH_NANOSEC_THRESHOLD` (50 ns) and writes a grouped 32×32 frame (`DP_PH_1024_IMG`)
4. Applies per-quabo image rotation and placement (0°/90°/180°/270°) via `util/image.cpp` to produce correctly oriented module images
5. Tracks per-quabo packet loss by `BOARDLOC` and `acq_mode` and reports counts to the Hashpipe status buffer
6. Writes completed module frames to the output buffer

### output_thread (`output_thread.c`)

Reads `RUNDIR` at startup (this key is intentionally cleared on each run — it must always be set explicitly). Creates `FILE_PTRS` for every module in `module.config`. For each output buffer block it:

1. Writes image frames to `DP_BIT16_IMG` and `DP_BIT8_IMG` PFF files
2. Writes pulse-height frames to `DP_PH_256_IMG` or `DP_PH_1024_IMG` PFF files
3. Rotates to a new file when the current file exceeds `MAXFILESIZE` megabytes (default 500), incrementing `seqno`
4. Uses a 1 MB `stdio` buffer for image files (vs. the default 4 KB) to reduce write latency
5. Flushes Redis metadata keys to disk via `libhiredis`

---

## Data Products

Four data product files are written per module per run, named:

```
start_{ISO8601}.dp_{product}.bpp_{bytes_per_pixel}.module_{N}.seqno_{N}.pff
```

| Product | Description | Shape | Bytes/pixel |
|---------|-------------|-------|-------------|
| `img16` | 16-bit movie image | 32×32 | 2 |
| `img8` | 8-bit movie image | 32×32 | 1 |
| `ph256` | Pulse-height, single quabo | 16×16 | 2 |
| `ph1024` | Pulse-height, 4 quabos grouped | 32×32 | 2 |

### PFF file format

Each `.pff` file is a sequence of alternating header and image blocks:

- **JSON header block**: starts with `{`, ends with `\n\n`, fixed-size (padded with spaces). Contains per-frame metadata: `quabo_num`, `pkt_num`, `pkt_tai`, `pkt_nsec` (WR/GNSS nanosecond timestamp), `tv_sec`, `tv_usec` (NTP Unix timestamp).
- **Binary image block**: preceded by `*`, followed by raw pixel data.

The PFF format is described in detail on the [PANOSETI wiki](https://github.com/panoseti/panoseti/wiki/Data-file-format). Parsing utilities are in `util/pff.cpp`.

### Timing precision

Science packets carry two timestamps:
- `tv_usec` — microseconds from the DAQ node's NTP clock
- `pkt_nsec` — nanoseconds since the last UTC second, from White Rabbit (WR) or GNSS

To reconstruct a nanosecond-precision event time: if `|tv_usec/1000 − pkt_nsec/1e6| > 25 ms`, adjust `tv_sec` by ±1 to account for the second boundary.

---

## Real-Time Snapshot Path

The net_thread maintains a `module_snapshot_buffer` per module — a linked list of `snapshot_t` objects, one per data product. Each incoming packet updates the matching snapshot. When a snapshot is complete (all 4 quabo bits set in `quabo_bitmap` for 32×32 products, or immediately for 16×16 PH) **and** the snapshot interval has elapsed, the frame is written to a Unix Domain Socket:

```
/tmp/hashpipe_grpc.dp_{product}.sock
```

The wire format is `[2-byte big-endian module_id][PFF frame]`.

The [panoseti_grpc](https://github.com/panoseti/panoseti_grpc) DaqData gRPC server listens on these sockets via its `UdsDataSource` components. It caches the latest frame per `(module_id, data_product)` and distributes them to any number of simultaneous `StreamImages` gRPC clients at a configurable update rate. Idle UDS connections are closed after 15 seconds of inactivity (`UDS_CONNECTION_TIMEOUT_US`) and re-established automatically.

To view live data from a running observing session:

```python
from panoseti_grpc.daq_data.client import DaqDataClient

with DaqDataClient(daq_config_path, network_config_path) as client:
    for pano_image in client.stream_images(stream_movie_data=True, stream_pulse_height_data=True):
        # pano_image['image_array'] is a NumPy array
        # pano_image['header']['wr_unix_timestamp'] is nanosecond-precision
        process(pano_image)
```

---

## Building

**Requirements**: `g++`, `libhashpipe`, `libhiredis`, `librt`, `libm`, `libdl`

```bash
# Build hashpipe.so for x86-64
make

# Build for ARM64
make -f Makefile.aarch64

# Build PFF/image utility library
cd util && make

# Build packet test data generator
cd tests/packetTestGenerator && cmake . && make

# Clean
make clean
```

The output is `hashpipe.so` — a shared library dynamically loaded by the `hashpipe` executable.

---

## Configuration

Hashpipe is launched with key-value options passed via `-o KEY=VALUE` on the command line. These are stored in the Hashpipe shared memory status buffer and persist across restarts unless explicitly cleared.

| Key | Default | Description |
|-----|---------|-------------|
| `BINDHOST` | `0.0.0.0` | Network interface or IP to bind for UDP reception |
| `BINDPORT` | `60001` | UDP port to listen on |
| `RUNDIR` | *(required)* | Output directory for this run — **always cleared between runs** |
| `CONFIG` | `./module.config` | Path to the module config file |
| `MAXFILESIZE` | `500` | Output file rotation size in megabytes |
| `SSINT` | `100` | Snapshot interval in milliseconds (also controls status buffer refresh rate) |
| `GROUPPHFRAMES` | `0` | Set to `1` to group 4 quabo PH frames into 32×32 `ph1024` images |
| `OBS` | *(observatory name)* | Observatory identifier written into PFF directory names |

`module.config` is a plain text file listing one module ID per line:

```
254
1
```

### Example launch command

```bash
hashpipe -p hashpipe.so -I 0 \
    -o BINDHOST=enp171s0 \
    -o RUNDIR=obs_20240725 \
    -o CONFIG=obs_20240725/module.config \
    -o MAXFILESIZE=500 \
    -o SSINT=100 \
    -o GROUPPHFRAMES=1 \
    net_thread compute_thread output_thread
```

The head node's `start.py` generates and executes this command on each DAQ node via SSH.

### Output directory layout

```
RUNDIR/
└── module_{N}/
    ├── start_2024-07-25T04_34_46Z.dp_img16.bpp_2.module_N.seqno_0.pff
    ├── start_2024-07-25T04_34_46Z.dp_img8.bpp_1.module_N.seqno_0.pff
    ├── start_2024-07-25T04_34_46Z.dp_ph256.bpp_2.module_N.seqno_0.pff
    └── start_2024-07-25T04_34_46Z.dp_ph1024.bpp_2.module_N.seqno_0.pff
```

---

## Monitoring

The Hashpipe status buffer is accessible on the DAQ node:

```bash
hashpipe_status_monitor.rb
```

To forward status to the head node's Redis and monitor remotely:

```bash
# On the DAQ node:
hashpipe_redis_gateway.rb -s <head_node_ip>

# On the head node:
hashpipe_redis_monitor.rb -s <head_node_ip> <daq_node_hostname>/0
```

Key status fields: `BINDHOST`, `BINDPORT`, `RUNDIR`, `NPACKETS` (total packets received), `NPHEVENT` (PH events received since last `SSINT` interval), and per-quabo packet loss counters.

---

## Testing

Two test layers are provided: fast Catch2 unit tests and Docker-based integration tests.

### Unit tests (no Docker required)

Unit tests cover `util/pff.cpp` and `util/image.cpp` in isolation using [Catch2](https://github.com/catchorg/Catch2). They run in seconds and require no Hashpipe installation.

**Requirements**: `g++` with C++17 support, `libcatch2-dev` (`apt install catch2`)

```bash
cd tests/unit
make test
```

### Integration tests

Integration tests spin up a real Hashpipe instance inside Docker, replay a captured packet trace via `tcpreplay`, and assert end-to-end behavior. The unit tests also run as part of the Docker builder stage — the image will fail to build if any unit test fails.

```bash
# Build image (runs unit tests) and execute integration tests
./run_ci_tests.sh

# Run individual integration test suites (requires built image)
docker build -t panoseti-daq -f tests/ci_tests/Dockerfile .
docker run --rm --shm-size=2g panoseti-daq \
    python3 -m pytest -s -v tests/ci_tests/test_can_hashpipe_init.py
```

| Test file | What it tests |
|-----------|---------------|
| `test_can_hashpipe_init.py` | Hashpipe starts and stays running; PFF files are written |
| `test_uds_resilience.py` | UDS connections reconnect correctly after the server restarts |
| `test_uds_data_path.py` | End-to-end: Hashpipe connects to UDS sockets and delivers correctly framed PH data |
| `test_pff_header_consistency.py` | PFF file headers are well-formed and consistent with binary image blocks |
| `test_packet_sequence_monotonic.py` | Per-quabo packet numbers are monotonically non-decreasing |
| `test_module_id_correctness.py` | Module IDs in UDS frames match the configured set |
| `test_timestamp_sanity.py` | Timestamps in headers are sane (pkt_nsec in range, pkt_tai non-zero) |
| `test_image_data_nonzero.py` | img16 frames carry real pixel data (not all-zero or all-saturated) |

The CI fixture (`conftest.py`) starts the Python test code as the **UDS server** (the role normally played by `panoseti_grpc`), replays a `.pcapng` capture at 1 Mbps on the loopback interface, and launches Hashpipe as the client — mirroring the production connection direction exactly.

CI runs on GitHub Actions (`.github/workflows/ci.yml`) on every push to `main` and `dev`.

---

## Repository Structure

```
├── net_thread.c          # Thread 1: UDP packet reception and UDS snapshot writes
├── compute_thread.c      # Thread 2: image assembly, rotation, PH grouping
├── output_thread.c       # Thread 3: PFF file I/O and file rotation
├── databuf.h             # Shared memory buffer layout and constants
├── snapshot.c/h          # UDS connection management and snapshot logic
├── util/
│   ├── pff.cpp/h         # PanoSETI File Format read/write
│   ├── image.cpp/h       # Quabo→module image assembly and rotation
│   └── packet_utils.h    # Inline timestamp reconciliation and packet-loss math
├── tests/
│   ├── unit/             # Catch2 unit tests for util/ (no Hashpipe dependency)
│   ├── ci_tests/         # Docker-based integration tests (pytest)
│   └── packetTestGenerator/  # Synthetic packet generator (CMake)
├── docs/
│   └── improvement-plan.md   # Planned robustness improvements and architecture proposals
├── Makefile              # x86-64 build
├── Makefile.aarch64      # ARM64 build
└── run_ci_tests.sh       # Local CI runner script
```

---

## Recent Improvements

A series of robustness and correctness fixes were applied to the codebase. See [`docs/improvement-plan.md`](docs/improvement-plan.md) for the complete roadmap.

### Phase 0 — Critical bug fixes

| Fix | File | Description |
|-----|------|-------------|
| Stack overflow | `compute_thread.c` | Moved 512 KB `quaboInd[]` array from stack to file-scope static |
| NULL deref | `compute_thread.c` | Added NULL guard on `quabo_info_t_new()` return |
| NULL deref | `output_thread.c` | Fixed NULL check ordering in `write_module_ph_file` |
| Memory leak | `output_thread.c` | Added NULL guards before `fclose()` in `close_files()` |
| Wrong default | `util/pff.h` | `bytes_per_pixel()` returned enum value instead of `-1` for `DP_NONE` |
| Signal safety | `net_thread.c` | Changed `INTSIG` to `volatile sig_atomic_t` |
| Signal safety | `output_thread.c` | Changed `QUITSIG` to `volatile sig_atomic_t` |
| Infinite loop | `net_thread.c` | Fixed do-while condition that let bad `acq_mode` packets escape the loop |
| Logging | All threads | Replaced all `printf`/`fprintf`/`exit` with `hashpipe_error`/`hashpipe_warn`/`hashpipe_info` |
| Dead code | Repository | Deleted unused `process_frame.c/h` |

---

## Related Repositories

| Repo | Role |
|------|------|
| [panoseti/panoseti](https://github.com/panoseti/panoseti) | Observatory control system (`start.py`, `stop.py`, quabo driver, config files) |
| [panoseti/panoseti_grpc](https://github.com/panoseti/panoseti_grpc) | gRPC services including DaqData, which streams real-time previews from this repo's UDS output |
| [panoseti/panoseti](https://github.com/panoseti/panoseti/wiki) | Full system documentation wiki |
