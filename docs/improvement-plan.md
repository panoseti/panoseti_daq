# PANOSETI DAQ Hashpipe Code Improvement Plan

This document describes a multi-phase roadmap for improving the robustness, testability, and maintainability of the `panoseti_daq_ssh` Hashpipe plugin.

The plugin is the most performance-critical component in the observatory stack — it receives every UDP science packet from quabo detector boards with zero tolerance for packet loss. All changes must preserve the exact same runtime behavior and must not add latency to the hot packet path.

---

## Phase 0 (Completed): Critical Bug Fixes

These bugs were fixed before any refactoring. Each fix corresponds to a latent correctness or safety issue.

### 0.1 Do-while loop use-after-free — `net_thread.c`

**Bug**: The original loop condition was:
```c
} while (!p_frame && run_threads() && !INTSIG && !check_acqmode(p_frame));
```
When `check_acqmode` returned false (bad acq_mode), the `!p_frame` term on the next iteration was `false` (because `p_frame` is non-NULL), causing the loop to exit and the bad frame pointer to escape into the caller — a use-after-free.

**Fix**: Restructured to `while (run_threads() && !INTSIG && (!p_frame || !check_acqmode(p_frame)))` — loop continues until a valid frame is received OR shutdown is requested.

### 0.2 Operator precedence bug — `net_thread.c`

**Bug**: `acq_mode & 0x01 == 0x01` evaluates as `acq_mode & (0x01 == 0x01)` due to C precedence.

**Fix**: Added explicit parentheses: `(acq_mode & 0x01) == 0x01`.

### 0.3 Stack overflow risk — `compute_thread.c`

**Bug**: `quabo_info_t *quaboInd[0xffff] = {NULL};` allocated ~512 KB on the stack inside `run()`. Combined with other per-thread stacks, this risked stack overflow.

**Fix**: Moved to static file scope, matching the existing pattern for `moduleInd` and `PHmoduleInd`.

### 0.4 malloc return unchecked — `compute_thread.c`

**Bug**: `malloc` return in `quabo_info_t_new()` was used without a NULL check.

**Fix**: Added NULL check with `hashpipe_error()` and NULL return on failure. The caller in `run()` now skips the packet if the return is NULL.

### 0.5 Signal handler variables missing `volatile` — `net_thread.c`, `output_thread.c`

**Bug**: `INTSIG` and `QUITSIG` were plain `int` globals written in signal handlers and read in the main loop. The compiler can cache these in a register.

**Fix**: Declared as `volatile sig_atomic_t`.

### 0.6 Output buffer mutation — `output_thread.c`

**Bug**: `write_img_header_json` and `write_ph_header_json` clamped `pkt_nsec` directly on the shared output buffer struct, corrupting data in place.

**Fix**: Use a local `uint32_t pkt_nsec` copy before clamping; never modify the buffer.

### 0.7 NULL dereference before NULL check — `output_thread.c`

**Bug**: In `write_module_img_file` and `write_module_ph_file`, `moduleToWrite` was dereferenced (to access `->bit16Img` etc.) before the `if (moduleToWrite == NULL)` guard.

**Fix**: Moved the NULL check to the top of each function, before any dereference.

### 0.8 `exit()` in thread functions — `output_thread.c`, `compute_thread.c`

**Bug**: Calling `exit()` from inside a Hashpipe thread kills the entire process without cleanup, bypassing Hashpipe's teardown lifecycle.

**Fix**: Replaced with `hashpipe_error()` + `return -1` (for `init()`) or `return NULL` (for allocation functions).

### 0.9 `bytes_per_pixel()` wrong default return — `util/pff.h`

**Bug**: The default `return DP_BIT16_IMG;` returned the enum value (1), not a valid bytes-per-pixel count.

**Fix**: Changed to `return -1;` so callers can detect unsupported data products.

### 0.10 `fclose()` without NULL check — `output_thread.c`

**Bug**: `close_files()` called `fclose()` on all four file pointers without checking whether they were successfully opened.

**Fix**: Added NULL guards before each `fclose()` call.

---

## Phase 1 (Completed): Dead Code Removal

### `process_frame.c/h`

`process_frame()` was declared but had an empty body and was never called. Both files were deleted and removed from all three Makefiles.

---

## Phase 2 (Completed): Logging Modernization

All `printf`, `fprintf(stderr, ...)`, and `perror` calls in the three thread files were replaced with Hashpipe's own logging API:

| Old call | Replacement |
|----------|-------------|
| `printf("info...\n")` | `hashpipe_info("thread_name", "info...")` |
| `fprintf(stderr, "warn...\n")` | `hashpipe_warn("thread_name", "warn...")` |
| `fprintf(stderr, "err...\n"); exit(1)` | `hashpipe_error("thread_name", "err..."); return -1` |
| `perror("msg")` | `hashpipe_error("thread_name", "msg: %s", strerror(errno))` |

Hashpipe's logging functions are thread-safe, include timestamps, and write to both stderr and the Hashpipe status buffer. Using them consistently means all DAQ log output is visible through the same monitoring path.

---

## Phase 3 (Completed): Unit Tests (Catch2)

A new test suite in `tests/unit/` tests internal logic without requiring Hashpipe, Docker, or network access.

### Setup

- **Framework**: Catch2 v3 (`apt install catch2` on Ubuntu 22.04+)
- **Build**: `cd tests/unit && make`
- **Run**: `make test` or `./panoseti_unit_tests`
- **CI integration**: Unit tests are built and run inside the Docker builder stage — a test failure fails the entire build before the runtime image is assembled

### Test files

| File | What it tests |
|------|---------------|
| `test_pff.cpp` | `bytes_per_pixel()` for all DATA_PRODUCTs including invalid; PFF JSON write/read round-trip; PFF image write/read round-trip; JSON+image interleaved; `FILENAME_INFO` make/parse round-trip; `dp_to_str()` |
| `test_image_rotation.cpp` | `quabo16_to_module16_copy` for all 4 quabo indices — full pixel-by-pixel verification; boundary corners; quadrant containment (no writes outside the quabo's quadrant); 8-bit copy variants; all-4-quabos assembly with no-overlap check |

---

## Phase 4 (Planned): Remaining Refactoring

These improvements are deferred to a later PR. None are required for correctness but improve long-term maintainability.

### 4.1 `snapshot.c` — UDS connection memory leak

`get_uds_connection()` allocates a `uds_connection_t` with `malloc` but the connection is never freed when it times out. Fix: add a `free_uds_connection()` path called on timeout via `UDS_CONNECTION_TIMEOUT_US`.

### 4.2 `snapshot.c` — Partial `writev()` not handled

A single `writev()` call is not guaranteed to write all bytes. Fix: retry up to 3 times on short write, then log and close the connection.

### 4.3 `compute_thread.c` — `storeData()` decomposition

`storeData()` is ~360 lines. Consider splitting into:
- `route_packet_to_module()` — determines target buffer
- `assemble_module_image()` — updates bitmap, returns true when complete
- `assemble_ph_image()` — same for PH data
- `update_pkt_loss()` — isolated packet loss accounting

Do NOT refactor the inner timing loops — they are intentionally performance-optimized.

### 4.4 `util/pff.cpp` — Unsafe string operations

Replace `sprintf` with `snprintf` (fixed buffers in `make_dirname`, `make_filename`), and `strcpy` in `NV_PAIR::parse` with `strncpy`. Check `strptime()` return value.

### 4.5 CMake build system

Add `CMakeLists.txt` alongside the existing `Makefile` to enable:
- `compile_commands.json` for IDE support (clangd, VSCode, JetBrains)
- Sanitizer build targets (`-DENABLE_ASAN=ON`, `-DENABLE_TSAN=ON`)
- Cross-platform aarch64 via toolchain file (supplementing `Makefile.aarch64`)

---

## Phase 5 (Planned): Additional Integration Tests

These supplement the existing CI tests. Add to `tests/ci_tests/`.

| Test | What it verifies |
|------|-----------------|
| `test_packet_sequence_monotonic.py` | `pkt_num` increases monotonically within each quabo (with 16-bit wrap) |
| `test_module_id_correctness.py` | All received frames have `module_id` in `[1, 254]` |
| `test_timestamp_sanity.py` | `pkt_tai` monotonic, `pkt_nsec` in [0, 999999999], no negative time deltas |
| `test_file_rotation.py` | `seqno` increments at rotation; no file exceeds 2× `MAXFILESIZE`; no gap at rotation boundary |
| `test_image_data_nonzero.py` | Binary image blocks are not all-zero (real data from PCAP is being processed) |
| Enable `test_frame_seeking_capability` | Currently `pytest.skip`-decorated — unblock this to verify random-access frame seeking |

---

## What NOT to Change

- The core packet reception loop in `net_thread.c` (memory-mapped packet socket logic) — already optimal
- Buffer sizes (`N_INPUT_BLOCKS`, `N_OUTPUT_BLOCKS`) — tuned for the Beelink DAQ hardware
- The `quabos_bitmap` assembly timing thresholds (`IMG_NANOSEC_THRESHOLD`, `PH_NANOSEC_THRESHOLD`) — observatory-tuned values
- The PFF binary format — consumed by all downstream analysis code
- The UDS wire format `[2-byte module_id][PFF frame]` — consumed by `panoseti_grpc`
