// test_packet_utils.cpp
// Unit tests for util/packet_utils.h
// No dependency on Hashpipe.

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "packet_utils.h"

using Catch::Approx;

// ─── reconcile_timestamp ─────────────────────────────────────────────────────

TEST_CASE("reconcile_timestamp: mid-second, no adjustment", "[packet_utils]") {
    // tv_usec=500000 (500ms), pkt_nsec=500000000 (500ms) → |diff|=0 < 25ms
    // Result: tv_sec + 0.5
    long tv_sec  = 1700000000L;
    long tv_usec = 500000L;
    uint32_t pkt_nsec = 500000000u;

    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec + 0.5).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: WR near start, NTP near end → add 1 to tv_sec", "[packet_utils]") {
    // pkt_nsec=1ms, tv_usec=999ms → diff = 1-999 = -998 < -25 → sec_adjust=+1
    // WR just crossed into the next second; NTP's tv_sec hasn't rolled yet.
    // True time = (tv_sec + 1) + 0.001
    long tv_sec  = 1700000000L;
    long tv_usec = 999000L;          // 999 ms
    uint32_t pkt_nsec = 1000000u;    // 1 ms

    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec + 1 + 0.001).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: WR near end, NTP near start → subtract 1 from tv_sec", "[packet_utils]") {
    // pkt_nsec=999ms, tv_usec=1ms → diff = 999-1 = 998 > 25 → sec_adjust=-1
    // NTP rolled its second counter early; the WR second hasn't ended yet.
    // True time = (tv_sec - 1) + 0.999
    long tv_sec  = 1700000000L;
    long tv_usec = 1000L;              // 1 ms
    uint32_t pkt_nsec = 999000000u;   // 999 ms

    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec - 1 + 0.999).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: pkt_nsec > 999999999 is clamped", "[packet_utils]") {
    // Oversized pkt_nsec must be clamped to 999999999 before use.
    long tv_sec  = 1700000000L;
    long tv_usec = 500000L;
    uint32_t pkt_nsec = 1000000001u;   // > 999999999

    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    // After clamping to 999999999: diff = 999-500 = 499 > 25 → sec_adjust = -1
    // Result = (tv_sec - 1) + 0.999999999
    CHECK(ts == Approx(tv_sec - 1 + 0.999999999).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: near-boundary but within 25ms → no adjustment", "[packet_utils]") {
    // diff = 20ms < 25ms → no adjustment
    long tv_sec  = 1700000000L;
    long tv_usec = 30000L;              // 30ms
    uint32_t pkt_nsec = 50000000u;     // 50ms → diff=50-30=20 < 25

    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec + 0.05).epsilon(1e-6));
}

// ─── calc_pkt_loss ────────────────────────────────────────────────────────────

TEST_CASE("calc_pkt_loss: first-packet sentinel (prev=0xFFFF) returns 0", "[packet_utils]") {
    CHECK(calc_pkt_loss(0xFFFF, 0)     == 0u);
    CHECK(calc_pkt_loss(0xFFFF, 100)   == 0u);
    CHECK(calc_pkt_loss(0xFFFF, 65534) == 0u);
}

TEST_CASE("calc_pkt_loss: consecutive packets have 0 lost", "[packet_utils]") {
    CHECK(calc_pkt_loss(100, 101) == 0u);
    CHECK(calc_pkt_loss(0,   1)   == 0u);
    CHECK(calc_pkt_loss(65534, 65535) == 0u);
}

TEST_CASE("calc_pkt_loss: single packet lost", "[packet_utils]") {
    CHECK(calc_pkt_loss(100, 102) == 1u);
}

TEST_CASE("calc_pkt_loss: large gap", "[packet_utils]") {
    // prev=100, curr=200 → 99 lost
    CHECK(calc_pkt_loss(100, 200) == 99u);
}

TEST_CASE("calc_pkt_loss: 16-bit wrap-around with no loss", "[packet_utils]") {
    // prev=65535, curr=0: no packet lost, wrap to 0
    CHECK(calc_pkt_loss(65535, 0) == 0u);
}

TEST_CASE("calc_pkt_loss: 16-bit wrap-around with loss", "[packet_utils]") {
    // prev=65000, curr=50 → (65535-65000)+50 = 535+50 = 585 lost
    uint16_t expected = (uint16_t)((65535u - 65000u) + 50u);
    CHECK(calc_pkt_loss(65000, 50) == expected);
}

TEST_CASE("calc_pkt_loss: duplicate packet yields 65535 (defined wrap underflow)", "[packet_utils]") {
    // curr == prev: formula gives (prev - prev - 1) = -1 as uint16 = 65535.
    // This is the defined behavior; callers should not send duplicate pkt_nums
    // and should guard against this if needed.
    CHECK(calc_pkt_loss(100, 100) == 65535u);
}

// ─── reconcile_timestamp boundary tests ──────────────────────────────────────

TEST_CASE("reconcile_timestamp: diff exactly 25ms — no adjustment", "[packet_utils]") {
    // diff = pkt_ms - ntp_ms = 25 ms exactly — threshold is > 25, so no adjust
    long tv_sec  = 1700000000L;
    long tv_usec = 50000L;           // 50 ms
    uint32_t pkt_nsec = 75000000u;  // 75 ms → diff = 75-50 = 25 → no adjust
    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec + 0.075).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: diff 26ms — adjustment triggered (WR near end)", "[packet_utils]") {
    // diff = 26 > 25 → sec_adjust = -1
    long tv_sec  = 1700000000L;
    long tv_usec = 50000L;           // 50 ms
    uint32_t pkt_nsec = 76000000u;  // 76 ms → diff = 76-50 = 26 > 25 → sec_adjust=-1
    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec - 1 + 0.076).epsilon(1e-6));
}

TEST_CASE("reconcile_timestamp: diff -26ms — adjustment triggered (WR near start)", "[packet_utils]") {
    // diff = -26 < -25 → sec_adjust = +1
    long tv_sec  = 1700000000L;
    long tv_usec = 76000L;           // 76 ms
    uint32_t pkt_nsec = 50000000u;  // 50 ms → diff = 50-76 = -26 < -25 → sec_adjust=+1
    double ts = reconcile_timestamp(tv_sec, tv_usec, pkt_nsec);
    CHECK(ts == Approx(tv_sec + 1 + 0.050).epsilon(1e-6));
}

// ─── is_valid_acq_mode ────────────────────────────────────────────────────────

TEST_CASE("is_valid_acq_mode: mode 0x00 is valid (disabled, but in-range index)", "[packet_utils]") {
    CHECK(is_valid_acq_mode(0x00) == true);
}

TEST_CASE("is_valid_acq_mode: mode 0x01 (PH) is valid", "[packet_utils]") {
    CHECK(is_valid_acq_mode(0x01) == true);
}

TEST_CASE("is_valid_acq_mode: max in-range mode 0x07 is valid", "[packet_utils]") {
    CHECK(is_valid_acq_mode(0x07) == true);
}

TEST_CASE("is_valid_acq_mode: mode 0x08 is invalid (just above max)", "[packet_utils]") {
    CHECK(is_valid_acq_mode(0x08) == false);
}

TEST_CASE("is_valid_acq_mode: mode 0xFF is invalid (corrupted packet)", "[packet_utils]") {
    CHECK(is_valid_acq_mode(0xFF) == false);
}

// ─── calc_board_loc / is_valid_board_loc ─────────────────────────────────────

TEST_CASE("calc_board_loc: lab module 1 quabo 0 → 4, valid", "[packet_utils]") {
    uint32_t loc = calc_board_loc(1, 0);
    CHECK(loc == 4u);
    CHECK(is_valid_board_loc(loc) == true);
}

TEST_CASE("calc_board_loc: lab module 254 quabo 3 → 1019, valid", "[packet_utils]") {
    uint32_t loc = calc_board_loc(254, 3);
    CHECK(loc == 1019u);
    CHECK(is_valid_board_loc(loc) == true);
}

TEST_CASE("calc_board_loc: minimum module 0 quabo 0 → 0, valid", "[packet_utils]") {
    uint32_t loc = calc_board_loc(0, 0);
    CHECK(loc == 0u);
    CHECK(is_valid_board_loc(loc) == true);
}

TEST_CASE("calc_board_loc: near-max module 16382 quabo 3 → 65531, valid", "[packet_utils]") {
    uint32_t loc = calc_board_loc(16382, 3);
    CHECK(loc == 65531u);
    CHECK(is_valid_board_loc(loc) == true);
}

TEST_CASE("calc_board_loc: boundary module 16383 quabo 3 → 65535, invalid (at MAX)", "[packet_utils]") {
    uint32_t loc = calc_board_loc(16383, 3);
    CHECK(loc == 65535u);
    CHECK(is_valid_board_loc(loc) == false); // 65535 is the array size, not a valid index
}

TEST_CASE("calc_board_loc: overflow case module 16384 quabo 0 → 65536, invalid", "[packet_utils]") {
    // With uint16_t arithmetic, 16384*4 wraps to 0. With uint32_t it gives 65536.
    // This test documents that calc_board_loc correctly avoids the overflow.
    uint32_t loc = calc_board_loc(16384, 0);
    CHECK(loc == 65536u);
    CHECK(is_valid_board_loc(loc) == false);
}

TEST_CASE("calc_board_loc: uint16_t wrap vs uint32_t — documents the fixed overflow", "[packet_utils]") {
    // If computed as uint16_t: (uint16_t)(16384 * 4 + 0) == 0 (wraps to 0!)
    // calc_board_loc uses uint32_t and returns 65536 — correctly detected as OOB.
    uint16_t naive = (uint16_t)((uint16_t)16384u * 4u + 0u);
    uint32_t safe  = calc_board_loc(16384, 0);
    CHECK(naive == 0u);    // uint16 wraps silently to a "valid" index
    CHECK(safe  == 65536u); // uint32 gives the true value, caught by is_valid_board_loc
    CHECK(is_valid_board_loc(safe) == false);
}

// ─── timeval_diff_us ──────────────────────────────────────────────────────────

TEST_CASE("timeval_diff_us: same second, positive diff", "[packet_utils]") {
    struct timeval start = {1L, 0L};
    struct timeval end   = {1L, 500000L};
    CHECK(timeval_diff_us(&start, &end) == 500000u);
}

TEST_CASE("timeval_diff_us: cross-second boundary", "[packet_utils]") {
    struct timeval start = {1L, 800000L};
    struct timeval end   = {2L, 200000L};
    CHECK(timeval_diff_us(&start, &end) == 400000u);
}

TEST_CASE("timeval_diff_us: equal timestamps → 0", "[packet_utils]") {
    struct timeval t = {1700000000L, 123456L};
    CHECK(timeval_diff_us(&t, &t) == 0u);
}

TEST_CASE("timeval_diff_us: usec borrow (end.usec < start.usec)", "[packet_utils]") {
    struct timeval start = {1L, 900000L};
    struct timeval end   = {2L, 100000L};
    CHECK(timeval_diff_us(&start, &end) == 200000u);
}

TEST_CASE("timeval_diff_us: large difference (many seconds)", "[packet_utils]") {
    struct timeval start = {0L, 0L};
    struct timeval end   = {10L, 0L};
    CHECK(timeval_diff_us(&start, &end) == 10000000u);
}

TEST_CASE("timeval_diff_us: end < start wraps (documented behavior)", "[packet_utils]") {
    // timeval_diff_us does not check for negative results.
    // When end < start the uint64 result wraps to a large value.
    struct timeval start = {2L, 0L};
    struct timeval end   = {1L, 0L};
    uint64_t result = timeval_diff_us(&start, &end);
    // The exact value is implementation-defined due to uint64 wrap,
    // but it must be non-zero and very large.
    CHECK(result > 0u);
    CHECK(result > (uint64_t)1000000u); // much larger than any real diff
}
