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
