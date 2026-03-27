// util/packet_utils.h
// Pure inline utilities for timestamp reconciliation and packet-loss accounting.
// No Hashpipe dependency — safe to include in unit tests.

#ifndef PANOSETI_PACKET_UTILS_H
#define PANOSETI_PACKET_UTILS_H

#include <stdint.h>

// reconcile_timestamp
//
// Combine the NTP Unix timestamp (tv_sec, tv_usec) with the White-Rabbit /
// GNSS sub-second counter (pkt_nsec) to produce a nanosecond-precision Unix
// timestamp as a double.
//
// Near a UTC second boundary NTP and WR may disagree about which second it is:
//   - If pkt_nsec is near 999 ms and tv_usec is near 0 ms the WR second
//     boundary has not yet been reflected in NTP → tv_sec is 1 too large.
//     Subtract 1 from tv_sec.
//   - If pkt_nsec is near 0 ms and tv_usec is near 999 ms the WR second
//     boundary was not yet reflected in tv_usec → tv_sec is 1 too small.
//     Add 1 to tv_sec.
//   - 25 ms is used as the boundary-straddle detection threshold.
//
// pkt_nsec values > 999 999 999 are clamped to 999 999 999.
//
inline double reconcile_timestamp(long tv_sec, long tv_usec, uint32_t pkt_nsec) {
    if (pkt_nsec > 999999999u) pkt_nsec = 999999999u;

    long pkt_ms = (long)(pkt_nsec / 1000000u);  // WR milliseconds within the second
    long ntp_ms = tv_usec / 1000L;               // NTP milliseconds within the second

    long diff = pkt_ms - ntp_ms;   // positive: WR is later in second than NTP

    long sec_adjust = 0;
    if (diff > 25L) {
        // WR is near end of second; NTP's tv_sec is 1 too high (rolled early)
        sec_adjust = -1;
    } else if (diff < -25L) {
        // WR is near start of second; NTP's tv_sec is 1 too low (hasn't rolled)
        sec_adjust = +1;
    }

    return (double)(tv_sec + sec_adjust) + (double)pkt_nsec * 1e-9;
}

// calc_pkt_loss
//
// Return the number of packets lost between the previous observed packet
// number (prev) and the current one (curr), accounting for 16-bit wrap-around.
//
// Special case: if prev == 0xFFFF (the sentinel for "no previous packet seen"),
// return 0 — the first packet can never cause a loss report.
//
// Note: if curr == prev (duplicate packet), the formula yields 65535 (uint16
// underflow), which is the defined behavior and the caller should handle.
//
inline uint16_t calc_pkt_loss(uint16_t prev, uint16_t curr) {
    if (prev == 0xFFFFu) return 0u;   // first packet sentinel — no loss

    if (curr < prev) {
        // 16-bit wrap-around: e.g. prev=65000, curr=50
        return (uint16_t)((0xFFFFu - prev) + curr);
    }
    // Normal case: consecutive or gap (curr - prev - 1 losses)
    return (uint16_t)(curr - prev - 1u);
}

#endif // PANOSETI_PACKET_UTILS_H
