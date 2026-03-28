// util/packet_utils.h
// Pure inline utilities for timestamp reconciliation, packet-loss accounting,
// Quabo UDP wire-header parsing, and board-location validation.
// No Hashpipe dependency — safe to include in unit tests.

#ifndef PANOSETI_PACKET_UTILS_H
#define PANOSETI_PACKET_UTILS_H

#include <stdint.h>
#include <sys/time.h>
#include <stdbool.h>

// ─── reconcile_timestamp ──────────────────────────────────────────────────────
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

// ─── calc_pkt_loss ────────────────────────────────────────────────────────────
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

// ─── timeval_diff ─────────────────────────────────────────────────────────────
//
// Return the time difference (end - start) in microseconds.
// If end < start the result wraps (no error is signalled).
//
// Note: snapshot.c exports a non-inline version with the same logic for use by
// production code. This static inline version is provided here for unit tests.
//
static inline uint64_t timeval_diff_us(const struct timeval *start, const struct timeval *end) {
    struct timeval diff;
    diff.tv_sec  = end->tv_sec  - start->tv_sec;
    diff.tv_usec = end->tv_usec - start->tv_usec;

    if (diff.tv_usec < 0) {
        diff.tv_sec  -= 1;
        diff.tv_usec += 1000000;
    }
    return (uint64_t)diff.tv_sec * 1000000u + (uint64_t)diff.tv_usec;
}

// ─── Packet validation helpers ────────────────────────────────────────────────
//
// Size of per-quabo tracking arrays in compute_thread (NUM_OF_MODES + 1 = 8).
// Valid acq_mode indices: 0..7; values 0x08–0xFF are OOB.
//
#define PACKET_UTILS_NUM_OF_MODES 7u

// Returns true if acq_mode is a valid index into per-quabo tracking arrays.
// Science acq_mode values per hardware docs: 0x01, 0x02, 0x03, 0x06, 0x07.
// 0x00 (disabled) and 0x08–0xFF are invalid science modes but 0x00 maps to a
// valid array index, so this function only rejects values > 7.
//
inline bool is_valid_acq_mode(uint8_t acq_mode) {
    return acq_mode <= PACKET_UTILS_NUM_OF_MODES;
}

// Maximum valid boardLoc for quaboInd[] (array size 0xFFFF = 65535;
// valid indices are 0..65534).
//
#define PACKET_UTILS_MAX_MODULE_INDEX 0xFFFFu

// Compute boardLoc = mod_num * 4 + quabo_num using uint32_t arithmetic
// to prevent the uint16_t wrap-around that occurs when mod_num >= 16384.
//
inline uint32_t calc_board_loc(uint16_t mod_num, uint8_t quabo_num) {
    return (uint32_t)mod_num * 4u + (uint32_t)quabo_num;
}

// Returns true if boardLoc is a valid index into quaboInd[].
//
inline bool is_valid_board_loc(uint32_t boardLoc) {
    return boardLoc < PACKET_UTILS_MAX_MODULE_INDEX;
}

// ─── Quabo UDP wire-header parser ─────────────────────────────────────────────
//
// Parsed representation of a Quabo UDP packet wire header.
// Field layout mirrors PACKET_HEADER in databuf.h; keep in sync.
//
// Wire format (14 bytes, from Quabo-packet-interface.md and net_thread.c):
//   Byte  0:    acq_mode
//   Byte  1:    reserved
//   Bytes 2-3:  pkt_num, little-endian uint16
//   Bytes 4-5:  BOARDLOC, little-endian uint16
//               bits[1:0] = quabo_num (0..3)
//               bits[15:2] = mod_num (0..16383)
//   Bytes 6-7:  pkt_tai, 10 valid bits little-endian
//               byte6 = bits[7:0], byte7 bits[1:0] = bits[9:8]
//   Bytes 8-9:  reserved
//   Bytes 10-13: pkt_nsec, little-endian uint32 (0..999 999 999)
//
typedef struct {
    uint8_t  acq_mode;    // byte 0
    uint16_t pkt_num;     // bytes [2:3] little-endian
    uint16_t mod_num;     // bits [15:2] of BOARDLOC word (bytes [4:5] LE)
    uint8_t  quabo_num;   // bits [1:0] of BOARDLOC word (byte 4)
    uint32_t pkt_tai;     // 10 valid bits at bytes [6:7] little-endian
    uint32_t pkt_nsec;    // bytes [10:13] little-endian (0..999 999 999)
} ParsedQuaboHeader;

// Parse the 14-byte Quabo UDP wire header starting at pkt_data[0].
// Returns true if acq_mode is a recognized science mode (0x01,0x02,0x03,0x06,0x07).
// Byte 1 and bytes 8-9 are reserved and not parsed.
// All shifts use explicit uint32_t casts to avoid signed-integer shift UB.
//
inline bool parse_quabo_udp_header(const uint8_t *pkt_data, ParsedQuaboHeader *out) {
    out->acq_mode = pkt_data[0];

    // pkt_num: little-endian 16-bit at bytes [2:3]
    out->pkt_num = ((uint16_t)pkt_data[3] << 8) | (uint16_t)pkt_data[2];

    // BOARDLOC: little-endian 16-bit at bytes [4:5]
    // quabo_num = bits[1:0] of byte4
    // mod_num   = bits[15:2] of BOARDLOC = (byte5 << 6) | (byte4 >> 2)
    out->quabo_num = pkt_data[4] & 0x03u;
    out->mod_num   = (((uint16_t)pkt_data[5] << 6) & 0x3FC0u)
                   | (((uint16_t)pkt_data[4] >> 2) & 0x003Fu);

    // pkt_tai: 10 valid bits, little-endian at bytes [6:7]
    // byte6 = bits[7:0], byte7 bits[1:0] = bits[9:8]
    out->pkt_tai = (((uint32_t)pkt_data[7] << 8) & 0x00000300u)
                 |  (uint32_t)pkt_data[6];

    // pkt_nsec: 32-bit little-endian at bytes [10:13].
    // uint32_t casts prevent implementation-defined signed-shift UB when
    // byte13 >= 0x80 on platforms with 32-bit int.
    out->pkt_nsec = ((uint32_t)pkt_data[13] << 24)
                  | ((uint32_t)pkt_data[12] << 16)
                  | ((uint32_t)pkt_data[11] <<  8)
                  |  (uint32_t)pkt_data[10];

    return (out->acq_mode == 0x01 || out->acq_mode == 0x02
         || out->acq_mode == 0x03 || out->acq_mode == 0x06
         || out->acq_mode == 0x07);
}

#endif // PANOSETI_PACKET_UTILS_H
