// test_net_thread_parsing.cpp
//
// Unit tests for parse_quabo_udp_header() in util/packet_utils.h.
//
// These tests replicate the exact bit-extraction logic of get_header() in
// net_thread.c and verify that each field is decoded correctly from the
// 14-byte Quabo UDP wire format.  A single bit-shift error in get_header()
// would silently corrupt all packet-loss accounting, timestamps, and module
// routing; these tests give us confidence that the logic is correct.
//
// Wire format (from Quabo-packet-interface.md and net_thread.c):
//   Byte  0:    acq_mode
//   Byte  1:    reserved
//   Bytes 2-3:  pkt_num, little-endian uint16
//   Bytes 4-5:  BOARDLOC, little-endian uint16
//               bits[1:0] = quabo_num (0..3)
//               bits[15:2] = mod_num  (0..16383)
//   Bytes 6-7:  pkt_tai, 10 valid bits little-endian
//   Bytes 8-9:  reserved
//   Bytes 10-13: pkt_nsec, little-endian uint32 (0..999 999 999)

#include <catch2/catch_test_macros.hpp>
#include <cstring>

#include "packet_utils.h"

// ─── helpers ─────────────────────────────────────────────────────────────────

// Build a 14-byte packet with all fields zeroed, then set byte 0 (acq_mode).
static void make_pkt(uint8_t pkt[14], uint8_t acq_mode = 0x01) {
    memset(pkt, 0, 14);
    pkt[0] = acq_mode;
}

// Encode mod_num + quabo_num into BOARDLOC and write to bytes [4:5] LE.
static void set_boardloc(uint8_t pkt[14], uint16_t mod_num, uint8_t quabo_num) {
    uint16_t boardloc = (uint16_t)(mod_num * 4u + quabo_num);
    pkt[4] = (uint8_t)(boardloc & 0xFFu);
    pkt[5] = (uint8_t)((boardloc >> 8) & 0xFFu);
}

// ─── acq_mode recognition ────────────────────────────────────────────────────

TEST_CASE("parse_quabo_udp_header: acq_mode 0x01 (PH) → returns true", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x01);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == true);
    CHECK(h.acq_mode == 0x01);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0x02 (16-bit img) → returns true", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x02);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == true);
    CHECK(h.acq_mode == 0x02);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0x03 (simultaneous) → returns true", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x03);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == true);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0x06 (8-bit img) → returns true", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x06);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == true);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0x07 (simultaneous 8-bit) → returns true", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x07);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == true);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0x00 (disabled) → returns false", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0x00);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == false);
    CHECK(h.acq_mode == 0x00);
}

TEST_CASE("parse_quabo_udp_header: acq_mode 0xFF (corrupted) → returns false", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt, 0xFF);
    ParsedQuaboHeader h;
    CHECK(parse_quabo_udp_header(pkt, &h) == false);
    CHECK(h.acq_mode == 0xFF);
}

// ─── pkt_num parsing (little-endian uint16 at bytes [2:3]) ───────────────────

TEST_CASE("parse_quabo_udp_header: pkt_num = 0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0x00; pkt[3] = 0x00;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 0u);
}

TEST_CASE("parse_quabo_udp_header: pkt_num = 1", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0x01; pkt[3] = 0x00;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 1u);
}

TEST_CASE("parse_quabo_udp_header: pkt_num = 65535 (max)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0xFF; pkt[3] = 0xFF;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 65535u);
}

TEST_CASE("parse_quabo_udp_header: pkt_num = 65534", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0xFE; pkt[3] = 0xFF;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 65534u);
}

TEST_CASE("parse_quabo_udp_header: pkt_num = 500", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0xF4; pkt[3] = 0x01;  // 0x01F4 = 500 LE
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 500u);
}

TEST_CASE("parse_quabo_udp_header: pkt_num little-endian correctness (byte2=0x01, byte3=0x02 → 0x0201=513)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[2] = 0x01; pkt[3] = 0x02;  // LE: low byte first → 0x0201 = 513
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_num == 513u);
    // Not 0x0102 = 258 (big-endian would give wrong result)
}

// ─── BOARDLOC / mod_num / quabo_num parsing ──────────────────────────────────

TEST_CASE("parse_quabo_udp_header: module 1 quabo 0 → mod_num=1 quabo_num=0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 1*4+0 = 4 = 0x0004 → byte4=0x04 byte5=0x00
    set_boardloc(pkt, 1, 0);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 1u);
    CHECK(h.quabo_num == 0u);
}

TEST_CASE("parse_quabo_udp_header: module 1 quabo 3 → mod_num=1 quabo_num=3", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 1*4+3 = 7 = 0x0007 → byte4=0x07 byte5=0x00
    set_boardloc(pkt, 1, 3);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 1u);
    CHECK(h.quabo_num == 3u);
}

TEST_CASE("parse_quabo_udp_header: module 254 quabo 0 → mod_num=254 quabo_num=0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 254*4 = 1016 = 0x03F8 → byte4=0xF8 byte5=0x03
    set_boardloc(pkt, 254, 0);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 254u);
    CHECK(h.quabo_num == 0u);
}

TEST_CASE("parse_quabo_udp_header: module 254 quabo 3 → mod_num=254 quabo_num=3", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 254*4+3 = 1019 = 0x03FB → byte4=0xFB byte5=0x03
    set_boardloc(pkt, 254, 3);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 254u);
    CHECK(h.quabo_num == 3u);
}

TEST_CASE("parse_quabo_udp_header: module 255 quabo 3 → mod_num=255 quabo_num=3", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 255*4+3 = 1023 = 0x03FF → byte4=0xFF byte5=0x03
    set_boardloc(pkt, 255, 3);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 255u);
    CHECK(h.quabo_num == 3u);
}

TEST_CASE("parse_quabo_udp_header: module 0 quabo 0 → mod_num=0 quabo_num=0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    set_boardloc(pkt, 0, 0);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 0u);
    CHECK(h.quabo_num == 0u);
}

TEST_CASE("parse_quabo_udp_header: module 0 quabo 1 → mod_num=0 quabo_num=1", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 0*4+1 = 1 → byte4=0x01 byte5=0x00
    set_boardloc(pkt, 0, 1);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 0u);
    CHECK(h.quabo_num == 1u);
}

TEST_CASE("parse_quabo_udp_header: module 128 quabo 0 → mid-range mod_num decodes correctly", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // BOARDLOC = 128*4 = 512 = 0x0200 → byte4=0x00 byte5=0x02
    // quabo_num = byte4 & 0x03 = 0x00 & 0x03 = 0
    // mod_num = (byte5<<6 & 0x3FC0) | (byte4>>2 & 0x003F)
    //         = (0x02<<6 & 0x3FC0) | (0x00>>2 & 0x003F)
    //         = (0x80 & 0x3FC0)    | 0
    //         = 0x80 = 128 ✓
    set_boardloc(pkt, 128, 0);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 128u);
    CHECK(h.quabo_num == 0u);
}

TEST_CASE("parse_quabo_udp_header: quabo_num bits don't pollute mod_num", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // module 63, quabo 3: BOARDLOC = 63*4+3 = 255 = 0x00FF
    // byte4 = 0xFF, byte5 = 0x00
    // quabo_num = 0xFF & 0x03 = 3 ✓
    // mod_num = (0x00<<6 & 0x3FC0) | (0xFF>>2 & 0x003F) = 0 | (0x3F & 0x3F) = 63 ✓
    set_boardloc(pkt, 63, 3);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 63u);
    CHECK(h.quabo_num == 3u);
}

TEST_CASE("parse_quabo_udp_header: high byte5 bits correctly contribute to mod_num", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // module 256, quabo 0: BOARDLOC = 256*4 = 1024 = 0x0400
    // byte4=0x00, byte5=0x04
    // quabo_num = 0x00 & 0x03 = 0 ✓
    // mod_num = (0x04<<6 & 0x3FC0) | (0x00>>2 & 0x003F)
    //         = (0x100 & 0x3FC0)   | 0
    //         = 0x100 = 256 ✓
    set_boardloc(pkt, 256, 0);
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.mod_num == 256u);
    CHECK(h.quabo_num == 0u);
}

// ─── pkt_tai parsing (10-bit LE at bytes [6:7]) ──────────────────────────────

TEST_CASE("parse_quabo_udp_header: pkt_tai = 0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0x00; pkt[7] = 0x00;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 0u);
}

TEST_CASE("parse_quabo_udp_header: pkt_tai = 1", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0x01; pkt[7] = 0x00;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 1u);
}

TEST_CASE("parse_quabo_udp_header: pkt_tai = 255 (single byte max)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0xFF; pkt[7] = 0x00;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 255u);
}

TEST_CASE("parse_quabo_udp_header: pkt_tai = 256 (bit set in byte7)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0x00; pkt[7] = 0x01;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 256u);
}

TEST_CASE("parse_quabo_udp_header: pkt_tai = 1023 (max 10-bit)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0xFF; pkt[7] = 0x03;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 1023u);
}

TEST_CASE("parse_quabo_udp_header: pkt_tai — extra bits in byte7 are masked out", "[net_thread_parsing]") {
    // Only bits[1:0] of byte7 are used (the 0x0300 mask).
    // byte7=0xFF: (0xFF << 8) & 0x0300 = 0xFF00 & 0x0300 = 0x0300 = 768
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[6] = 0x00; pkt[7] = 0xFF;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_tai == 768u);  // only 0x0300 bits survive the mask
}

// ─── pkt_nsec parsing (LE uint32 at bytes [10:13]) ───────────────────────────

TEST_CASE("parse_quabo_udp_header: pkt_nsec = 0", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    // bytes 10-13 already zeroed by make_pkt
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 0u);
}

TEST_CASE("parse_quabo_udp_header: pkt_nsec = 1", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[10] = 0x01;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 1u);
}

TEST_CASE("parse_quabo_udp_header: pkt_nsec = 256 (spans byte10 and byte11)", "[net_thread_parsing]") {
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[10] = 0x00; pkt[11] = 0x01;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 256u);
}

TEST_CASE("parse_quabo_udp_header: pkt_nsec = 500000000 (0x1DCD6500)", "[net_thread_parsing]") {
    // 500,000,000 = 0x1DCD6500
    // LE bytes: 0x00, 0x65, 0xCD, 0x1D
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[10] = 0x00; pkt[11] = 0x65; pkt[12] = 0xCD; pkt[13] = 0x1D;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 500000000u);
}

TEST_CASE("parse_quabo_udp_header: pkt_nsec = 999999999 (0x3B9AC9FF)", "[net_thread_parsing]") {
    // 999,999,999 = 0x3B9AC9FF
    // LE bytes: 0xFF, 0xC9, 0x9A, 0x3B
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[10] = 0xFF; pkt[11] = 0xC9; pkt[12] = 0x9A; pkt[13] = 0x3B;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 999999999u);
}

TEST_CASE("parse_quabo_udp_header: pkt_nsec with high byte bit7 set — no sign-extension UB", "[net_thread_parsing]") {
    // byte13 = 0x80: the original get_header() code does (pkt_data[13] << 24)
    // without a uint32_t cast. On platforms where int is 32 bits, shifting a
    // value of 0x80 left 24 positions sets the sign bit — UB in C.
    // parse_quabo_udp_header uses (uint32_t)pkt_data[13] << 24 which is
    // well-defined and must produce 0x80000000 = 2147483648.
    uint8_t pkt[14]; make_pkt(pkt);
    pkt[10] = 0x00; pkt[11] = 0x00; pkt[12] = 0x00; pkt[13] = 0x80;
    ParsedQuaboHeader h;
    parse_quabo_udp_header(pkt, &h);
    CHECK(h.pkt_nsec == 0x80000000u);  // = 2147483648
}

// ─── Complete packet round-trip tests ────────────────────────────────────────

TEST_CASE("parse_quabo_udp_header: PH round-trip — module 1 quabo 2 pkt_num=100 tai=50 nsec=123456789", "[net_thread_parsing]") {
    // Construct packet matching a representative real-world PH frame.
    // pkt_num = 100 = 0x0064 LE → byte2=0x64 byte3=0x00
    // BOARDLOC = 1*4+2 = 6 = 0x0006 → byte4=0x06 byte5=0x00
    // pkt_tai = 50 = 0x32 → byte6=0x32 byte7=0x00
    // pkt_nsec = 123456789 = 0x075BCD15 → bytes[10:13] LE = 0x15,0xCD,0x5B,0x07
    uint8_t pkt[14]; make_pkt(pkt, 0x01);
    pkt[2] = 0x64; pkt[3] = 0x00;
    pkt[4] = 0x06; pkt[5] = 0x00;
    pkt[6] = 0x32; pkt[7] = 0x00;
    pkt[10] = 0x15; pkt[11] = 0xCD; pkt[12] = 0x5B; pkt[13] = 0x07;

    ParsedQuaboHeader h;
    bool valid = parse_quabo_udp_header(pkt, &h);

    CHECK(valid == true);
    CHECK(h.acq_mode   == 0x01);
    CHECK(h.pkt_num    == 100u);
    CHECK(h.mod_num    == 1u);
    CHECK(h.quabo_num  == 2u);
    CHECK(h.pkt_tai    == 50u);
    CHECK(h.pkt_nsec   == 123456789u);
}

TEST_CASE("parse_quabo_udp_header: img16 round-trip — module 254 quabo 3 pkt_num=65535 tai=1023 nsec=999999999", "[net_thread_parsing]") {
    // module 254, quabo 3: BOARDLOC = 254*4+3 = 1019 = 0x03FB → byte4=0xFB byte5=0x03
    // pkt_num = 65535 = 0xFFFF LE → byte2=0xFF byte3=0xFF
    // pkt_tai = 1023 = 0x3FF → byte6=0xFF byte7=0x03
    // pkt_nsec = 999999999 = 0x3B9AC9FF → LE: byte10=0xFF byte11=0xC9 byte12=0x9A byte13=0x3B
    uint8_t pkt[14]; make_pkt(pkt, 0x02);
    pkt[2] = 0xFF; pkt[3] = 0xFF;
    pkt[4] = 0xFB; pkt[5] = 0x03;
    pkt[6] = 0xFF; pkt[7] = 0x03;
    pkt[10] = 0xFF; pkt[11] = 0xC9; pkt[12] = 0x9A; pkt[13] = 0x3B;

    ParsedQuaboHeader h;
    bool valid = parse_quabo_udp_header(pkt, &h);

    CHECK(valid == true);
    CHECK(h.acq_mode   == 0x02);
    CHECK(h.pkt_num    == 65535u);
    CHECK(h.mod_num    == 254u);
    CHECK(h.quabo_num  == 3u);
    CHECK(h.pkt_tai    == 1023u);
    CHECK(h.pkt_nsec   == 999999999u);
}
