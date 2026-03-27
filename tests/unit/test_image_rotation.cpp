// test_image_rotation.cpp
// Unit tests for util/image.cpp rotation functions.
// No dependency on Hashpipe.
//
// Hardware quabo rotations on the module board:
//   quabo 0 (upper left)  → 90°  CW applied by hardware → undo = 90° CCW
//   quabo 1 (upper right) → 180° CW applied by hardware → undo = 180°
//   quabo 2 (lower right) → 270° CW applied by hardware → undo = 270° CCW
//   quabo 3 (lower left)  → 0°  (no rotation)
//
// Expected output coordinates (32x32 module image):
//   quabo 0: in[i][j]  → out[j][15-i]
//   quabo 1: in[i][j]  → out[15-i][31-j]
//   quabo 2: in[i][j]  → out[31-j][16+i]
//   quabo 3: in[i][j]  → out[16+i][j]

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <cstdint>

#include "image.h"

// Fill a 16x16 image with unique values: pixel (i,j) = i*16 + j + 1
// (offset by 1 so (0,0) is nonzero, making zero-check meaningful)
static void fill_input16(QUABO_IMG16 &img) {
    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            img[i][j] = (uint16_t)(i * QUABO_DIM + j + 1);
}

static void fill_input8(QUABO_IMG8 &img) {
    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            img[i][j] = (uint8_t)(i * QUABO_DIM + j + 1);
}

// ─── quabo16_to_module16_copy ────────────────────────────────────────────────

TEST_CASE("quabo16_to_module16_copy quabo0: pixel (i,j) lands at out[j][15-i]", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_module16_copy(in, 0, out);

    // Spot-check corners
    CHECK(out[0][15] == in[0][0]);   // (0,0) → (0,15)
    CHECK(out[15][15] == in[0][15]); // (0,15) → (15,15)
    CHECK(out[0][0] == in[15][0]);   // (15,0) → (0,0)
    CHECK(out[15][0] == in[15][15]); // (15,15) → (15,0)

    // Full verification
    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[j][15-i] == in[i][j]);
}

TEST_CASE("quabo16_to_module16_copy quabo1: pixel (i,j) lands at out[15-i][31-j]", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_module16_copy(in, 1, out);

    CHECK(out[15][31] == in[0][0]);
    CHECK(out[15][16] == in[0][15]);
    CHECK(out[0][31] == in[15][0]);
    CHECK(out[0][16] == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[15-i][31-j] == in[i][j]);
}

TEST_CASE("quabo16_to_module16_copy quabo2: pixel (i,j) lands at out[31-j][16+i]", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_module16_copy(in, 2, out);

    CHECK(out[31][16] == in[0][0]);
    CHECK(out[16][16] == in[0][15]);
    CHECK(out[31][31] == in[15][0]);
    CHECK(out[16][31] == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[31-j][16+i] == in[i][j]);
}

TEST_CASE("quabo16_to_module16_copy quabo3: pixel (i,j) lands at out[16+i][j]", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_module16_copy(in, 3, out);

    CHECK(out[16][0] == in[0][0]);
    CHECK(out[16][15] == in[0][15]);
    CHECK(out[31][0] == in[15][0]);
    CHECK(out[31][15] == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[16+i][j] == in[i][j]);
}

TEST_CASE("quabo16_to_module16_copy does not write outside the quabo's quadrant", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    // Fill output with a sentinel value
    memset(out, 0xFF, sizeof(out));

    quabo16_to_module16_copy(in, 3, out);  // quabo 3 → lower-left: rows [16,31], cols [0,15]

    // Upper half (rows 0-15) must be untouched (0xFFFF)
    for (int r = 0; r < QUABO_DIM; r++)
        for (int c = 0; c < MODULE_DIM; c++)
            REQUIRE(out[r][c] == 0xFFFF);

    // Right half of lower portion (cols 16-31) must be untouched
    for (int r = QUABO_DIM; r < MODULE_DIM; r++)
        for (int c = QUABO_DIM; c < MODULE_DIM; c++)
            REQUIRE(out[r][c] == 0xFFFF);
}

// ─── quabo8_to_module8_copy ──────────────────────────────────────────────────

TEST_CASE("quabo8_to_module8_copy quabo0: same mapping as 16-bit version", "[image]") {
    QUABO_IMG8 in;
    MODULE_IMG8 out;
    fill_input8(in);
    memset(out, 0, sizeof(out));

    quabo8_to_module8_copy(in, 0, out);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[j][15-i] == in[i][j]);
}

TEST_CASE("quabo8_to_module8_copy quabo3: same mapping as 16-bit version", "[image]") {
    QUABO_IMG8 in;
    MODULE_IMG8 out;
    fill_input8(in);
    memset(out, 0, sizeof(out));

    quabo8_to_module8_copy(in, 3, out);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[16+i][j] == in[i][j]);
}

// ─── All four quabos assemble a complete module image with no overlaps ───────

TEST_CASE("All four quabos fill the 32x32 module image with no overlaps", "[image]") {
    QUABO_IMG16 in0, in1, in2, in3;
    MODULE_IMG16 out;
    memset(out, 0, sizeof(out));

    // Give each quabo a unique base value so any overlap is detectable
    for (int i = 0; i < QUABO_DIM; i++) {
        for (int j = 0; j < QUABO_DIM; j++) {
            in0[i][j] = (uint16_t)(1 * 256 + i * 16 + j);
            in1[i][j] = (uint16_t)(2 * 256 + i * 16 + j);
            in2[i][j] = (uint16_t)(3 * 256 + i * 16 + j);
            in3[i][j] = (uint16_t)(4 * 256 + i * 16 + j);
        }
    }

    quabo16_to_module16_copy(in0, 0, out);
    quabo16_to_module16_copy(in1, 1, out);
    quabo16_to_module16_copy(in2, 2, out);
    quabo16_to_module16_copy(in3, 3, out);

    // Every pixel must be non-zero (all quadrants written)
    for (int r = 0; r < MODULE_DIM; r++)
        for (int c = 0; c < MODULE_DIM; c++)
            REQUIRE(out[r][c] != 0);
}

// ─── quabo8_to_module16_copy ─────────────────────────────────────────────────

TEST_CASE("quabo8_to_module16_copy quabo1: pixel (i,j) lands at out[15-i][31-j]", "[image]") {
    QUABO_IMG8 in;
    MODULE_IMG16 out;
    fill_input8(in);
    memset(out, 0, sizeof(out));

    quabo8_to_module16_copy(in, 1, out);

    CHECK(out[15][31] == in[0][0]);
    CHECK(out[0][16]  == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[15-i][31-j] == in[i][j]);
}

TEST_CASE("quabo8_to_module16_copy quabo2: pixel (i,j) lands at out[31-j][16+i]", "[image]") {
    QUABO_IMG8 in;
    MODULE_IMG16 out;
    fill_input8(in);
    memset(out, 0, sizeof(out));

    quabo8_to_module16_copy(in, 2, out);

    CHECK(out[31][16] == in[0][0]);
    CHECK(out[16][31] == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[31-j][16+i] == in[i][j]);
}

// ─── quabo16_to_quabo16_copy ─────────────────────────────────────────────────
//
// When SRC_DIM == DST_DIM == QUABO_DIM == 16:
//   case 0: out[j][15-i]     — valid 16x16 writes, rows/cols in [0,15]
//   case 1: out[15-i][15-j]  — valid 16x16 writes, rows/cols in [0,15]
//   case 2: out[15-j][16+i]  — col 16+i reaches [16,31], out-of-bounds for a
//                              standalone 16x16 array. In production this function
//                              is called with ph_data->data (2048-byte buffer),
//                              where the overflow lands in the second 512-byte quabo slot.
//   case 3: out[16+i][j]     — row 16+i reaches [16,31], same OOB situation.
//
// Tests here cover only the in-bounds cases (0 and 1). Production usage with the
// 2048-byte PH buffer is covered by the integration tests.

TEST_CASE("quabo16_to_quabo16_copy quabo0: pixel (i,j) lands at out[j][15-i]", "[image]") {
    QUABO_IMG16 in;
    QUABO_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_quabo16_copy(in, 0, out);

    CHECK(out[0][15] == in[0][0]);
    CHECK(out[15][0] == in[15][15]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[j][15-i] == in[i][j]);
}

TEST_CASE("quabo16_to_quabo16_copy quabo1: pixel (i,j) lands at out[15-i][15-j]", "[image]") {
    // Note: DST_DIM=16 here (not 32), so case 1 maps to out[15-i][15-j].
    // This is DIFFERENT from quabo16_to_module16_copy quabo1 which maps to out[15-i][31-j].
    QUABO_IMG16 in;
    QUABO_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_quabo16_copy(in, 1, out);

    CHECK(out[15][15] == in[0][0]);
    CHECK(out[0][0]   == in[15][15]);
    CHECK(out[15][0]  == in[0][15]);
    CHECK(out[0][15]  == in[15][0]);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[15-i][15-j] == in[i][j]);
}

// ─── quabo16_to_module16_add ─────────────────────────────────────────────────

TEST_CASE("quabo16_to_module16_add accumulates with += operator", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    // Write quabo 3 twice — output values should be exactly 2× input
    quabo16_to_module16_add(in, 3, out);
    quabo16_to_module16_add(in, 3, out);

    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[16+i][j] == (uint16_t)(2 * in[i][j]));

    // Pixels in other quadrants must still be zero
    for (int r = 0; r < QUABO_DIM; r++)
        for (int c = 0; c < MODULE_DIM; c++)
            CHECK(out[r][c] == 0);
}

TEST_CASE("quabo16_to_module16_add quabo0: accumulates using rotation case 0", "[image]") {
    QUABO_IMG16 in;
    MODULE_IMG16 out;
    fill_input16(in);
    memset(out, 0, sizeof(out));

    quabo16_to_module16_add(in, 0, out);
    quabo16_to_module16_add(in, 0, out);

    // Result should be 2× the single-copy result
    for (int i = 0; i < QUABO_DIM; i++)
        for (int j = 0; j < QUABO_DIM; j++)
            REQUIRE(out[j][15-i] == (uint16_t)(2 * in[i][j]));
}

// ─── zero_module_img16 ───────────────────────────────────────────────────────

TEST_CASE("zero_module_img16 zeros all pixels", "[image]") {
    MODULE_IMG16 out;
    memset(out, 0xFF, sizeof(out));   // initialize to non-zero sentinel

    // Verify it's non-zero before calling
    CHECK(out[0][0] != 0);

    zero_module_img16(out);

    for (int r = 0; r < MODULE_DIM; r++)
        for (int c = 0; c < MODULE_DIM; c++)
            REQUIRE(out[r][c] == 0);
}
