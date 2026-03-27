// test_pff.cpp
// Unit tests for util/pff.h and util/pff.cpp
// No dependency on Hashpipe.

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#include "pff.h"

// ─── bytes_per_pixel ────────────────────────────────────────────────────────

TEST_CASE("bytes_per_pixel returns correct values for all DATA_PRODUCTs", "[pff]") {
    CHECK(bytes_per_pixel(DP_BIT16_IMG)   == 2);
    CHECK(bytes_per_pixel(DP_BIT8_IMG)    == 1);
    CHECK(bytes_per_pixel(DP_PH_256_IMG)  == 2);
    CHECK(bytes_per_pixel(DP_PH_1024_IMG) == 2);
}

TEST_CASE("bytes_per_pixel returns -1 for DP_NONE (invalid)", "[pff]") {
    int result = bytes_per_pixel(DP_NONE);
    CHECK(result == -1);
}

// ─── PFF read/write round-trip ───────────────────────────────────────────────

TEST_CASE("pff write/read round-trip preserves JSON content", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    const char *json = "{\n   \"quabo_0\": { \"pkt_num\":        100 }\n}";

    pff_start_json(f);
    fprintf(f, "%s", json);
    pff_end_json(f);

    rewind(f);

    std::string s;
    int ret = pff_read_json(f, s);
    CHECK(ret == 0);
    CHECK(s.find("quabo_0") != std::string::npos);
    CHECK(s.find("100") != std::string::npos);

    fclose(f);
}

TEST_CASE("pff write/read round-trip preserves binary image data", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    const int NBYTES = 512;
    uint8_t src[NBYTES], dst[NBYTES];
    for (int i = 0; i < NBYTES; i++) src[i] = (uint8_t)(i & 0xff);

    pff_write_image(f, NBYTES, src);

    rewind(f);

    int ret = pff_read_image(f, NBYTES, dst);
    CHECK(ret == 0);
    CHECK(memcmp(src, dst, NBYTES) == 0);

    fclose(f);
}

TEST_CASE("pff header followed by image round-trips correctly", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    // Write a header block then an image block
    pff_start_json(f);
    fprintf(f, "{ \"frame\": 42 }");
    pff_end_json(f);

    const int NBYTES = 256;
    uint8_t src[NBYTES], dst[NBYTES];
    for (int i = 0; i < NBYTES; i++) src[i] = (uint8_t)(i ^ 0xAB);
    pff_write_image(f, NBYTES, src);

    rewind(f);

    std::string json;
    int ret = pff_read_json(f, json);
    CHECK(ret == 0);
    CHECK(json.find("42") != std::string::npos);

    ret = pff_read_image(f, NBYTES, dst);
    CHECK(ret == 0);
    CHECK(memcmp(src, dst, NBYTES) == 0);

    fclose(f);
}

TEST_CASE("pff_read_json returns error on empty file", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);
    std::string s;
    int ret = pff_read_json(f, s);
    CHECK(ret == PFF_ERROR_READ);
    fclose(f);
}

// ─── FILENAME_INFO make/parse round-trip ────────────────────────────────────

TEST_CASE("FILENAME_INFO make_filename / parse_filename round-trip", "[pff]") {
    FILENAME_INFO fi;
    fi.start_time = 1700000000.0;
    fi.data_product = DP_BIT16_IMG;
    fi.bytes_per_pixel = 2;
    fi.module = 42;
    fi.seqno = 7;

    std::string name;
    fi.make_filename(name);

    // The filename must end in .pff
    REQUIRE(ends_with(name.c_str(), ".pff"));

    // Parse it back
    char buf[512];
    strncpy(buf, name.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    FILENAME_INFO fi2;
    fi2.parse_filename(buf);

    CHECK(fi2.data_product    == DP_BIT16_IMG);
    CHECK(fi2.bytes_per_pixel == 2);
    CHECK(fi2.module          == 42);
    CHECK(fi2.seqno           == 7);
}

TEST_CASE("dp_to_str returns expected strings", "[pff]") {
    CHECK(std::string(dp_to_str(DP_BIT16_IMG))   == "img16");
    CHECK(std::string(dp_to_str(DP_BIT8_IMG))    == "img8");
    CHECK(std::string(dp_to_str(DP_PH_256_IMG))  == "ph256");
    CHECK(std::string(dp_to_str(DP_PH_1024_IMG)) == "ph1024");
}

// ─── acq_mode_to_dp ──────────────────────────────────────────────────────────

TEST_CASE("acq_mode_to_dp maps all known acquisition modes correctly", "[pff]") {
    // PH modes (acq_mode 0x01)
    CHECK(acq_mode_to_dp(0x01, 0) == DP_PH_256_IMG);   // no grouping
    CHECK(acq_mode_to_dp(0x01, 1) == DP_PH_1024_IMG);  // grouping enabled

    // 16-bit imaging modes
    CHECK(acq_mode_to_dp(0x02, 0) == DP_BIT16_IMG);
    CHECK(acq_mode_to_dp(0x03, 0) == DP_BIT16_IMG);

    // 8-bit imaging modes
    CHECK(acq_mode_to_dp(0x06, 0) == DP_BIT8_IMG);
    CHECK(acq_mode_to_dp(0x07, 0) == DP_BIT8_IMG);

    // Unknown mode
    CHECK(acq_mode_to_dp(0x00, 0) == DP_NONE);
    CHECK(acq_mode_to_dp(0xFF, 0) == DP_NONE);
}

// ─── is_pff_file ─────────────────────────────────────────────────────────────

TEST_CASE("is_pff_file returns true only for .pff files", "[pff]") {
    CHECK(is_pff_file("foo.pff")               == true);
    CHECK(is_pff_file(".pff")                  == true);
    CHECK(is_pff_file("path/to/data.pff")      == true);
    CHECK(is_pff_file("foo.h5")                == false);
    CHECK(is_pff_file("foo.pffx")              == false);
    CHECK(is_pff_file("foo.pff.gz")            == false);
    CHECK(is_pff_file("pff")                   == false);
    CHECK(is_pff_file("")                      == false);
}

// ─── PFF error cases ─────────────────────────────────────────────────────────

TEST_CASE("pff_read_json returns PFF_ERROR_BAD_TYPE for image-start marker", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    // Write an image block marker where a JSON block is expected
    const char marker = PFF_IMAGE_START;
    fwrite(&marker, 1, 1, f);
    rewind(f);

    std::string s;
    int ret = pff_read_json(f, s);
    CHECK(ret == PFF_ERROR_BAD_TYPE);

    fclose(f);
}

TEST_CASE("pff_read_image returns PFF_ERROR_BAD_TYPE for JSON-start marker", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    // Write a JSON block marker where an image block is expected
    const char marker = PFF_JSON_START;
    fwrite(&marker, 1, 1, f);
    rewind(f);

    uint8_t dst[512] = {};
    int ret = pff_read_image(f, 512, dst);
    CHECK(ret == PFF_ERROR_BAD_TYPE);

    fclose(f);
}

TEST_CASE("pff_read_image returns PFF_ERROR_READ on truncated image data", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    // Write image start but only 4 bytes of data (< requested 512)
    const char marker = PFF_IMAGE_START;
    fwrite(&marker, 1, 1, f);
    const uint8_t short_data[4] = {1, 2, 3, 4};
    fwrite(short_data, 1, 4, f);
    rewind(f);

    uint8_t dst[512] = {};
    int ret = pff_read_image(f, 512, dst);
    CHECK(ret == PFF_ERROR_READ);

    fclose(f);
}

// ─── ends_with edge cases ─────────────────────────────────────────────────────

TEST_CASE("ends_with: empty string returns false", "[pff]") {
    CHECK(ends_with("", ".pff") == false);
    CHECK(ends_with("", "")     == true);
}

TEST_CASE("ends_with: suffix longer than string returns false", "[pff]") {
    CHECK(ends_with("ab", "abc") == false);
}

TEST_CASE("ends_with: suffix equals full string returns true", "[pff]") {
    CHECK(ends_with("foo.pff", "foo.pff") == true);
}

// ─── bytes_per_pixel loop invariant ──────────────────────────────────────────

TEST_CASE("bytes_per_pixel: all valid products return 1 or 2", "[pff]") {
    DATA_PRODUCT valid[] = {DP_BIT16_IMG, DP_BIT8_IMG, DP_PH_256_IMG, DP_PH_1024_IMG};
    for (DATA_PRODUCT dp : valid) {
        int bpp = bytes_per_pixel(dp);
        REQUIRE(bpp > 0);
        REQUIRE(bpp <= 2);
    }
}

TEST_CASE("bytes_per_pixel: DP_NONE returns -1", "[pff]") {
    CHECK(bytes_per_pixel(DP_NONE) == -1);
}

// ─── pff_parse_path ───────────────────────────────────────────────────────────

TEST_CASE("pff_parse_path extracts dir and filename correctly", "[pff]") {
    const char* path =
        "obs_Palomar/run_dir/start_2024-01-01T00_00_00Z.dp_img16.bpp_2.module_5.seqno_0.pff";
    std::string dir, file;
    int ret = pff_parse_path(path, dir, file);
    REQUIRE(ret == 0);
    CHECK(dir  == "run_dir");
    CHECK(file == "start_2024-01-01T00_00_00Z.dp_img16.bpp_2.module_5.seqno_0.pff");
}

TEST_CASE("pff_parse_path returns -1 for path with no slash", "[pff]") {
    std::string dir, file;
    int ret = pff_parse_path("nodir.pff", dir, file);
    CHECK(ret == -1);
}

// ─── pff_read_json skips leading newlines ────────────────────────────────────

TEST_CASE("pff_read_json skips newlines before the opening brace", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    // Write newlines then a JSON block (pff_start_json writes nothing itself)
    const char* prefix = "\n\n";
    fwrite(prefix, 1, strlen(prefix), f);
    pff_start_json(f);
    fprintf(f, "{\"key\": 1}");
    pff_end_json(f);

    rewind(f);

    std::string s;
    int ret = pff_read_json(f, s);
    CHECK(ret == 0);
    CHECK(s.find("key") != std::string::npos);

    fclose(f);
}

// ─── DIRNAME_INFO make/parse round-trip ──────────────────────────────────────

TEST_CASE("DIRNAME_INFO round-trips observatory and run_type for all run types", "[pff]") {
    const char* run_types[] = {"SCI", "CAL", "ENG"};
    const char* obs = "Palomar";
    // Use a fixed time well away from DST transitions for reproducibility
    double t = 1700000000.0;

    for (const char* rt : run_types) {
        DIRNAME_INFO di(t, obs, rt);
        std::string name;
        di.make_dirname(name);
        REQUIRE(!name.empty());

        char buf[512];
        strncpy(buf, name.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        DIRNAME_INFO di2;
        di2.parse_dirname(buf);

        CHECK(di2.observatory == obs);
        CHECK(di2.run_type    == rt);
    }
}

// ─── Multiple frames sequential write/read ───────────────────────────────────

TEST_CASE("pff write/read 20 alternating header+image pairs round-trips correctly", "[pff]") {
    FILE *f = tmpfile();
    REQUIRE(f != nullptr);

    const int N = 20;
    const int NBYTES = 64;
    uint8_t src[N][NBYTES];
    for (int k = 0; k < N; k++)
        for (int b = 0; b < NBYTES; b++)
            src[k][b] = (uint8_t)((k * 7 + b) & 0xff);

    // Write all N pairs
    for (int k = 0; k < N; k++) {
        pff_start_json(f);
        fprintf(f, "{\"frame\": %d}", k);
        pff_end_json(f);
        pff_write_image(f, NBYTES, src[k]);
    }

    rewind(f);

    // Read all N pairs back
    for (int k = 0; k < N; k++) {
        std::string json;
        int ret = pff_read_json(f, json);
        REQUIRE(ret == 0);
        // Verify frame index appears in header
        char expected[32];
        snprintf(expected, sizeof(expected), "%d", k);
        REQUIRE(json.find(expected) != std::string::npos);

        uint8_t dst[NBYTES] = {};
        ret = pff_read_image(f, NBYTES, dst);
        REQUIRE(ret == 0);
        REQUIRE(memcmp(src[k], dst, NBYTES) == 0);
    }

    fclose(f);
}

// ─── FILENAME_INFO seqno preservation ────────────────────────────────────────

TEST_CASE("FILENAME_INFO preserves large seqno (999) through round-trip", "[pff]") {
    FILENAME_INFO fi;
    fi.start_time = 1700000000.0;
    fi.data_product = DP_PH_256_IMG;
    fi.bytes_per_pixel = 2;
    fi.module = 3;
    fi.seqno = 999;

    std::string name;
    fi.make_filename(name);
    REQUIRE(ends_with(name.c_str(), ".pff"));

    char buf[512];
    strncpy(buf, name.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    FILENAME_INFO fi2;
    fi2.parse_filename(buf);
    CHECK(fi2.seqno == 999);
    CHECK(fi2.data_product == DP_PH_256_IMG);
    CHECK(fi2.module == 3);
}

// ─── FILENAME_INFO round-trips for all data products ─────────────────────────

TEST_CASE("FILENAME_INFO round-trips all DATA_PRODUCT values", "[pff]") {
    DATA_PRODUCT dps[] = {DP_BIT16_IMG, DP_BIT8_IMG, DP_PH_256_IMG, DP_PH_1024_IMG};
    int bpps[]         = {2, 1, 2, 2};

    for (int k = 0; k < 4; k++) {
        FILENAME_INFO fi;
        fi.start_time = 1700000000.0;
        fi.data_product = dps[k];
        fi.bytes_per_pixel = bpps[k];
        fi.module = 7;
        fi.seqno = k;

        std::string name;
        fi.make_filename(name);
        REQUIRE(ends_with(name.c_str(), ".pff"));

        char buf[512];
        strncpy(buf, name.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        FILENAME_INFO fi2;
        fi2.parse_filename(buf);

        CHECK(fi2.data_product    == dps[k]);
        CHECK(fi2.bytes_per_pixel == bpps[k]);
        CHECK(fi2.module          == 7);
        CHECK(fi2.seqno           == k);
    }
}
