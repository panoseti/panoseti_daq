# test_image_data_nonzero.py
#
# Verifies that PH frames delivered via UDS carry real (non-trivial) pixel data
# rather than all-zero or all-saturated arrays.
#
# ph256 frames: 16×16 pixels at 2 bytes each = 512 bytes
# img16 frames: 32×32 pixels at 2 bytes each = 2048 bytes  (skipped if no data)
#
# We assert:
#   - The image payload is non-empty.
#   - Not every byte is 0x00 (all-zero image would indicate a dropped/empty frame).
#   - Not every uint16 is 0xFFFF (saturated/corrupted).
#   - At least MIN_NONZERO_FRACTION of uint16 pixels are non-zero.
#
# NOTE: The CI test PCAP contains only PH data, so img16 UDS frames may not
# appear.  img16-specific tests are skipped automatically when no data arrives.

import time
import struct
import pytest

from control_util import is_hashpipe_running

NUM_FRAMES           = 20
WAIT_TIMEOUT         = 30    # seconds
MIN_NONZERO_FRACTION = 0.05  # at least 5% of pixels must be non-zero

@pytest.mark.usefixtures("daq_env")
class TestImageDataNonzero:
    def _collect_frames(self, daq_env, dp_name, n, timeout):
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers[dp_name]
        start = time.time()
        while time.time() - start < timeout:
            if srv.frames_received >= n:
                break
            time.sleep(0.5)
        return list(srv.recent_frames[-n:])

    def _assert_image_nonzero(self, img_bytes, label):
        """Check that img_bytes represents real (non-trivial) pixel data."""
        assert len(img_bytes) > 0, f"{label}: image_data is empty"
        assert any(b != 0 for b in img_bytes), f"{label}: image_data is all zeros"

        if len(img_bytes) >= 2:
            n_pixels = len(img_bytes) // 2
            pixels = struct.unpack(f"<{n_pixels}H", img_bytes[:n_pixels * 2])

            assert not all(p == 0xFFFF for p in pixels), \
                f"{label}: all pixels are 0xFFFF (saturated/corrupted)"

            nonzero = sum(1 for p in pixels if p != 0)
            fraction = nonzero / n_pixels
            assert fraction >= MIN_NONZERO_FRACTION, (
                f"{label}: only {fraction:.1%} of pixels are non-zero "
                f"(minimum {MIN_NONZERO_FRACTION:.0%})"
            )

    def test_ph_frames_carry_nonzero_pixel_data(self, daq_env):
        """
        PH frames must contain real pixel data: not all-zero and not
        all-saturated, with at least MIN_NONZERO_FRACTION non-zero pixels.
        """
        ph_dp = daq_env["ph_dp"]
        frames = self._collect_frames(daq_env, ph_dp, NUM_FRAMES, WAIT_TIMEOUT)
        assert len(frames) >= 5, \
            f"Need at least 5 {ph_dp} frames, got {len(frames)}"

        for i, frame in enumerate(frames):
            img_bytes = frame["image_data"]
            mid = frame["module_id"]
            self._assert_image_nonzero(img_bytes, f"{ph_dp} frame {i} (module {mid})")

        assert is_hashpipe_running(), "Hashpipe should remain running"

    def test_ph_server_receives_frames(self, daq_env):
        """
        Sanity check: the PH UDS server must receive at least some frames.
        """
        ph_dp = daq_env["ph_dp"]
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers[ph_dp]

        start = time.time()
        while time.time() - start < WAIT_TIMEOUT:
            if srv.frames_received >= 5:
                break
            time.sleep(0.5)

        assert srv.frames_received >= 1, \
            f"{ph_dp} UDS server received no frames — PH pipeline may not be running"
        assert is_hashpipe_running(), "Hashpipe should remain running"

    def test_img16_frames_carry_nonzero_pixel_data(self, daq_env):
        """
        img16 frames (if received) must contain real pixel data.
        Skipped when the test PCAP does not contain img16 data.
        """
        frames = self._collect_frames(daq_env, "img16", NUM_FRAMES, WAIT_TIMEOUT)
        if len(frames) < 5:
            pytest.skip(
                f"Only {len(frames)} img16 frames received — "
                "PCAP likely does not contain imaging data"
            )

        for i, frame in enumerate(frames):
            img_bytes = frame["image_data"]
            mid = frame["module_id"]
            self._assert_image_nonzero(img_bytes, f"img16 frame {i} (module {mid})")

        assert is_hashpipe_running(), "Hashpipe should remain running"
