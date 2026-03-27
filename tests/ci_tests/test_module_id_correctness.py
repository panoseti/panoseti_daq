# test_module_id_correctness.py
#
# Verifies that the 2-byte big-endian module_id prefix written by Hashpipe
# into every UDS frame belongs to the set of module IDs that were configured
# at startup (MODULE_IDS = [1, 254] in conftest.py).
#
# Frames are read from the UDS server's stored recent_frames, which record
# the decoded module_id alongside the JSON header and image payload.

import time
import pytest

from control_util import is_hashpipe_running

NUM_FRAMES   = 50
WAIT_TIMEOUT = 30   # seconds

@pytest.mark.usefixtures("daq_env")
class TestModuleIdCorrectness:
    def _collect_frames(self, daq_env, dp_name, n, timeout):
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers[dp_name]
        start = time.time()
        while time.time() - start < timeout:
            if srv.frames_received >= n:
                break
            time.sleep(0.5)
        return list(srv.recent_frames[-n:])

    def test_module_ids_are_in_configured_set(self, daq_env):
        """
        All module IDs seen in UDS frames must be from the configured set.
        """
        expected_module_ids = set(daq_env["module_ids"])
        ph_dp = daq_env["ph_dp"]

        frames = self._collect_frames(daq_env, ph_dp, NUM_FRAMES, WAIT_TIMEOUT)
        assert len(frames) >= 5, \
            f"Need at least 5 frames for module_id test, got {len(frames)}"

        seen_module_ids = set()
        for frame in frames:
            mid = frame["module_id"]
            assert isinstance(mid, int), f"module_id must be int, got {type(mid)}"
            assert mid in expected_module_ids, (
                f"Unexpected module_id {mid}; "
                f"expected one of {expected_module_ids}"
            )
            seen_module_ids.add(mid)

        print(f"Observed module_ids: {seen_module_ids} (expected {expected_module_ids})")
        assert is_hashpipe_running(), "Hashpipe should remain running after module_id test"

    def test_img16_module_ids_are_in_configured_set(self, daq_env):
        """
        Module IDs in img16 UDS frames must also be from the configured set.
        """
        expected_module_ids = set(daq_env["module_ids"])

        frames = self._collect_frames(daq_env, "img16", NUM_FRAMES, WAIT_TIMEOUT)
        if len(frames) < 5:
            pytest.skip(f"Not enough img16 frames ({len(frames)}); skipping")

        for frame in frames:
            mid = frame["module_id"]
            assert mid in expected_module_ids, (
                f"Unexpected img16 module_id {mid}; expected {expected_module_ids}"
            )

        assert is_hashpipe_running(), "Hashpipe should remain running"
