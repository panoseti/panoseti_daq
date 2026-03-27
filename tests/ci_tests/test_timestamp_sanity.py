# test_timestamp_sanity.py
#
# Verifies that the timestamp fields in PFF JSON headers delivered via UDS
# are physically plausible:
#   - pkt_nsec in [0, 999999999] (nanoseconds within one second)
#   - pkt_tai  > 0               (non-zero TAI counter)
#   - tv_sec   >= 1577836800     (after 2020-01-01 00:00:00 UTC)
#
# Also checks that pkt_tai is non-decreasing across consecutive frames from
# the same (module_id, quabo) pair.

import time
import pytest

from control_util import is_hashpipe_running

NUM_FRAMES   = 100
WAIT_TIMEOUT = 30  # seconds
MIN_TV_SEC   = 1577836800  # 2020-01-01 00:00:00 UTC

@pytest.mark.usefixtures("daq_env")
class TestTimestampSanity:
    def _collect_frames(self, daq_env, dp_name, n, timeout):
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers[dp_name]
        start = time.time()
        while time.time() - start < timeout:
            if srv.frames_received >= n:
                break
            time.sleep(0.5)
        return list(srv.recent_frames[-n:])

    def _check_quabo_header(self, q_hdr, label):
        """Assert one quabo's header fields are sane."""
        pkt_nsec = q_hdr.get("pkt_nsec")
        pkt_tai  = q_hdr.get("pkt_tai")
        tv_sec   = q_hdr.get("tv_sec")

        assert pkt_nsec is not None, f"{label}: pkt_nsec missing"
        assert pkt_tai  is not None, f"{label}: pkt_tai missing"
        assert tv_sec   is not None, f"{label}: tv_sec missing"

        assert 0 <= pkt_nsec <= 999999999, \
            f"{label}: pkt_nsec={pkt_nsec} out of range [0, 999999999]"
        assert pkt_tai > 0, \
            f"{label}: pkt_tai={pkt_tai} must be > 0"
        assert tv_sec >= MIN_TV_SEC, \
            f"{label}: tv_sec={tv_sec} is before 2020-01-01 (implausibly old)"

    def test_ph_frame_timestamps_are_sane(self, daq_env):
        """
        All timestamp fields in PH frames must be within valid ranges.
        """
        ph_dp = daq_env["ph_dp"]
        frames = self._collect_frames(daq_env, ph_dp, NUM_FRAMES, WAIT_TIMEOUT)
        assert len(frames) >= 10, \
            f"Need at least 10 frames for timestamp test, got {len(frames)}"

        for i, frame in enumerate(frames):
            hdr = frame["header"]
            mid = frame["module_id"]
            label = f"frame {i} (module {mid})"

            if ph_dp == "ph256":
                self._check_quabo_header(hdr, label)
            else:  # ph1024
                for q in range(4):
                    q_hdr = hdr.get(f"quabo_{q}", {})
                    if q_hdr:
                        self._check_quabo_header(q_hdr, f"{label} quabo_{q}")

        assert is_hashpipe_running(), "Hashpipe should remain running"

    def test_img16_frame_timestamps_are_sane(self, daq_env):
        """
        All timestamp fields in img16 frames must be within valid ranges.
        """
        frames = self._collect_frames(daq_env, "img16", NUM_FRAMES, WAIT_TIMEOUT)
        if len(frames) < 5:
            pytest.skip(f"Not enough img16 frames ({len(frames)}); skipping")

        for i, frame in enumerate(frames):
            hdr = frame["header"]
            mid = frame["module_id"]
            label = f"img16 frame {i} (module {mid})"

            # img16 header: {"quabo_0": {...}, "quabo_1": {...}, ...}
            for q in range(4):
                q_hdr = hdr.get(f"quabo_{q}", {})
                if q_hdr:
                    self._check_quabo_header(q_hdr, f"{label} quabo_{q}")

        assert is_hashpipe_running(), "Hashpipe should remain running"

    def test_pkt_tai_non_decreasing_per_quabo(self, daq_env):
        """
        pkt_tai must be non-decreasing across consecutive frames from the
        same (module_id, quabo) pair.  We allow for pcap loop restarts
        (large backward jumps are skipped).
        """
        ph_dp = daq_env["ph_dp"]
        frames = self._collect_frames(daq_env, ph_dp, NUM_FRAMES, WAIT_TIMEOUT)
        assert len(frames) >= 10, \
            f"Need at least 10 frames for TAI monotonicity test, got {len(frames)}"

        # Track last pkt_tai per (module_id, quabo_num) key
        last_tai: dict = {}
        # A backward jump of more than RESTART_THR TAI units indicates the
        # tcpreplay loop restarted and replayed from the beginning of the PCAP.
        # Normal inter-frame TAI increments are 0 or 1 unit, so any drop > 5
        # is treated as a loop restart rather than a real ordering violation.
        RESTART_THR = 5

        for frame in frames:
            hdr = frame["header"]
            mid = frame["module_id"]

            if ph_dp == "ph256":
                qnum = hdr.get("quabo_num", 0)
                tai  = hdr.get("pkt_tai")
                if tai is None:
                    continue
                key = (mid, qnum)
                if key in last_tai:
                    diff = tai - last_tai[key]
                    if diff < -RESTART_THR:
                        # pcap loop restart — reset
                        last_tai[key] = tai
                        continue
                    assert diff >= 0, \
                        f"pkt_tai decreased: module {mid} quabo {qnum}: " \
                        f"{last_tai[key]} → {tai}"
                last_tai[key] = tai
            else:
                for q in range(4):
                    q_hdr = hdr.get(f"quabo_{q}", {})
                    tai = q_hdr.get("pkt_tai")
                    if tai is None:
                        continue
                    key = (mid, q)
                    if key in last_tai:
                        diff = tai - last_tai[key]
                        if diff < -RESTART_THR:
                            last_tai[key] = tai
                            continue
                        assert diff >= 0, \
                            f"pkt_tai decreased: module {mid} quabo_{q}: " \
                            f"{last_tai[key]} → {tai}"
                    last_tai[key] = tai

        assert is_hashpipe_running(), "Hashpipe should remain running"
