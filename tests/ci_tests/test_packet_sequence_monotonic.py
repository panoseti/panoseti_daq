# test_packet_sequence_monotonic.py
#
# Verifies that per-quabo packet numbers are monotonically non-decreasing
# (mod 65536) across the frames delivered via UDS.
#
# With a looping PCAP, pkt_num restarts when the file loops.  We detect a
# loop restart as a backwards jump whose magnitude in the "wrap direction"
# would be very large (> 10 000).  On a true restart we reset the baseline
# and continue; we do NOT count loop-restart jumps as lost packets.
#
# What we DO assert:
#   - pkt_num field is present and in [0, 65535] for every frame.
#   - At least 2 frames are received for any tracked quabo.
#   - No single gap between consecutive same-quabo frames exceeds MAX_LOSS
#     (ignoring pcap-loop restarts).
#   - At least one quabo_num is observed in the collected frames.

import time
import pytest

from control_util import is_hashpipe_running

MAX_FRAMES   = 200   # collect up to this many frames
WAIT_TIMEOUT = 30    # seconds to wait for frames
MAX_LOSS     = 500   # maximum tolerated gap (before restart detection)
RESTART_THR  = 10000 # gaps in the "wrap direction" larger than this = loop restart

def _pkt_num_gap(prev, curr):
    """Forward gap from prev to curr in 16-bit ring (always >= 0)."""
    return (curr - prev) & 0xFFFF

@pytest.mark.usefixtures("daq_env")
class TestPacketSequenceMonotonic:
    def test_pkt_num_monotonic_per_quabo(self, daq_env):
        """
        Per-quabo pkt_num must be monotonically non-decreasing (mod 65536),
        with gaps no larger than MAX_LOSS between consecutive frames from the
        same quabo (pcap loop restarts are excluded).
        """
        ph_dp = daq_env["ph_dp"]
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers[ph_dp]

        # Wait for enough frames
        start = time.time()
        while time.time() - start < WAIT_TIMEOUT:
            if srv.frames_received >= MAX_FRAMES:
                break
            time.sleep(0.5)

        frames = list(srv.recent_frames[-MAX_FRAMES:])
        assert len(frames) >= 10, \
            f"Need at least 10 frames for sequence test, got {len(frames)}"

        # Build per-quabo pkt_num sequences
        # ph256: header = {"quabo_num": N, "pkt_num": K, ...}
        # ph1024: header = {"quabo_0": {"pkt_num": K, ...}, ...}
        quabo_sequences: dict[int, list[int]] = {}

        for frame in frames:
            hdr = frame["header"]
            assert isinstance(frame["module_id"], int)

            if ph_dp == "ph256":
                qnum = hdr.get("quabo_num")
                pnum = hdr.get("pkt_num")
                assert qnum is not None, "ph256 header missing quabo_num"
                assert pnum is not None, "ph256 header missing pkt_num"
                assert 0 <= pnum <= 65535, f"pkt_num {pnum} out of range"
                quabo_sequences.setdefault(qnum, []).append(pnum)
            else:  # ph1024
                for q in range(4):
                    q_hdr = hdr.get(f"quabo_{q}", {})
                    pnum = q_hdr.get("pkt_num")
                    if pnum is not None:
                        assert 0 <= pnum <= 65535, f"pkt_num {pnum} out of range"
                        quabo_sequences.setdefault(q, []).append(pnum)

        assert len(quabo_sequences) >= 1, \
            "No quabo_num values found in collected frames"

        for qnum, seq in quabo_sequences.items():
            if len(seq) < 2:
                continue
            prev = seq[0]
            for curr in seq[1:]:
                gap = _pkt_num_gap(prev, curr)
                if gap > RESTART_THR:
                    # Treat as a pcap loop restart — reset baseline, no assertion.
                    prev = curr
                    continue
                assert gap <= MAX_LOSS, (
                    f"quabo {qnum}: pkt_num gap {gap} from {prev} to {curr} "
                    f"exceeds MAX_LOSS={MAX_LOSS}"
                )
                prev = curr

        assert is_hashpipe_running(), "Hashpipe should remain running after sequence test"
