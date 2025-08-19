import time
from pathlib import Path

import pytest

from status_daq import status
from control_util import is_hashpipe_running

def print_status():
    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print('status on test DAQ node at ', time_str)
    j = status()
    if j['hashpipe_running']:
        print(' hashpipe is running')
    else:
        print(' hashpipe is not running')
    if 'current_run' in j.keys():
        print(' current run:', j['current_run'])
        if 'current_run_disk' in j.keys():
            print(' disk usage:', j['current_run_disk'])
        else:
            print(" run dir doesn't exist")
    else:
        print(' no current run')
    vols = j['vols']
    print(' volumes:')
    for name in vols.keys():
        vol = vols[name]
        print(' name:', name)
        print(' free space: %.8fGB'%(vol['free']/1e9))
        print(' modules:', vol['modules'])

@pytest.mark.usefixtures("daq_env")
def test_hashpipe_valid(daq_env):
    for _ in range(10):
        assert is_hashpipe_running(), "Hashpipe process should be running."
        print_status()
        time.sleep(2)
    assert is_hashpipe_running(), "Hashpipe process should still be running after 20 seconds."

def _latest_pff_mtime(mod_run: Path):
    pffs = list(mod_run.glob("*.pff"))
    if not pffs:
        return None
    return max(p.stat().st_mtime for p in pffs)

@pytest.mark.usefixtures("daq_env")
def test_filesystem_outputs_progress(daq_env):
    base_dir = daq_env["base_dir"]
    run_name = daq_env["run_name"]
    initial = {}
    for mid in daq_env["module_ids"]:
        mod_run = base_dir / f"module_{mid}" / run_name
        mod_run.mkdir(parents=True, exist_ok=True)
        initial[mid] = _latest_pff_mtime(mod_run)
    time.sleep(3)
    progressed = False
    for mid in daq_env["module_ids"]:
        mod_run = base_dir / f"module_{mid}" / run_name
        later = _latest_pff_mtime(mod_run)
        if (initial[mid] is None and later is not None) or (later is not None and later > (initial[mid] or 0)):
            progressed = True
    assert progressed, "Expected at least one module to have updated PFF outputs."

@pytest.mark.usefixtures("daq_env")
def test_uds_ph_frames(daq_env):
    """
    The tests act as the UDS SERVER. Verify that the ph256 or ph1024 server accepted a connection
    and received at least one frame from hashpipe within a reasonable time.
    """
    uds_mgr = daq_env["uds_manager"]
    ph_dp = daq_env["ph_dp"]
    srv = uds_mgr.servers[ph_dp]

    # Wait up to 10s for a client connection (hashpipe)
    start = time.time()
    connected = False
    while time.time() - start < 10:
        if srv.connected.is_set():
            connected = True
            break
        time.sleep(0.2)
    assert connected, f"{ph_dp} UDS server did not receive a connection from hashpipe within 10s"

    # Wait a bit for at least one frame
    start = time.time()
    while time.time() - start < 10 and srv.frames_received == 0:
        time.sleep(0.2)
    assert srv.frames_received > 0, f"{ph_dp} UDS server did not receive any frames within 10s"

# @pytest.mark.usefixtures("daq_env")
# def test_uds_img16_frames(daq_env):
#     """
#     Similarly validate img16 server connectivity and frame reception.
#     """
#     uds_mgr = daq_env["uds_manager"]
#     srv = uds_mgr.servers["img16"]

#     start = time.time()
#     connected = False
#     while time.time() - start < 10:
#         if srv.connected.is_set():
#             connected = True
#             break
#         time.sleep(0.2)
#     assert connected, "img16 UDS server did not receive a connection from hashpipe within 10s"

#     start = time.time()
#     while time.time() - start < 10 and srv.frames_received == 0:
#         time.sleep(0.2)
#     assert srv.frames_received > 0, "img16 UDS server did not receive any frames within 10s"
