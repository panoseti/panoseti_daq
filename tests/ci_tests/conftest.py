
import sys
import os
import signal
import time
from pathlib import Path
import pytest
import subprocess

from control_util import is_hashpipe_running

def is_utility_available(name):
    """Check if a command-line utility is in the system PATH."""
    return subprocess.run(["which", name], capture_output=True).returncode == 0


@pytest.fixture(scope="session")
def hashpipe_pcap_runner():
    """
    A session-scoped fixture that creates a realistic hashpipe run environment,
    starts tcpreplay to feed it data from a pcap file, and launches the
    hashpipe process with command-line arguments that mimic a production run.

    This enables testing of the data flow:
    tcpreplay -> hashpipe (net_thread) 
    """
    if not is_utility_available("hashpipe") or not is_utility_available("tcpreplay"):
        pytest.fail("Required utility 'hashpipe' or 'tcpreplay' not found in PATH.")

    # 1. Define Paths and Configuration
    pcap_file = "/app/test_data.pcapng"

    # Define a base directory for the test, which will be the Current Working Directory (CWD)
    # for the hashpipe process. This matches the behavior of the production start_daq.py script.
    base_dir = Path("/tmp/ci_run_dir")

    # Define a relative run name. It must start with "obs_" for the server to find it.
    run_name = "obs_ci_run"

    # Create the directory structure that `make_run_dirs` in start.py would create.
    module_ids = [1, 254]
    cfg_str = ""
    for mid in module_ids:
        module_dir = base_dir / "module_{}".format(mid) / run_name
        module_dir.mkdir(parents=True, exist_ok=True)
        cfg_str += f"{mid}\n"

    # The config file for hashpipe goes in base_dir/run_name/
    config_dir = base_dir / run_name
    config_dir.mkdir(exist_ok=True)

    # The module.config file tells hashpipe which module to listen for.
    module_config_path = config_dir / "module.config"
    with open(module_config_path, "w") as f:
        f.write(cfg_str)

    # 2. Build commands 
    # Command to loop the pcap file to the loopback interface, simulating network traffic.
    tcpreplay_cmd = [
        "tcpreplay",
        "--mbps=1",
        "--loop=0",  # Loop indefinitely
        "--intf1=lo",  # Send to loopback interface
        pcap_file
    ]

    hashpipe_cmd = [
        "hashpipe",
        "-p", "hashpipe.so",
        "-I", "0",
        "-o", "BINDHOST=lo",
        "-o", f"RUNDIR={run_name}",
        "-o", f"CONFIG={run_name}/module.config",
        "-o", "MAXFILESIZE=1",
        "-o", "GROUPPHFRAMES=0",
        "-o", "OBS=TEST",
        "net_thread", "compute_thread", "output_thread"
    ]

    # 3. Start processes 
    # Start tcpreplay to generate UDP packets.
    tcpreplay_proc = subprocess.Popen(tcpreplay_cmd)#, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Start the hashpipe process with the CWD set to the base directory.
    hashpipe_proc = subprocess.Popen(
        hashpipe_cmd,
        cwd=base_dir
    )

    # 4. Wait for initialization and validation 
    num_retries = 20
    for i in range(num_retries):
        # Allow time for processes to initialize and sockets to be created.
        if tcpreplay_proc.poll() is not None:
            pytest.fail(f"tcpreplay failed to start. Exit code: {tcpreplay_proc.returncode}")
        elif hashpipe_proc.poll() is not None:
            pytest.fail(f"hashpipe failed to start. Exit code: {hashpipe_proc.returncode}. Check logs in {base_dir}.")
        if is_hashpipe_running():
            print(f"hashpipe is running after {i} retries.")
            break
        print(f"hashpipe is not running after {i}/{num_retries} retries. Retrying in 1 second.")
        time.sleep(1)
    else:
        pytest.fail(f"hashpipe failed to start after {num_retries} retries. Check logs in {base_dir}.")

    # Yield to let the tests run
    yield

    # 5. Teardown
    print("\n-- Tearing down hashpipe and tcpreplay processes --")

    # First, stop tcpreplay so it stops feeding data.
    tcpreplay_proc.terminate()
    try:
        tcpreplay_proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        tcpreplay_proc.kill()

    # Now, run stop_daq.py to gracefully shut down hashpipe.
    # The Dockerfile places project source code in /app.
    stop_daq_script_path = "/app/panoseti_util/stop_daq.py"
    if os.path.exists(stop_daq_script_path):
        print(f"-- Running {stop_daq_script_path} in {base_dir} --")
        # stop_daq.py expects to be run from the data dir (which is our run_dir)
        # and reads the PID from a file in its cwd.
        try:
            completed_process = subprocess.run(
                [sys.executable, stop_daq_script_path],
                cwd=base_dir,
                capture_output=True,
                text=True,
                timeout=10  # Add a timeout to prevent hanging
            )
            print(f"stop_daq.py stdout:\n{completed_process.stdout}")
            print(f"stop_daq.py stderr:\n{completed_process.stderr}")
            if completed_process.returncode != 0:
                # If it fails, fall back to killing the process directly.
                print("stop_daq.py failed, falling back to direct process termination.")
                if hashpipe_proc.poll() is None:
                    hashpipe_proc.send_signal(signal.SIGINT)  # Graceful shutdown
                    try:
                        hashpipe_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        hashpipe_proc.kill()  # Forceful shutdown
        except subprocess.TimeoutExpired:
            print("stop_daq.py timed out. Killing hashpipe process directly.")
            if hashpipe_proc.poll() is None:
                hashpipe_proc.kill()
    else:
        print(f"{stop_daq_script_path} not found. Terminating hashpipe process directly.")
        # Fallback to original method if script is not found.
        if hashpipe_proc.poll() is None:
            hashpipe_proc.send_signal(signal.SIGINT)  # Graceful shutdown
            try:
                hashpipe_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hashpipe_proc.kill()  # Forceful shutdown

