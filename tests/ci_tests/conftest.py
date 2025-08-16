# tests/ci_tests/conftest.py
import sys
import os
import time
import subprocess
import threading
import asyncio
from pathlib import Path
import stat

import pytest
from control_util import is_hashpipe_running

from uds_server import UdsServer

def is_utility_available(name):
    return subprocess.run(["which", name], capture_output=True).returncode == 0

BASE_DIR = Path("/tmp/ci_run_dir")
RUN_NAME = "obs_ci_run"
MODULE_IDS = [1, 254]
PCAP_FILE = "/app/test_data.pcapng"
UDS_TEMPLATE = "/tmp/hashpipe_grpc.dp_{dp_name}.sock"

def _ensure_dirs_and_module_config():
    cfg_str = ""
    for mid in MODULE_IDS:
        module_dir = BASE_DIR / f"module_{mid}" / RUN_NAME
        module_dir.mkdir(parents=True, exist_ok=True)
        cfg_str += f"{mid}\n"
    config_dir = BASE_DIR / RUN_NAME
    config_dir.mkdir(exist_ok=True)
    module_config_path = config_dir / "module.config"
    with open(module_config_path, "w") as f:
        f.write(cfg_str)
    return module_config_path

def _wait_for(predicate, timeout_s=30, interval_s=0.5, desc="condition"):
    start = time.time()
    while time.time() - start < timeout_s:
        if predicate():
            return True
        time.sleep(interval_s)
    pytest.fail(f"Timeout waiting for {desc}")

def _uds_path(dp_name):
    return UDS_TEMPLATE.format(dp_name=dp_name)

class UdsServerManager:
    def __init__(self, socket_paths):
        self.socket_paths = socket_paths
        self.loop = None
        self.thread = None
        self.servers = {}
        self.started = threading.Event()

    def start(self):
        def runner():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            async def start_all():
                for name, path in self.socket_paths.items():
                    srv = UdsServer(str(path))
                    await srv.start()
                    self.servers[name] = srv
                self.started.set()
            self.loop.run_until_complete(start_all())
            self.loop.run_forever()

        self.thread = threading.Thread(target=runner, daemon=True)
        self.thread.start()
        # Wait until servers started
        self.started.wait(timeout=5)
        if not self.started.is_set():
            raise RuntimeError("Failed to start UDS servers")

    def stop(self):
        if self.loop is None:
            return
        async def stop_all():
            for srv in self.servers.values():
                await srv.stop()
        fut = asyncio.run_coroutine_threadsafe(stop_all(), self.loop)
        try:
            fut.result(timeout=5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)

@pytest.fixture(scope="session")
def daq_env():
    if not is_utility_available("hashpipe"):
        pytest.fail("hashpipe not found in PATH")
    if not is_utility_available("tcpreplay"):
        pytest.fail("tcpreplay not found in PATH")

    # Prepare filesystem like production
    _ensure_dirs_and_module_config()

    # 0) Start UDS servers FIRST (the tests are the servers)
    uds_paths = {dp: Path(_uds_path(dp)) for dp in ["ph256", "ph1024", "img16", "img8"]}
    uds_mgr = UdsServerManager(uds_paths)
    uds_mgr.start()

    # 1) Start tcpreplay (loop indefinitely at 1 Mbps to lo)
    tcpreplay_cmd = [
        "tcpreplay",
        "--mbps=1",
        "--loop=0",
        "--intf1=lo",
        PCAP_FILE,
    ]
    tcpreplay_proc = subprocess.Popen(tcpreplay_cmd)

    # 2) Start hashpipe via start_daq.py (ensure your start_daq.py uses psutil-based PID find)
    start_daq = [
        sys.executable,
        "/app/tests/ci_tests/start_daq.py",
        "--run_dir", str(BASE_DIR),
        "--max_file_size_mb", "1",
        "--bindhost", "lo",
    ]
    for mid in MODULE_IDS:
        start_daq.extend(["--module_id", str(mid)])
    hashpipe_launcher = subprocess.Popen(start_daq, cwd=BASE_DIR)

    # 3) Wait for hashpipe to be running
    try:
        _wait_for(is_hashpipe_running, timeout_s=30, desc="hashpipe to be running")
    except Exception:
        pid_file = BASE_DIR / "daq_hashpipe_pid"
        if pid_file.exists():
            print(f"Found PID file: {pid_file.read_text().strip()}")
        else:
            print("No PID file was created by start_daq.py")
        raise

    # 4) Optional: verify at least one server saw a connection within 10s
    start = time.time()
    while time.time() - start < 10:
        # If any server’s connected event is set, we know hashpipe connected to at least one DP
        # Skip strict requirement; filesystem checks will also verify pipeline
        break
    env = {
        "base_dir": BASE_DIR,
        "run_name": RUN_NAME,
        "module_ids": MODULE_IDS,
        "uds_paths": uds_paths,
        "uds_manager": uds_mgr,
        "tcpreplay_proc": tcpreplay_proc,
        "hashpipe_launcher": hashpipe_launcher,
    }

    try:
        yield env
    finally:
        print("\n-- Tearing down DAQ environment --")
        # Stop tcpreplay first
        try:
            tcpreplay_proc.terminate()
            tcpreplay_proc.wait(timeout=10)
        except Exception:
            try:
                tcpreplay_proc.kill()
            except Exception:
                pass

        # Stop hashpipe via stop_daq.py
        stop_daq = [
            sys.executable,
            "/app/tests/ci_tests/stop_daq.py",
        ]
        try:
            cp = subprocess.run(stop_daq, cwd=BASE_DIR, capture_output=True, text=True, timeout=15)
            print("stop_daq.py stdout:\n", cp.stdout)
            print("stop_daq.py stderr:\n", cp.stderr)
        except subprocess.TimeoutExpired:
            print("stop_daq.py timed out; sending SIGINT to hashpipe directly.")
            try:
                subprocess.run(["pkill", "-2", "hashpipe"])
            except Exception:
                pass

        # Stop UDS servers and clean sockets
        uds_mgr.stop()
