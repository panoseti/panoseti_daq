import os
import time
import socket
import asyncio
import stat
import threading
from pathlib import Path
from typing import Optional, Set

import pytest

from control_util import is_hashpipe_running
from uds_server import UdsServer

# Reuse the same UDS template used by hashpipe snapshot.c
UDS_TEMPLATE = "/tmp/hashpipe_grpc.dp_{dp}.sock"
DPS = ["ph256", "ph1024", "img16", "img8"]

def uds_path(dp):
    return UDS_TEMPLATE.format(dp=dp)

def _wait_for(predicate, timeout_s=10, interval_s=0.1):
    start = time.time()
    while time.time() - start < timeout_s:
        if predicate():
            return True
        time.sleep(interval_s)
    return False

def _uds_exists(path):
    return os.path.exists(path) and stat.S_ISSOCK(os.stat(path).st_mode)

def _wait_for_any_server_connection(uds_mgr, timeout_s=10):
    start = time.time()
    while time.time() - start < timeout_s:
        for srv in uds_mgr.servers.values():
            if srv.connected.is_set():
                return True
        time.sleep(0.1)
    return False

@pytest.mark.usefixtures("daq_env")
class TestUdsResilience:
    # 1) UDS sockets don't exist at hashpipe startup
    # Expectation: Hashpipe should not crash and should continue to run, dropping frames until sockets appear.
    def test_no_uds_sockets_at_start(self, daq_env):
        # In daq_env fixture, servers are started before hashpipe; stop them to simulate "no sockets"
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        # Ensure sockets are gone
        for dp in DPS:
            p = uds_path(dp)
            if os.path.exists(p):
                if stat.S_ISSOCK(os.stat(p).st_mode):
                    os.unlink(p)
                else:
                    raise RuntimeError(f"{p} exists and is not a socket")

        # Hashpipe is already started by fixture; ensure it's still running after a delay
        assert is_hashpipe_running(), "Hashpipe should be running even with no UDS sockets at start."
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe should remain running with no UDS sockets."

    # 2) UDS sockets created only after Hashpipe starts
    # Expectation: Hashpipe periodically attempts non-blocking connect; when sockets appear, it connects and streams without crashing.
    def test_sockets_created_after_start(self, daq_env):
        # First ensure no servers/sockets
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()
        for dp in DPS:
            p = uds_path(dp)
            if os.path.exists(p):
                os.unlink(p)

        assert is_hashpipe_running(), "Hashpipe should be running prior to late socket creation."

        # Start servers now (late)
        uds_paths = {dp: Path(uds_path(dp)) for dp in DPS}
        late_mgr = UdsServerManager(uds_paths)
        late_mgr.start()

        # Hashpipe should connect to at least one server within a few seconds
        assert _wait_for_any_server_connection(late_mgr, timeout_s=15), "Expected late UDS connections to succeed."

        # Let data flow a bit; ensure hashpipe remains alive
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe should keep running after late socket creation."

        # Cleanup late manager
        late_mgr.stop()

    # 3) UDS sockets exist before Hashpipe starts
    # Expectation: Existing sockets allow immediate connect; frames increment and no crash.
    def test_sockets_exist_before_start(self, daq_env):
        # This scenario is already the default setup of daq_env: servers start before hashpipe.
        # Just verify connection and frame receipt without crashes.
        uds_mgr = daq_env["uds_manager"]
        assert _wait_for_any_server_connection(uds_mgr, timeout_s=10), "Expected early UDS connection."

        # Wait for at least one server to receive frames
        start = time.time()
        while time.time() - start < 10:
            if any(srv.frames_received > 0 for srv in uds_mgr.servers.values()):
                break
            time.sleep(0.2)

        assert any(srv.frames_received > 0 for srv in uds_mgr.servers.values()), "Expected at least one UDS frame."
        assert is_hashpipe_running(), "Hashpipe should be running with pre-existing sockets."

    # 4) UDS sockets improperly closed immediately after connection
    # Expectation: Hashpipe handles EPIPE/ECONNRESET/EBADF, closes fd, and keeps running (drops frames until reconnect).
    def test_immediate_close_after_connect(self, daq_env):
        uds_mgr = daq_env["uds_manager"]

        # Wait for initial connection
        assert _wait_for_any_server_connection(uds_mgr, timeout_s=10), "Expected initial UDS connection."

        # Stop server to force EPIPE/ECONNRESET on writer side shortly after connect
        uds_mgr.stop()

        # Let hashpipe attempt to write and observe no crash
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe must not crash when server closes immediately after connect."

        # Restart servers so writer can reconnect on subsequent writes
        uds_paths = {dp: Path(uds_path(dp)) for dp in DPS}
        uds_mgr2 = UdsServerManager(uds_paths)
        uds_mgr2.start()
        assert _wait_for_any_server_connection(uds_mgr2, timeout_s=15), "Expected reconnect after server restart."

        # Let frames flow, ensure still alive
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe remains running after reconnect."
        uds_mgr2.stop()

    # 5) UDS sockets closed while hashpipe is running (mid-run disconnect)
    # Expectation: net_thread detects idle sockets, closes fds, writer tolerates disconnect; hashpipe keeps running.
    def test_midrun_disconnect(self, daq_env):
        uds_mgr = daq_env["uds_manager"]
        assert _wait_for_any_server_connection(uds_mgr, timeout_s=10), "Expected initial connection."

        # Disconnect mid-run
        uds_mgr.stop()

        # Allow hashpipe to encounter write errors / idle detection
        time.sleep(4)  # > UDS_IDLE_CHECK_PERIOD_US and near timeout window

        # Still alive
        assert is_hashpipe_running(), "Hashpipe must not crash on mid-run UDS disconnects."

        # Recreate servers and expect reconnection
        uds_paths = {dp: Path(uds_path(dp)) for dp in DPS}
        uds_mgr2 = UdsServerManager(uds_paths)
        uds_mgr2.start()
        assert _wait_for_any_server_connection(uds_mgr2, timeout_s=15), "Expected reconnection after mid-run disconnect."

        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe remains alive after reconnection."
        uds_mgr2.stop()

    # 6) UDS sockets exist but fill up (receiver stops reading; EAGAIN/EWOULDBLOCK path)
    # Expectation: Hashpipe handles EAGAIN/EWOULDBLOCK by dropping frames; process keeps running.
    def test_socket_backpressure_eagain(self, daq_env):
        # Create a "busy" server that accepts the connection but never reads,
        # causing the sender's socket buffer to fill and writev to return EAGAIN.
        class BusyNoReadServer:
            def __init__(self, socket_path):
                self.socket_path = socket_path
                self.server = None
                self.loop = None
                self.thread: Optional[threading.Thread] = None
                self.started = threading.Event()
                self._client_tasks: Set[asyncio.Task] = set()

            def start(self):
                def runner():
                    self.loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.loop)
                    self.loop.run_until_complete(self._start())
                    self.started.set()
                    self.loop.run_forever()
                self.thread = threading.Thread(target=runner, daemon=True)
                self.thread.start()
                self.started.wait(timeout=5)
                if not self.started.is_set():
                    raise RuntimeError("Failed to start BusyNoReadServer")

            async def _start(self):
                try:
                    if os.path.exists(self.socket_path):
                        s = os.stat(self.socket_path)
                        if stat.S_ISSOCK(s.st_mode):
                            os.unlink(self.socket_path)
                        else:
                            raise RuntimeError(f"{self.socket_path} exists and is not a socket")
                except Exception:
                    raise
                self.server = await asyncio.start_unix_server(self._client_wrapper, path=self.socket_path)

            async def _client_wrapper(self, reader, writer):
                """Wrapper to track client tasks for proper cleanup"""
                task = asyncio.create_task(self._handle(reader, writer))
                self._client_tasks.add(task)
                task.add_done_callback(lambda t: self._client_tasks.discard(t))

            async def _handle(self, reader, writer):
                # Accept connection and never read; leave it hanging so sender buffer fills.
                try:
                    # Keep the connection open but do not read.
                    while True:
                        await asyncio.sleep(1.0)
                except asyncio.CancelledError:
                    # Handle cancellation gracefully
                    pass
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            def stop(self):
                if not self.loop:
                    return

                async def _stop():
                    # Cancel all client tasks first
                    tasks = list(self._client_tasks)
                    for task in tasks:
                        task.cancel()
                    
                    # Wait for tasks to complete cancellation
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Close the server
                    if self.server:
                        self.server.close()
                        try:
                            await self.server.wait_closed()
                        except Exception:
                            pass

                fut = asyncio.run_coroutine_threadsafe(_stop(), self.loop)
                try:
                    fut.result(timeout=10)  # Increased timeout for proper cleanup
                except Exception:
                    pass
                self.loop.call_soon_threadsafe(self.loop.stop)
                if self.thread:
                    self.thread.join(timeout=10)
                try:
                    if os.path.exists(self.socket_path):
                        os.unlink(self.socket_path)
                except Exception:
                    pass

        # Tear down the normal servers so we control one DP explicitly
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        # Start a BusyNoRead server for ph256 only; leave others absent to focus on a filled socket path
        ph_path = uds_path("ph256")
        busy_srv = BusyNoReadServer(ph_path)
        busy_srv.start()

        # Confirm hashpipe running, and give it time to connect and attempt writes
        assert is_hashpipe_running(), "Hashpipe should be running before backpressure."
        # Wait for connection file to exist (connect is non-blocking; we can poll by file presence)
        assert _wait_for(lambda: _uds_exists(ph_path), timeout_s=5), "Busy server socket file should exist."

        # Allow some time for sender to fill the socket and hit EAGAIN
        time.sleep(4)

        # Hashpipe should not crash despite backpressure
        assert is_hashpipe_running(), "Hashpipe must not crash when UDS socket buffers fill (EAGAIN)."

        # Cleanup busy server properly
        busy_srv.stop()
        
        # Give hashpipe time to detect the closed connection and clean up its state
        time.sleep(2)

        # Optionally, bring back regular servers and see that it still runs
        uds_paths = {dp: Path(uds_path(dp)) for dp in DPS}
        mgr2 = UdsServerManager(uds_paths)
        mgr2.start()
        assert _wait_for_any_server_connection(mgr2, timeout_s=15), "Expected reconnect to normal servers."
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe remains running after backpressure scenario."
        mgr2.stop()


# Local import to avoid circular references at top
from conftest import UdsServerManager
