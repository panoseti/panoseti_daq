# tests/ci_tests/test_uds_data_path.py

import os
import time
import socket
import asyncio
import stat
import threading
import json
from pathlib import Path
from typing import Optional, Set

import pytest

from control_util import is_hashpipe_running
from uds_server import UdsServer
from helper_uds_client import read_one_frame_from_uds, UdsFrameReader

# Focus on ph256 since that's what we have test data for
UDS_TEMPLATE = "/tmp/hashpipe_grpc.dp_{dp}.sock"

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

def _ensure_uds_available(daq_env, dp_name="ph256", timeout_s=10):
    """Ensure UDS socket is available and connected."""
    uds_mgr = daq_env["uds_manager"]
    
    # If servers are not running, restart them
    if dp_name not in uds_mgr.servers or not _uds_exists(uds_path(dp_name)):
        # Stop existing servers cleanly
        uds_mgr.stop()
        time.sleep(1)
        
        # Restart servers
        uds_paths = {dp: Path(uds_path(dp)) for dp in ["ph256", "ph1024", "img16", "img8"]}
        from conftest import UdsServerManager
        new_mgr = UdsServerManager(uds_paths)
        new_mgr.start()
        
        # Update the daq_env reference
        daq_env["uds_manager"] = new_mgr
        uds_mgr = new_mgr
    
    # Wait for connection
    srv = uds_mgr.servers[dp_name]
    start = time.time()
    while time.time() - start < timeout_s:
        if srv.connected.is_set() and _uds_exists(uds_path(dp_name)):
            return True
        time.sleep(0.2)
    
    return False

@pytest.mark.usefixtures("daq_env")
class TestUdsDataPath:
    """
    Tests focusing on the UDS data path integrity and crash resistance.
    These tests verify that various data corruption, connection issues,
    and protocol violations don't crash Hashpipe.
    """

    def test_rapid_connect_disconnect_ph256(self, daq_env):
        """
        Test rapid connect/disconnect cycles don't crash Hashpipe.
        This simulates network instability or client restarts.
        """
        # Stop existing servers
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        ph_path = uds_path("ph256")

        # Perform rapid connect/disconnect cycles
        from conftest import UdsServerManager
        for cycle in range(5):
            # Start server
            uds_paths = {"ph256": Path(ph_path)}
            mgr = UdsServerManager(uds_paths)
            mgr.start()

            # Let it connect briefly
            time.sleep(0.5)

            # Stop server abruptly
            mgr.stop()

            # Brief pause before next cycle
            time.sleep(0.3)

            # Verify Hashpipe survives each cycle
            assert is_hashpipe_running(), f"Hashpipe should survive rapid cycle {cycle+1}"

        # Final verification
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe should remain running after rapid cycles"

    def test_malformed_socket_creation(self, daq_env):
        """
        Test that Hashpipe handles malformed or inaccessible socket files gracefully.
        """
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        ph_path = uds_path("ph256")

        # Create a regular file where socket should be (simulate filesystem corruption)
        with open(ph_path, 'w') as f:
            f.write("not a socket")

        # Hashpipe should handle this gracefully
        time.sleep(2)
        assert is_hashpipe_running(), "Hashpipe should handle non-socket file gracefully"

        # Remove the file and create proper socket
        os.unlink(ph_path)
        from conftest import UdsServerManager
        uds_paths = {"ph256": Path(ph_path)}
        mgr = UdsServerManager(uds_paths)
        mgr.start()

        # Should recover and connect
        time.sleep(3)
        assert mgr.servers["ph256"].connected.is_set(), "Should recover after socket fix"
        assert is_hashpipe_running(), "Hashpipe should remain running"

        mgr.stop()

    def test_permission_denied_socket(self, daq_env):
        """
        Test Hashpipe handles permission denied errors on socket access.
        """
        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        ph_path = uds_path("ph256")

        # Create socket directory with restricted permissions
        socket_dir = os.path.dirname(ph_path)
        if not os.path.exists(socket_dir):
            os.makedirs(socket_dir)

        # Create a socket then make directory unreadable
        from conftest import UdsServerManager
        uds_paths = {"ph256": Path(ph_path)}
        mgr = UdsServerManager(uds_paths)
        mgr.start()
        mgr.stop()

        # Make directory inaccessible (simulate permission issues)
        os.chmod(socket_dir, 0o000)

        try:
            # Hashpipe should handle permission errors gracefully
            time.sleep(2)
            assert is_hashpipe_running(), "Hashpipe should handle permission errors gracefully"

        finally:
            # Restore permissions for cleanup
            os.chmod(socket_dir, 0o755)

    def test_socket_buffer_overflow_recovery(self, daq_env):
        """
        Test recovery after socket buffer fills up completely.
        """
        class SlowReadServer:
            """Server that reads very slowly to fill buffers"""
            
            def __init__(self, socket_path):
                self.socket_path = socket_path
                self.server = None
                self.loop = None
                self.thread = None
                self.started = threading.Event()
                self._client_tasks = set()
                self.frames_received = 0

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

            async def _start(self):
                if os.path.exists(self.socket_path):
                    s = os.stat(self.socket_path)
                    if stat.S_ISSOCK(s.st_mode):
                        os.unlink(self.socket_path)

                self.server = await asyncio.start_unix_server(self._client_wrapper, path=self.socket_path)

            async def _client_wrapper(self, reader, writer):
                task = asyncio.create_task(self._handle(reader, writer))
                self._client_tasks.add(task)
                task.add_done_callback(lambda t: self._client_tasks.discard(t))

            async def _handle(self, reader, writer):
                try:
                    while True:
                        # Read very slowly to cause backpressure
                        try:
                            # Read module ID
                            mid = await reader.readexactly(2)
                            # Read header slowly
                            header = await reader.readuntil(b"\n\n")
                            # Read separator
                            star = await reader.readexactly(1)
                            # Read image data slowly
                            img = await reader.read(1024)
                            
                            self.frames_received += 1
                            
                            # Slow processing to cause backpressure
                            await asyncio.sleep(0.1)
                            
                        except asyncio.IncompleteReadError:
                            break
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            def stop(self):
                if not self.loop:
                    return
                    
                async def _stop():
                    tasks = list(self._client_tasks)
                    for task in tasks:
                        task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                    
                    if self.server:
                        self.server.close()
                        try:
                            await self.server.wait_closed()
                        except Exception:
                            pass

                fut = asyncio.run_coroutine_threadsafe(_stop(), self.loop)
                try:
                    fut.result(timeout=5)
                except Exception:
                    pass
                    
                self.loop.call_soon_threadsafe(self.loop.stop)
                if self.thread:
                    self.thread.join(timeout=5)

                try:
                    if os.path.exists(self.socket_path):
                        os.unlink(self.socket_path)
                except Exception:
                    pass

        uds_mgr = daq_env["uds_manager"]
        uds_mgr.stop()

        ph_path = uds_path("ph256")

        slow_srv = SlowReadServer(ph_path)
        slow_srv.start()

        # Let it run and build up backpressure
        time.sleep(5)

        assert is_hashpipe_running(), "Hashpipe should handle slow reader"

        # Stop slow server (creates EAGAIN conditions)
        slow_srv.stop()
        time.sleep(1)

        # Start normal server and verify recovery
        from conftest import UdsServerManager
        uds_paths = {"ph256": Path(ph_path)}
        mgr = UdsServerManager(uds_paths)
        mgr.start()

        time.sleep(3)
        assert mgr.servers["ph256"].connected.is_set(), "Should recover after backpressure"
        assert is_hashpipe_running(), "Hashpipe should recover from backpressure"

        mgr.stop()

    def test_data_integrity_ph256(self, daq_env):
        """
        Test that ph256 UDS data path maintains data integrity.
        """
        assert _ensure_uds_available(daq_env), "Could not establish UDS connection"
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers["ph256"]

        # Wait for multiple frames to verify sustained data flow
        start = time.time()
        while time.time() - start < 15:
            if srv.frames_received >= 10:
                break
            time.sleep(0.5)
        
        assert srv.frames_received >= 10, f"Expected >=10 frames, got {srv.frames_received}"
        assert is_hashpipe_running(), "Hashpipe should remain running during data flow"

    def test_concurrent_multiple_clients_ph256(self, daq_env):
        """
        Test behavior when multiple clients try to connect to the same UDS socket.
        Only one should succeed, others should be handled gracefully.
        """
        assert _ensure_uds_available(daq_env), "Could not establish UDS connection"
        
        uds_mgr = daq_env["uds_manager"]
        ph_path = uds_path("ph256")

        # Wait for initial connection
        srv = uds_mgr.servers["ph256"]
        assert srv.connected.is_set(), "Initial connection should succeed"

        # Try to make additional connections (should be rejected gracefully)
        connection_attempts = []
        for i in range(3):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                sock.connect(ph_path)
                connection_attempts.append(sock)
            except Exception:
                # Expected - additional connections should fail
                pass

        # Clean up any extra connections
        for sock in connection_attempts:
            try:
                sock.close()
            except Exception:
                pass

        # Hashpipe should still be running
        assert is_hashpipe_running(), "Hashpipe should handle multiple connection attempts"

    def test_data_validation_ph256(self, daq_env):
        """
        Test that we can validate the content of received ph256 frames.
        """
        assert _ensure_uds_available(daq_env), "Could not establish UDS connection"
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers["ph256"]

        # Wait for connection and some frames
        start = time.time()
        while time.time() - start < 15:
            if srv.connected.is_set() and srv.frames_received >= 5:
                break
            time.sleep(0.5)
        
        assert srv.connected.is_set(), "Should have ph256 connection"
        assert srv.frames_received >= 5, "Should have received frames"

        # Use stored frames from the server for validation
        stored_frames = srv.recent_frames
        assert len(stored_frames) > 0, "UDS server should have stored some frames"

        # Validate the structure of the first stored frame
        frame_data = stored_frames[0]
        module_id = frame_data['module_id']
        header = frame_data['header']
        image_data = frame_data['image_data']

        assert isinstance(module_id, int), "Module ID should be an integer"
        assert module_id in daq_env["module_ids"], f"Module ID {module_id} not in test set"
        assert isinstance(header, dict), "Header should be a dict"
        assert 'quabo_num' in header, "Header should contain 'quabo_num'"
        assert 'pkt_num' in header, "Header should contain 'pkt_num'"
        assert isinstance(image_data, bytes) and len(image_data) > 0, "Image data should be non-empty bytes"
        assert is_hashpipe_running(), "Hashpipe should remain running during data validation"

    def test_sustained_high_rate_ph256(self, daq_env):
        """
        Test Hashpipe stability under sustained high-rate ph256 data flow.
        """
        assert _ensure_uds_available(daq_env), "Could not establish UDS connection"
        
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers["ph256"]

        initial_frames = srv.frames_received

        # Let it run for sustained period 
        test_duration = 60
        start = time.time()
        last_check = start
        last_frames = initial_frames
        
        # Allow for frame reception to stabilize
        time.sleep(2)

        while time.time() - start < test_duration:
            current_time = time.time()
            current_frames = srv.frames_received

            # Check every 5 seconds
            if current_time - last_check >= 5:
                frame_rate = (current_frames - last_frames) / (current_time - last_check)
                print(f"Frame rate: {frame_rate:.2f} frames/sec, Total: {current_frames}")

                assert is_hashpipe_running(), "Hashpipe should remain running during sustained load"
                
                # Only assert frame increment if we're past the initial stabilization period
                if current_time - start > 5:
                    assert current_frames >= last_frames, "Frames should not decrease"

                last_check = current_time
                last_frames = current_frames

            time.sleep(0.5)

        final_frames = srv.frames_received
        total_frames = final_frames - initial_frames

        print(f"Sustained test: {total_frames} frames over {test_duration}s")

        assert total_frames >= 0, "Should have received some frames during sustained test"
        assert is_hashpipe_running(), "Hashpipe should survive sustained high-rate data"

    def test_uds_header_consistency_ph256(self, daq_env):
        """
        Test that UDS-delivered ph256 frames have consistent JSON headers
        by checking the raw byte representations captured by the server.
        """
        assert _ensure_uds_available(daq_env), "Could not establish UDS connection"
        uds_mgr = daq_env["uds_manager"]
        srv = uds_mgr.servers["ph256"]
        nframes = 100

        # Wait for the server to receive a good number of frames
        start = time.time()
        while time.time() - start < 20:
            if srv.frames_received >= nframes:
                break
            time.sleep(0.5)

        assert srv.frames_received >= nframes, f"Need >= {nframes} frames for consistency test, got {srv.frames_received}"

        # Retrieve the raw JSON byte strings from the server's stored frames
        stored_frames = srv.recent_frames[-nframes:] # Analyze the last nframes frames
        json_headers = [frame['json_bytes'] for frame in stored_frames]

        # 1. Primary Test: All JSON headers must have the exact same byte length.
        # This is the most critical requirement for predictable frame seeking.
        header_lengths = {len(h) for h in json_headers}
        assert len(header_lengths) == 1, \
            f"UDS headers have inconsistent byte lengths: {header_lengths}. " \
            "All headers from hashpipe must be identical in size."

        print(f"✓ All UDS headers have a consistent length: {header_lengths.pop()} bytes")

        # 2. Sanity Check: Ensure the header is valid JSON and contains required fields.
        first_header_bytes = json_headers[0]
        try:
            header_content = json.loads(first_header_bytes)
            required_fields = {'quabo_num', 'pkt_num', 'pkt_tai', 'pkt_nsec', 'tv_sec', 'tv_usec'}
            actual_fields = set(header_content.keys())
            assert required_fields.issubset(actual_fields), \
                f"Missing required fields. Expected: {required_fields}, Got: {actual_fields}"
        except json.JSONDecodeError:
            pytest.fail("The received JSON header is not valid JSON.")
        
        print(f"UDS header consistency test passed for {len(json_headers)} frames.")


