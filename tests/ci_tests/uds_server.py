# tests/ci_tests/uds_server.py
import asyncio
import os
import stat
import socket
import struct

class UdsServer:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.server = None
        self.connected = asyncio.Event()
        self.frames_received = 0
        self._stop_event = asyncio.Event()
        self._tasks = set()

    async def start(self):
        # Remove stale file if present
        try:
            if os.path.exists(self.socket_path):
                s = os.stat(self.socket_path)
                if stat.S_ISSOCK(s.st_mode):
                    os.unlink(self.socket_path)
                else:
                    raise RuntimeError(f"{self.socket_path} exists and is not a socket file")
        except Exception:
            # If cleanup fails, do not start
            raise

        # Create the server socket via asyncio
        self.server = await asyncio.start_unix_server(self._client_wrapper, path=self.socket_path)
        # Ready immediately for accept; the caller may wait on self.connected

    async def _client_wrapper(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(lambda t: self._tasks.discard(t))

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.connected.set()
        try:
            while not self._stop_event.is_set():
                # 1) module id: 2 bytes
                mid = await reader.readexactly(2)
                # 2) header until \n\n
                header = await reader.readuntil(b"\n\n")
                # 3) star
                star = await reader.readexactly(1)
                if star != b"*":
                    # If malformed, drop connection
                    break
                # 4) Read "some" data without blocking test. Since we don't know DP size here,
                #    read what's immediately available (if any), but don't block forever.
                #    Hashpipe may deliver a full frame in a single writev; reading a single chunk is fine to confirm activity.
                # Use small timeout to avoid hanging if client is slow; if timeout, we accept what we got so far.
                # We’ll try to read 4096 bytes max, similar to helper_uds_client.
                try:
                    img = await asyncio.wait_for(reader.read(4096), timeout=0.05)
                except asyncio.TimeoutError:
                    img = b""
                self.frames_received += 1
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        self._stop_event.set()
        # Close the server
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        # Cancel any outstanding client tasks gracefully
        if self._tasks:
            for t in list(self._tasks):
                t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
        # Remove socket file
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception:
            pass
