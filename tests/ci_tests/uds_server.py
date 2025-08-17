# tests/ci_tests/uds_server.py

import asyncio
import os
import stat
import socket
import struct
import logging

class UdsServer:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.server = None
        self.connected = asyncio.Event()
        self.frames_received = 0
        self._stop_event = asyncio.Event()
        self._tasks = set()
        self._logger = logging.getLogger(f"UdsServer-{socket_path}")

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
            raise

        # Create the server socket via asyncio
        self.server = await asyncio.start_unix_server(
            self._client_wrapper, 
            path=self.socket_path
        )

    async def _client_wrapper(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._tasks.add(task)
        
        def on_task_done(t):
            self._tasks.discard(t)
            # Log any exceptions that occurred
            try:
                if t.exception():
                    self._logger.debug(f"Client task completed with exception: {t.exception()}")
            except asyncio.CancelledError:
                pass
        
        task.add_done_callback(on_task_done)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.connected.set()
        client_info = writer.get_extra_info('peername', 'unknown')
        
        try:
            while not self._stop_event.is_set():
                try:
                    # 1) module id: 2 bytes
                    mid = await asyncio.wait_for(reader.readexactly(2), timeout=1.0)
                    
                    # 2) header until \n\n
                    header = await asyncio.wait_for(reader.readuntil(b"\n\n"), timeout=1.0)
                    
                    # 3) star
                    star = await asyncio.wait_for(reader.readexactly(1), timeout=1.0)
                    if star != b"*":
                        self._logger.warning(f"Expected '*', got {star!r}")
                        break
                    
                    # 4) Read image data with timeout
                    try:
                        img = await asyncio.wait_for(reader.read(4096), timeout=0.1)
                        self.frames_received += 1
                    except asyncio.TimeoutError:
                        # No more data available, that's fine
                        self.frames_received += 1
                        
                except asyncio.TimeoutError:
                    # Check if we should continue waiting
                    continue
                except (asyncio.IncompleteReadError, ConnectionResetError):
                    break
                    
        except asyncio.CancelledError:
            self._logger.debug(f"Client handler for {client_info} was cancelled")
        except Exception as e:
            self._logger.error(f"Unexpected error in client handler: {e}")
        finally:
            # Ensure proper cleanup
            if not writer.is_closing():
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except asyncio.TimeoutError:
                    self._logger.warning("Timeout waiting for writer to close")

    async def stop(self):
        """Properly stop the server and clean up all resources."""
        self._stop_event.set()
        
        # Close the server first to stop accepting new connections
        if self.server:
            self.server.close()
            try:
                await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                self._logger.warning("Timeout waiting for server to close")

        # Cancel and wait for all client tasks to complete
        if self._tasks:
            self._logger.debug(f"Cancelling {len(self._tasks)} client tasks")
            
            # Cancel all tasks
            for task in list(self._tasks):
                if not task.done():
                    task.cancel()
            
            # Wait for all tasks to complete with timeout
            if self._tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*list(self._tasks), return_exceptions=True),
                        timeout=5.0
                    )
                except asyncio.TimeoutError:
                    self._logger.warning("Timeout waiting for client tasks to complete")
                
                # Force cleanup any remaining tasks
                self._tasks.clear()

        # Remove socket file
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception as e:
            self._logger.warning(f"Failed to remove socket file: {e}")
        
        # Clear the connected event
        self.connected.clear()
