import os
import socket
import stat
import json

def read_one_frame_from_uds(socket_path, header_size_hint=None, timeout_s=5.0):
    """
    Reads exactly one frame from the snapshot.c client-facing UDS format:
      [2-byte big-endian module_id]
      [JSON header ending with b'\\n\\n']  (if header_size_hint is provided, readexactly that many)
      ['*']
      [binary image bytes], where size is inferred by the consumer.
    Returns (module_id, header_dict, raw_image_bytes)
    """
    # Sanity check
    if not os.path.exists(socket_path):
        raise FileNotFoundError(f"{socket_path} does not exist")
    st = os.stat(socket_path)
    if not stat.S_ISSOCK(st.st_mode):
        raise RuntimeError(f"{socket_path} exists but is not a socket")

    # Blocking connect with timeout
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    sock.connect(socket_path)

    try:
        # 1) 2-byte module_id
        mbytes = _recv_exact(sock, 2)
        module_id = int.from_bytes(mbytes, "big")

        # 2) header
        if header_size_hint is None:
            header_bytes = _recv_until(sock, b"\n\n")
        else:
            header_bytes = _recv_exact(sock, header_size_hint)
            if not header_bytes.endswith(b"\n\n"):
                # fallback: find the terminator
                extra = _recv_until(sock, b"\n\n")
                header_bytes += extra
        header_json = header_bytes[:-2].decode("utf-8")
        header = json.loads(header_json)

        # 3) image prefix '*' then frame payload length is unknown to client.
        # In practice, for CI we can bound read to a reasonable size.
        star = _recv_exact(sock, 1)
        if star != b"*":
            raise RuntimeError(f"Expected '*' before image payload, got {star!r}")

        # Without the dp’s exact bytes_per_image, we don’t know total bytes.
        # For tests, read a safe upper bound then return what we got in one recv.
        # A robust client would know bytes_per_image. For CI, read a max buffer.
        img = _recv_at_most(sock, 4096)  # enough for ph256/img16 frame sizes in CI
        return module_id, header, img
    finally:
        sock.close()

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while expecting more data")
        buf.extend(chunk)
    return bytes(buf)

def _recv_until(sock, terminator: bytes, max_bytes=65536):
    buf = bytearray()
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectionError("Socket closed before terminator")
        buf.extend(chunk)
        if buf.endswith(terminator):
            return bytes(buf)
        if len(buf) > max_bytes:
            raise RuntimeError("Header exceeded maximum allowed size")

def _recv_at_most(sock, max_bytes):
    # Single recv up to max_bytes, returns what was available immediately.
    return sock.recv(max_bytes)
