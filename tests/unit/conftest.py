from __future__ import annotations

import os
import socket
import struct
import threading

import pytest

from wlogtest.client import LogtestError


class UnixSocketServer:
    """Tiny real AF_UNIX server in a tmp dir, one connection per instance."""

    def __init__(self, path, handler):
        self.path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(path)
        self._sock.listen(1)
        self._thread = threading.Thread(target=self._serve, args=(handler,))
        self._thread.daemon = True
        self._thread.start()

    def _serve(self, handler):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            handler(conn)
        finally:
            conn.close()

    def close(self):
        try:
            self._sock.close()
        finally:
            if os.path.exists(self.path):
                os.unlink(self.path)


def read_frame(conn, timeout=None):
    """Read one length-prefixed frame (used by server-side handlers)."""
    if timeout is not None:
        conn.settimeout(timeout)
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    (size,) = struct.unpack("<I", header)
    body = b""
    while len(body) < size:
        chunk = conn.recv(size - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def send_frame(conn, payload, chunk_size=None):
    """Send one length-prefixed frame, optionally in small chunks."""
    frame = struct.pack("<I", len(payload)) + payload
    if chunk_size is None:
        conn.sendall(frame)
        return
    for index in range(0, len(frame), chunk_size):
        conn.sendall(frame[index:index + chunk_size])


@pytest.fixture
def unix_socket_server(tmp_path):
    """Factory: start a real AF_UNIX server; auto-closed after the test."""
    servers = []

    def start(handler):
        server = UnixSocketServer(str(tmp_path / f"logtest{len(servers)}.sock"), handler)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


class FakeLogtestClient:
    """Scripted logtest client for DatasetRunner tests."""

    def __init__(self, scripted, fail_remove=False):
        self._scripted = list(scripted)
        self.fail_remove = fail_remove
        self.calls = []
        self.removed = []

    def run_log(self, event, location="stdin", log_format="syslog", token=None, options=None):
        self.calls.append(
            {
                "event": event,
                "location": location,
                "log_format": log_format,
                "token": token,
                "options": options,
            }
        )
        if not self._scripted:
            return {
                "token": "deadbeef",
                "messages": [],
                "output": {},
                "alert": True,
                "codemsg": 0,
            }
        item = self._scripted.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def remove_session(self, token):
        if self.fail_remove:
            raise LogtestError(9, "cannot remove")
        self.removed.append(token)
        return {}

    def close(self):
        pass


@pytest.fixture
def fake_client():
    """Factory for FakeLogtestClient instances (scripted per-call responses)."""
    created = []

    def make(scripted=None, fail_remove=False):
        client = FakeLogtestClient(scripted or [], fail_remove=fail_remove)
        created.append(client)
        return client

    yield make
