from __future__ import annotations

import json
import os
import socket
import struct

DEFAULT_SOCKET_PATH = "/var/ossec/queue/sockets/logtest"
DEFAULT_ORIGIN = {"name": "Logtest", "module": "framework"}
MAX_PAYLOAD = 65536
MAX_REPLY_PAYLOAD = 4 * 1024 * 1024

_HEADER = struct.Struct("<I")


class LogtestError(Exception):
    """Server returned a top-level error != 0."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class LogtestProcessingError(LogtestError):
    """Server processed the event but the analysis failed (codemsg == -1)."""

    def __init__(self, code: int, message: str = "", codemsg: int = -1, token: str = "") -> None:
        super().__init__(code, message)
        self.codemsg = codemsg
        self.token = token


class LogtestTransportError(Exception):
    """Socket/connect/IO/timeout failure."""


class LogtestProtocolError(LogtestTransportError):
    """Bad framing or JSON in the reply."""


def create_wazuh_socket_message(origin: dict, command: str, parameters: dict) -> dict:
    """Build the request envelope as defined by the Wazuh logtest protocol."""
    return {
        "version": 1,
        "origin": origin,
        "command": command,
        "parameters": parameters,
    }


class LogtestClient:
    def __init__(self, socket_path: str | None = None, timeout: float = 10.0) -> None:
        self.socket_path = (
            socket_path
            or os.environ.get("WAZUH_LOGTEST_SOCKET")
            or DEFAULT_SOCKET_PATH
        )
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
        except socket.timeout as exc:
            sock.close()
            raise LogtestTransportError(
                f"timed out connecting to {self.socket_path}"
            ) from exc
        except OSError as exc:
            sock.close()
            raise LogtestTransportError(
                f"cannot connect to {self.socket_path}: {exc}"
            ) from exc
        return sock

    @staticmethod
    def _send_raw(sock: socket.socket, payload: bytes) -> None:
        frame = _HEADER.pack(len(payload)) + payload
        sock.sendall(frame)

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks = []
        received = 0
        while received < size:
            chunk = sock.recv(size - received)
            if not chunk:
                raise LogtestProtocolError(
                    f"connection closed before {size} bytes received"
                )
            chunks.append(chunk)
            received += len(chunk)
        return b"".join(chunks)

    @classmethod
    def _recv_raw(cls, sock: socket.socket) -> bytes:
        header = cls._recv_exact(sock, _HEADER.size)
        size = _HEADER.unpack(header)[0]
        if size > MAX_REPLY_PAYLOAD:
            raise LogtestProtocolError(
                f"reply too large: {size} bytes (max {MAX_REPLY_PAYLOAD})"
            )
        return cls._recv_exact(sock, size)

    def send(self, command: str, parameters: dict) -> dict:
        message = create_wazuh_socket_message(DEFAULT_ORIGIN, command, parameters)
        payload = json.dumps(message).encode("utf-8")
        if len(payload) > MAX_PAYLOAD:
            raise LogtestTransportError(
                f"payload too large: {len(payload)} bytes (max {MAX_PAYLOAD})"
            )
        sock = None
        try:
            sock = self._connect()
            try:
                self._send_raw(sock, payload)
                raw = self._recv_raw(sock)
            except socket.timeout as exc:
                raise LogtestTransportError(
                    f"timed out talking to {self.socket_path}"
                ) from exc
            except OSError as exc:
                raise LogtestTransportError(
                    f"I/O error talking to {self.socket_path}: {exc}"
                ) from exc
        finally:
            if sock is not None:
                sock.close()
        try:
            response = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise LogtestProtocolError(f"invalid JSON reply from logtest: {exc}") from exc
        if not isinstance(response, dict):
            raise LogtestProtocolError("reply is not a JSON object")
        if response.get("error", 0) != 0:
            raise LogtestError(response["error"], response.get("message", ""))
        return response

    def run_log(
        self,
        event,
        location: str = "stdin",
        log_format: str = "syslog",
        token=None,
        options=None,
    ) -> dict:
        parameters = {
            "event": event,
            "location": location,
            "log_format": log_format,
        }
        if token:
            parameters["token"] = token
        if options:
            parameters["options"] = options
        response = self.send("log_processing", parameters)
        data = response.get("data")
        if not isinstance(data, dict):
            data = {}
        if data.get("codemsg") == -1:
            messages = data.get("messages") or []
            message = messages[0] if messages else "log processing error"
            raise LogtestProcessingError(
                -1, message, codemsg=-1, token=data.get("token", "") or ""
            )
        return data

    def remove_session(self, token: str) -> dict:
        response = self.send("remove_session", {"token": token})
        data = response.get("data")
        return data if isinstance(data, dict) else {}

    def close(self) -> None:
        pass
