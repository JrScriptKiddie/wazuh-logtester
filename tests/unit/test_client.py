from __future__ import annotations

import json
import socket
import struct
from unittest import mock

import pytest

from wlogtest.client import (
    DEFAULT_SOCKET_PATH,
    LogtestClient,
    LogtestError,
    LogtestProcessingError,
    LogtestProtocolError,
    LogtestTransportError,
    create_wazuh_socket_message,
)
from tests.unit.conftest import read_frame, send_frame


def frame_bytes(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


# ---------------------------------------------------------------------------
# create_wazuh_socket_message
# ---------------------------------------------------------------------------

def test_create_wazuh_socket_message_exact_envelope():
    origin = {"name": "Logtest", "module": "framework"}
    envelope = create_wazuh_socket_message(
        origin, "log_processing", {"event": "hello", "location": "stdin"}
    )
    assert envelope == {
        "version": 1,
        "origin": origin,
        "command": "log_processing",
        "parameters": {"event": "hello", "location": "stdin"},
    }


# ---------------------------------------------------------------------------
# framing
# ---------------------------------------------------------------------------

def test_send_raw_frames_with_little_endian_uint32_length():
    sock = mock.Mock()
    payload = b'{"version": 1}'
    LogtestClient._send_raw(sock, payload)
    expected = struct.pack("<I", len(payload)) + payload
    sock.sendall.assert_called_once_with(expected)


def test_send_raw_empty_payload():
    sock = mock.Mock()
    LogtestClient._send_raw(sock, b"")
    sock.sendall.assert_called_once_with(struct.pack("<I", 0))


def test_full_request_frame_over_real_socket(unix_socket_server):
    received = {}

    def handler(conn):
        frame = read_frame(conn)
        received["frame"] = frame
        reply = {
            "error": 0,
            "data": {
                "token": "abc12345",
                "messages": ["ok"],
                "output": {"rule": {"id": "100100"}},
                "alert": True,
                "codemsg": 0,
            },
        }
        send_frame(conn, json.dumps(reply).encode("utf-8"), chunk_size=3)

    server = unix_socket_server(handler)
    client = LogtestClient(server.path)
    response = client.send("log_processing", {"event": "hello", "location": "stdin"})
    assert response["data"]["token"] == "abc12345"
    envelope = json.loads(received["frame"].decode("utf-8"))
    assert envelope == {
        "version": 1,
        "origin": {"name": "Logtest", "module": "framework"},
        "command": "log_processing",
        "parameters": {"event": "hello", "location": "stdin"},
    }


def test_client_constructor_defaults_and_env_override(monkeypatch):
    monkeypatch.delenv("WAZUH_LOGTEST_SOCKET", raising=False)
    assert LogtestClient().socket_path == DEFAULT_SOCKET_PATH
    monkeypatch.setenv("WAZUH_LOGTEST_SOCKET", "/tmp/mysock")
    assert LogtestClient().socket_path == "/tmp/mysock"
    assert LogtestClient(socket_path="/explicit").socket_path == "/explicit"
    assert LogtestClient(timeout=2.5).timeout == 2.5


# ---------------------------------------------------------------------------
# error paths
# ---------------------------------------------------------------------------

def test_server_error_raises_logtest_error_with_code_and_message(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        send_frame(conn, b'{"error": 7, "message": "invalid token"}')

    server = unix_socket_server(handler)
    client = LogtestClient(server.path)
    with pytest.raises(LogtestError) as excinfo:
        client.send("remove_session", {"token": "bad"})
    assert excinfo.value.code == 7
    assert excinfo.value.message == "invalid token"
    assert str(excinfo.value) == "invalid token"


def test_server_error_without_message(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        send_frame(conn, b'{"error": 3}')

    server = unix_socket_server(handler)
    with pytest.raises(LogtestError) as excinfo:
        LogtestClient(server.path).send("log_processing", {})
    assert excinfo.value.code == 3
    assert excinfo.value.message == ""


def test_codemsg_minus_one_raises_processing_error_with_first_message(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        reply = {
            "error": 0,
            "data": {
                "token": "abc12345",
                "messages": ["decoder failed"],
                "output": {},
                "alert": False,
                "codemsg": -1,
            },
        }
        send_frame(conn, json.dumps(reply).encode("utf-8"))

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProcessingError) as excinfo:
        LogtestClient(server.path).run_log("bad event")
    assert excinfo.value.code == -1
    assert excinfo.value.message == "decoder failed"
    assert isinstance(excinfo.value, LogtestError)


def test_codemsg_minus_one_without_messages_uses_generic_message(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        reply = {
            "error": 0,
            "data": {"token": "t", "messages": [], "output": {}, "alert": False, "codemsg": -1},
        }
        send_frame(conn, json.dumps(reply).encode("utf-8"))

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProcessingError) as excinfo:
        LogtestClient(server.path).run_log("bad event")
    assert excinfo.value.message == "log processing error"


def test_truncated_header_raises_protocol_error(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        conn.sendall(b"\x02\x00")  # 2 of the 4 header bytes, then close

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProtocolError) as excinfo:
        LogtestClient(server.path).send("log_processing", {})
    assert "connection closed before 4 bytes received" in str(excinfo.value)


def test_connection_closed_without_reply_raises_protocol_error(unix_socket_server):
    def handler(conn):
        read_frame(conn)  # accept, read, reply nothing

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProtocolError) as excinfo:
        LogtestClient(server.path).send("log_processing", {})
    assert "connection closed before 4 bytes received" in str(excinfo.value)


def test_short_payload_read_raises_protocol_error(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        conn.sendall(struct.pack("<I", 10) + b"short")  # declares 10, sends 5

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProtocolError) as excinfo:
        LogtestClient(server.path).send("log_processing", {})
    assert "connection closed before 10 bytes received" in str(excinfo.value)


def test_oversized_reply_raises_protocol_error(unix_socket_server):
    def handler(conn):
        read_frame(conn)
        conn.sendall(struct.pack("<I", 70000))

    server = unix_socket_server(handler)
    with pytest.raises(LogtestProtocolError) as excinfo:
        LogtestClient(server.path).send("log_processing", {})
    assert "reply too large: 70000 bytes" in str(excinfo.value)


def test_invalid_json_reply_raises_protocol_error():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.recv.side_effect = [struct.pack("<I", 8), b"not json"]
        with pytest.raises(LogtestProtocolError) as excinfo:
            LogtestClient("/sock").send("log_processing", {})
        assert "invalid JSON reply" in str(excinfo.value)


def test_non_dict_reply_raises_protocol_error():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.recv.side_effect = [struct.pack("<I", 2), b"[]"]
        with pytest.raises(LogtestProtocolError) as excinfo:
            LogtestClient("/sock").send("log_processing", {})
        assert "not a JSON object" in str(excinfo.value)


def test_socket_timeout_during_reply_raises_transport_error():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.recv.side_effect = socket.timeout("timed out")
        with pytest.raises(LogtestTransportError) as excinfo:
            LogtestClient("/sock").send("log_processing", {})
        assert "timed out talking to /sock" in str(excinfo.value)


def test_oserror_during_reply_raises_transport_error():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.sendall.side_effect = OSError("broken pipe")
        with pytest.raises(LogtestTransportError) as excinfo:
            LogtestClient("/sock").send("log_processing", {})
        assert "I/O error talking to /sock" in str(excinfo.value)


def test_connect_timeout_raises_transport_error():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.connect.side_effect = socket.timeout("connect timed out")
        with pytest.raises(LogtestTransportError) as excinfo:
            LogtestClient("/sock").send("log_processing", {})
        assert "timed out connecting to /sock" in str(excinfo.value)


def test_connect_oserror_raises_transport_error(tmp_path):
    missing = str(tmp_path / "no-such-socket")
    with pytest.raises(LogtestTransportError) as excinfo:
        LogtestClient(missing).send("log_processing", {})
    assert f"cannot connect to {missing}" in str(excinfo.value)


def test_oversized_request_rejected_before_send():
    with mock.patch("socket.socket") as socket_class:
        client = LogtestClient("/sock")
        with pytest.raises(LogtestTransportError) as excinfo:
            client.send("log_processing", {"event": "x" * 70000})
        assert "payload too large" in str(excinfo.value)
        assert not socket_class.called


def test_payload_at_limit_is_sent():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.recv.side_effect = [struct.pack("<I", 2), b"{}"]
        client = LogtestClient("/sock")
        event = "x" * 65000
        response = client.send("log_processing", {"event": event})
        assert response == {}
        header, payload = sock.sendall.call_args.args[0][:4], sock.sendall.call_args.args[0][4:]
        assert struct.unpack("<I", header)[0] == len(payload)


# ---------------------------------------------------------------------------
# run_log / remove_session / close
# ---------------------------------------------------------------------------

def test_run_log_forwards_all_arguments():
    client = LogtestClient("/sock")
    captured = {}

    def fake_send(command, parameters):
        captured["command"] = command
        captured["parameters"] = parameters
        return {
            "error": 0,
            "data": {
                "token": "tok00001",
                "messages": [],
                "output": {},
                "alert": True,
                "codemsg": 0,
            },
        }

    with mock.patch.object(client, "send", side_effect=fake_send):
        data = client.run_log(
            {"foo": "bar"},
            location="agent-1",
            log_format="json",
            token="tok00001",
            options={"rules_debug": True},
        )
    assert captured == {
        "command": "log_processing",
        "parameters": {
            "event": {"foo": "bar"},
            "location": "agent-1",
            "log_format": "json",
            "token": "tok00001",
            "options": {"rules_debug": True},
        },
    }
    assert data["token"] == "tok00001"


def test_run_log_omits_token_and_options_when_not_given():
    client = LogtestClient("/sock")
    captured = {}

    def fake_send(command, parameters):
        captured["parameters"] = parameters
        return {"error": 0, "data": {}}

    with mock.patch.object(client, "send", side_effect=fake_send):
        data = client.run_log("plain event")
    assert captured["parameters"] == {
        "event": "plain event",
        "location": "stdin",
        "log_format": "syslog",
    }
    assert data == {}


def test_run_log_non_dict_data_returns_empty_dict():
    client = LogtestClient("/sock")
    with mock.patch.object(client, "send", return_value={"error": 0, "data": None}):
        assert client.run_log("event") == {}


def test_remove_session_sends_command_with_token(unix_socket_server):
    received = {}

    def handler(conn):
        frame = read_frame(conn)
        received["envelope"] = json.loads(frame.decode("utf-8"))
        send_frame(conn, b'{"error": 0, "data": {"result": "ok"}}')

    server = unix_socket_server(handler)
    data = LogtestClient(server.path).remove_session("abc12345")
    assert received["envelope"]["command"] == "remove_session"
    assert received["envelope"]["parameters"] == {"token": "abc12345"}
    assert data == {"result": "ok"}


def test_remove_session_non_dict_data_returns_empty_dict():
    client = LogtestClient("/sock")
    with mock.patch.object(
        client, "send", return_value={"error": 0, "data": ["not", "a", "dict"]}
    ):
        assert client.remove_session("t") == {}


def test_close_is_safe_noop():
    client = LogtestClient("/sock")
    client.close()
    client.close()


def test_client_socket_closed_after_send():
    with mock.patch("socket.socket") as socket_class:
        sock = mock.Mock()
        socket_class.return_value = sock
        sock.recv.side_effect = [struct.pack("<I", 2), b"{}"]
        LogtestClient("/sock").send("log_processing", {})
    sock.close.assert_called()
