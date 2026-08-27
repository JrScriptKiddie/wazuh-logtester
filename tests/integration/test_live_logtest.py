from __future__ import annotations

import os
import socket

import pytest

from wlogtest.client import LogtestClient

pytestmark = pytest.mark.integration

SOCKET_PATH = os.environ.get("WAZUH_LOGTEST_SOCKET")


def _socket_reachable():
    if not SOCKET_PATH:
        return False
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(2.0)
        probe.connect(SOCKET_PATH)
        probe.close()
        return True
    except OSError:
        return False


skip_live = pytest.mark.skipif(
    not _socket_reachable(),
    reason="WAZUH_LOGTEST_SOCKET is not set or the socket is not reachable",
)


@pytest.fixture
def live_client():
    return LogtestClient(SOCKET_PATH, timeout=10.0)


@skip_live
def test_smoke_run_log_returns_expected_schema(live_client):
    data = live_client.run_log("hello logtest")
    assert isinstance(data, dict)
    assert "token" in data
    assert "messages" in data
    assert "output" in data
    assert isinstance(data["messages"], list)
    assert isinstance(data["output"], dict)


@skip_live
def test_remove_session_works(live_client):
    data = live_client.run_log("session probe event")
    token = data.get("token")
    assert token
    removed = live_client.remove_session(token)
    assert isinstance(removed, dict)
