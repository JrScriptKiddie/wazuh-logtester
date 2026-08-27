from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

import wlogtest.cli as cli_module
from wlogtest.cli import main
from wlogtest.client import LogtestError

GOOD_DATA = {
    "token": "abc12345",
    "messages": ["processed"],
    "output": {"rule": {"id": "100100"}},
    "alert": True,
    "codemsg": 0,
}


class StubClient:
    def __init__(self, socket_path=None, timeout=10.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self.calls = []
        self.removed = []
        self.data = GOOD_DATA

    def run_log(self, event, location="stdin", log_format="syslog", token=None, options=None):
        self.calls.append(
            dict(
                event=event,
                location=location,
                log_format=log_format,
                token=token,
                options=options,
            )
        )
        if isinstance(self.data, Exception):
            raise self.data
        return self.data

    def remove_session(self, token):
        self.removed.append(token)
        return {}

    def close(self):
        pass


class FakeStdin:
    def __init__(self, lines=(), tty=False):
        self._lines = iter(lines)
        self._tty = tty

    def isatty(self):
        return self._tty

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._lines)


@pytest.fixture
def stub_client(monkeypatch):
    created = []

    class StubClass(StubClient):
        pass

    def make(**kwargs):
        client = StubClass()
        client.data = kwargs.get("data", GOOD_DATA)
        created.append(client)
        monkeypatch.setattr(cli_module, "LogtestClient", lambda *a, **kw: client)
        return client

    make.instances = created
    return make


def test_version_subcommand_exits_zero_with_version(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "1.0.0"


def test_logtest_single_event_prints_phase_output(capsys, stub_client):
    client = stub_client()
    assert main(["logtest", "-e", "hello world"]) == 0
    out = capsys.readouterr().out
    assert "**Phase 1: Completed pre-decoding." in out
    assert "**Phase 2: Completed decoding." in out
    assert "**Phase 3: Completed filtering (rules)." in out
    assert "id: '100100'" in out
    assert "**Alert to be generated." in out


def test_logtest_json_flag_prints_raw_json(capsys, stub_client):
    client = stub_client()
    assert main(["logtest", "-e", "hello world", "--json"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["token"] == "abc12345"
    assert data["output"]["rule"]["id"] == "100100"


def test_logtest_forwards_location_format_token_options(capsys, stub_client):
    client = stub_client()
    assert (
        main(
            [
                "logtest",
                "-e",
                "hello",
                "-l",
                "agent-1",
                "-f",
                "json",
                "--token",
                "abc12345",
                "--debug",
            ]
        )
        == 0
    )
    call = client.calls[0]
    assert call["event"] == "hello"
    assert call["location"] == "agent-1"
    assert call["log_format"] == "json"
    assert call["token"] == "abc12345"
    assert call["options"] == {"rules_debug": True}


def test_logtest_without_debug_passes_no_options(capsys, stub_client):
    client = stub_client()
    assert main(["logtest", "-e", "hello"]) == 0
    assert client.calls[0]["options"] is None


def test_logtest_end_session_removes_token(capsys, stub_client):
    client = stub_client()
    assert main(["logtest", "-e", "hello", "--end-session"]) == 0
    assert client.removed == ["abc12345"]


def test_logtest_end_session_remove_failure_is_swallowed(capsys, stub_client):
    client = stub_client()
    client.remove_session = lambda token: (_ for _ in ()).throw(LogtestError(9, "nope"))
    assert main(["logtest", "-e", "hello", "--end-session"]) == 0


def test_logtest_error_exits_one_with_error_json(capsys, stub_client):
    client = stub_client(data=LogtestError(3, "nope"))
    assert main(["logtest", "-e", "hello"]) == 1
    err = capsys.readouterr().err
    parsed = json.loads(err)
    assert parsed == {"error": 3, "message": "nope"}


def test_logtest_transport_error_prints_clean_message(capsys, stub_client):
    from wlogtest.client import LogtestTransportError

    client = stub_client()
    client.run_log = lambda *a, **kw: (_ for _ in ()).throw(
        LogtestTransportError("cannot connect to /var/ossec/queue/sockets/logtest")
    )
    assert main(["logtest", "-e", "hello"]) == 1
    err = capsys.readouterr().err
    assert "error: cannot connect" in err
    assert "Traceback" not in err


def test_logtest_piped_stdin_processes_each_line(capsys, stub_client, monkeypatch):
    client = stub_client()
    monkeypatch.setattr(cli_module.sys, "stdin", FakeStdin(["line one\n", "line two\n"]))
    assert main(["logtest"]) == 0
    assert [call["event"] for call in client.calls] == ["line one", "line two"]
    out = capsys.readouterr().out
    assert out.count("**Phase 1: Completed pre-decoding.") == 2


class MockInput:
    def __init__(self, responses):
        self._responses = list(responses)

    def __call__(self, prompt=""):
        if not self._responses:
            raise EOFError
        print(prompt, end="")
        return self._responses.pop(0)


def test_logtest_repl_processes_until_quit(capsys, stub_client, monkeypatch):
    client = stub_client()
    monkeypatch.setattr(cli_module.sys, "stdin", FakeStdin(tty=True))
    monkeypatch.setattr("builtins.input", MockInput(["repl event", ":quit"]))
    assert main(["logtest", "-i"]) == 0
    assert [call["event"] for call in client.calls] == ["repl event"]
    assert "wlogtest> " in capsys.readouterr().out


def test_logtest_repl_eof_exits_cleanly(capsys, stub_client, monkeypatch):
    client = stub_client()
    monkeypatch.setattr(cli_module.sys, "stdin", FakeStdin(tty=True))
    monkeypatch.setattr("builtins.input", MockInput([]))
    assert main(["logtest", "-i"]) == 0
    assert client.calls == []


def test_logtest_repl_short_quit(capsys, stub_client, monkeypatch):
    client = stub_client()
    monkeypatch.setattr(cli_module.sys, "stdin", FakeStdin(tty=True))
    monkeypatch.setattr("builtins.input", MockInput([":q"]))
    assert main(["logtest", "-i"]) == 0
    assert client.calls == []


def test_logtest_tty_without_event_or_interactive_errors(capsys, stub_client, monkeypatch):
    stub_client()
    monkeypatch.setattr(cli_module.sys, "stdin", FakeStdin(tty=True))
    with pytest.raises(SystemExit) as excinfo:
        main(["logtest"])
    assert excinfo.value.code == 2
    assert "one of -e/--event or -i/--interactive" in capsys.readouterr().err


def write_dataset(tmp_path, expect):
    dataset = {
        "name": "cli ds",
        "tests": [{"name": "case", "event": "hello", "expect": expect}],
    }
    path = tmp_path / "ds.json"
    path.write_text(json.dumps(dataset), encoding="utf-8")
    return str(path)


def test_run_with_passing_dataset_exits_zero(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", write_dataset(tmp_path, {"alert": True})]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "Summary: 1 total, 1 passed, 0 failed, 0 errors" in out


def test_run_with_failing_dataset_exits_one(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", write_dataset(tmp_path, {"alert": False})]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "Summary: 1 total, 0 passed, 1 failed, 0 errors" in out


def test_run_json_output_parses(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", write_dataset(tmp_path, {"alert": True}), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"] == {"total": 1, "passed": 1, "failed": 0, "errors": 0}


def test_run_junit_output_parses(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", write_dataset(tmp_path, {"alert": True}), "--junit"]) == 0
    root = ET.fromstring(capsys.readouterr().out)
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "1"
    assert root.attrib["failures"] == "0"


def test_run_output_file_written(capsys, stub_client, tmp_path):
    stub_client()
    out_file = tmp_path / "report.txt"
    assert main(["run", write_dataset(tmp_path, {"alert": True}), "-o", str(out_file)]) == 0
    content = out_file.read_text(encoding="utf-8")
    assert "PASS" in content
    assert capsys.readouterr().out == ""


def test_run_output_file_unwritable_exits_one(capsys, stub_client, tmp_path):
    stub_client()
    out_file = tmp_path / "missing-dir" / "report.txt"
    assert main(["run", write_dataset(tmp_path, {"alert": True}), "-o", str(out_file)]) == 1
    assert "cannot write" in capsys.readouterr().err


def test_run_missing_dataset_exits_one(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", str(tmp_path / "nope.json")]) == 1
    assert "error:" in capsys.readouterr().err


def test_run_verbose_includes_checks(capsys, stub_client, tmp_path):
    stub_client()
    assert main(["run", write_dataset(tmp_path, {"alert": True}), "-v"]) == 0
    out = capsys.readouterr().out
    assert "alert: expected True, actual True" in out


def test_unknown_subcommand_exits_two(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["frobnicate"])
    assert excinfo.value.code == 2
    assert "usage" in capsys.readouterr().err


def test_no_arguments_prints_help_and_exits_two(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out


def test_help_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "usage" in capsys.readouterr().out


def test_logtest_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["logtest", "--help"])
    assert excinfo.value.code == 0


@pytest.mark.filterwarnings("ignore:.*found in sys.modules.*:RuntimeWarning")
def test_module_entry_point_runs_main(capsys, monkeypatch):
    import runpy

    monkeypatch.setattr(cli_module.sys, "argv", ["wlogtest.cli"])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("wlogtest.cli", run_name="__main__")
    assert excinfo.value.code == 2
    assert "usage" in capsys.readouterr().out
