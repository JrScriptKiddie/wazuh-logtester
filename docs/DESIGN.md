# DESIGN.md — wazuh-logtest-offline

Single source of truth for module APIs. Agents implementing/touching code MUST follow
these signatures exactly; tests are written against this contract.

## Architecture

```
host (students)                    docker network
┌─────────────────────────────┐    ┌───────────────────────────┐
│ docker compose run runner   │    │ manager (wazuh-manager)   │
│  wlogtest run /data/ds.json ├──► │ analysisd (logtest server)│
│  python:3.12-slim image     │    │ /var/ossec/etc/decoders   │
└──────────┬──────────────────┘    │ /var/ossec/etc/rules      │
           └── shared volume: /var/ossec/queue ──► socket logtest
```

- `wazuh/wazuh-manager:4.14.7` is the logtest engine (analysisd). Custom decoders/rules
  are bind-mounted into `/var/ossec/etc/decoders|rules`. `<rule_test>` enabled in
  `docker/config/ossec.conf`.
- `runner` image = `python:3.12-slim` + our `wlogtest` package (no runtime deps).
- Socket shared via named volume `wazuh-queue:/var/ossec/queue`.

## Protocol (wazuh 4.14.7, verified against vendor/wazuh sources)

- Transport: AF_UNIX stream at `/var/ossec/queue/sockets/logtest`
  (`WAZUH_LOGTEST_SOCKET` env overrides).
- Framing: `struct.pack("<I", len(payload)) + payload` (UTF-8 JSON). Max 65536.
- One connection per request/response; server closes after reply.
- Request envelope: `{"version": 1, "origin": {"name": "Logtest", "module": "framework"},
  "command": <str>, "parameters": <dict>}`.
- `log_processing` parameters: `event` (str|dict, required), `location` (str, required),
  `log_format` (str, required), `token` (optional 8-hex), `options` (optional dict;
  only `rules_debug` bool honored).
- `remove_session` parameters: `{"token": <str>}`.
- Response: `{"error": int, "data": {...}, "message"?: str}`. `error==0` ok; on
  `error!=0` raise. `data`: `token`, `messages` (list[str]), `output` (alert dict:
  rule/decoder/data/full_log/...), `alert` (bool), `codemsg` (-1 error / 0 ok / 1 warn).

## Package `wlogtest` (Python >= 3.9, stdlib only)

### wlogtest/__init__.py
- `__version__ = "1.0.0"`

### wlogtest/client.py
```python
class LogtestError(Exception):            # .code = top-level error int, .message str
class LogtestProcessingError(LogtestError):  # codemsg == -1
class LogtestTransportError(Exception):   # socket/connect/IO/timeout
class LogtestProtocolError(LogtestTransportError):  # bad framing/JSON in reply

def create_wazuh_socket_message(origin, command, parameters) -> dict  # envelope per protocol

class LogtestClient:
    def __init__(self, socket_path: str | None = None, timeout: float = 10.0) -> None
        # default socket_path from env WAZUH_LOGTEST_SOCKET or "/var/ossec/queue/sockets/logtest"
    def send(self, command: str, parameters: dict) -> dict
        # returns full response dict {error, data, ...}; raises LogtestError if error != 0
    def run_log(self, event, location="stdin", log_format="syslog",
                token=None, options=None) -> dict
        # returns response["data"]; convenience wrapper around send("log_processing", ...)
    def remove_session(self, token: str) -> dict
    def close(self) -> None   # no-op safety; connections are per-request
```

### wlogtest/dataset.py
```python
class DatasetError(Exception)   # invalid dataset file; message includes path + reason

class TestCase:      # dataclass
    name: str
    event: str
    expect: dict                    # matcher map (see verdict.py); may be empty -> just runs
    location: str | None = None     # override dataset default
    log_format: str | None = None
    session: str | None = None      # named session for correlation (None = per-test session)
    skip: bool = False

class Dataset:       # dataclass
    name: str
    description: str = ""
    default_location: str = "stdin"
    default_log_format: str = "syslog"
    session_mode: str = "per_test"  # "per_test" | "shared" ("shared" == all cases, one session)
    tests: list[TestCase] = field(default_factory=list)

def load_dataset(path: str) -> Dataset
# JSON always. YAML also supported if yaml importable (optional dev convenience).
# Validation: name non-empty; every test has event (str) + name; expect is dict if present;
# unknown matcher keys -> DatasetError listing offending path.
```

### wlogtest/verdict.py
Field paths are dotted, evaluated against a *view* dict:
`view = {"alert": data["alert"], "token": data["token"], "messages": data["messages"],
**data.get("output", {})}`. `messages` is a list; matchers on it use `contains`
(list membership of any) unless the matcher object is used.

Matcher spec (value in `expect`):
- plain scalar/str/number/bool/null → exact equality (`null` means field is absent/null)
- `{"eq": v}`, `{"ne": v}`, `{"gt": n}`, `{"gte": n}`, `{"lt": n}`, `{"lte": n}`
- `{"in": [...]}`, `{"nin": [...]}`
- `{"contains": s}` — string containment (or list membership when actual is a list)
- `{"regex": "pattern"}` — `re.search` on str(actual)
- `{"exists": bool}` — field presence (path must exist and not be None)
- `{"any": [m1, m2, ...]}`, `{"all": [m1, m2, ...]}` — nested matchers

```python
@dataclass
class CheckResult:
    path: str; expected: object; actual: object; matched: bool; reason: str = ""

@dataclass
class Verdict:
    case_name: str
    status: str          # "pass" | "fail" | "error"
    checks: list[CheckResult] = field(default_factory=list)
    error: str = ""      # set when logtest raised -> status "error"
    actual: dict = field(default_factory=dict)  # raw response data (for reports)

def evaluate(case_name: str, expect: dict, actual_data: dict) -> Verdict
# actual_data = response["data"] from LogtestClient.run_log
# empty expect -> verdict passes vacuously (status "pass", no checks)
```

### wlogtest/runner.py
```python
@dataclass
class CaseResult:
    verdict: Verdict
    session: str        # session key used
    token: str          # session token used ("" if none)

@dataclass
class RunReport:
    dataset_name: str
    results: list[CaseResult]
    duration_ms: float
    @property
    def passed(self) -> bool          # all status == "pass"
    @property
    def summary(self) -> dict         # {"total","passed","failed","errors"}
    def to_dict(self) -> dict         # {"dataset", "summary", "duration_ms", "results": [...]}

class DatasetRunner:
    def __init__(self, client: LogtestClient, dataset: Dataset) -> None
    def run(self) -> RunReport
# Session logic: session_mode "per_test" -> fresh token per case (removed afterwards).
# "shared" or named sessions -> one token per session key, reused across cases in order.
# On LogtestError during a case: verdict status "error", continue with next case.
# After run: remove_session for every live token (best effort).
```

### wlogtest/report.py
```python
def render_console(report: RunReport, verbose: bool = False) -> str
def render_json(report: RunReport) -> str          # json.dumps(report.to_dict(), indent=2)
def render_junit_xml(report: RunReport) -> str     # testsuite XML; failure text = check reasons
```

### wlogtest/cli.py
argparse, stdlib only. `main(argv=None) -> int` (exit code).
```
wlogtest logtest [-e EVENT | -i] [-l LOCATION] [-f FORMAT] [--token TOKEN]
                 [--debug] [--end-session] [--socket PATH]
    # -e: single event; -i: interactive REPL (persistent session); stdin lines if piped.
    # prints response data as indented JSON; exit 0 if error==0 and codemsg != -1, else 1
wlogtest run DATASET [--socket PATH] [--json|--junit] [--verbose] [-o FILE]
    # prints console report to stdout (or file via -o; with --json/--junit prints that format)
    # exit 0 iff report.passed else 1
wlogtest version
```
Module entry: `python3 -m wlogtest.cli`. Console script `wlogtest` in pyproject.toml.

## pyproject.toml
- name `wazuh-logtest-offline`, version 1.0.0, requires-python >= 3.9
- dependencies: none. optional: `[project.optional-dependencies] yaml = ["PyYAML>=6"]`
- dev (pytest, pytest-cov), `[project.scripts] wlogtest = "wlogtest.cli:main"`
- `[tool.pytest.ini_options]` markers: `integration` (deselected by default addopts `-m "not integration"`)

## Tests (test-engineer)
- `tests/unit/test_client.py` — framing bytes (struct, header), envelope shape, error paths
  (error!=0 → LogtestError; codemsg -1 → LogtestProcessingError; broken frame; short read;
  timeout; oversized payload > 65536 → LogtestTransportError), run_log/remove_session args.
  Use a fake socket via `unittest.mock.patch` on `socket.socket`.
- `tests/unit/test_verdict.py` — every matcher op incl. null, exists, any/all, nested
  paths, messages contains, regex, in/nin; unknown matcher key raises ValueError.
- `tests/unit/test_dataset.py` — valid JSON roundtrip, YAML (skip if no yaml), all
  validation error cases (missing name/event, bad expect type, unknown matcher).
- `tests/unit/test_runner.py` — FakeLogtestClient (scripted responses) covering:
  per_test sessions, shared session token reuse, named sessions, error case -> "error"
  verdict and continuation, remove_session called, empty expect passes, duration set.
- `tests/unit/test_report.py` — console/json/junit renderers on a constructed report;
  junit XML well-formed (xml.etree parses); failing report exit logic covered via cli tests.
- `tests/unit/test_cli.py` — logtest single event, run with fake socket (patch
  LogtestClient), exit codes 0/1, --json/--junit output, version.
- `tests/integration/test_live_logtest.py` — marker `integration`; skips unless
  `WAZUH_LOGTEST_SOCKET` reachable; smoke: send event, expect response schema fields.
- Coverage gate: `python3 -m pytest --cov=wlogtest --cov-report=term-missing` >= 85%.

## examples/ (implementer)
- `examples/decoders/9999_hw_decoders.xml` — custom decoder for student logs
  (program `myapp`: `<program_name>myapp</program_name>`, regex extracts fields e.g. user, action).
- `examples/rules/9999_hw_rules.xml` — rule 100100 (level 5, single event, fields),
  rule 100101 (child, if_sid 100100), rule 100102 (frequency 3 in 60s, level 10 — correlation).
- `examples/datasets/basic.json` — decoders+single rules verdicts (all pass).
- `examples/datasets/correlation.json` — shared session; 3× same event; last case expects
  rule 100102 (frequency rule) → proves stateful session + firedtimes.
- `examples/datasets/fail_demo.json` — intentionally wrong expectations (expect rule 100999)
  to demonstrate FAIL verdicts and non-zero exit (educational).

## docker/ (infra)
- `docker/Dockerfile` — multi-stage: stage 1 `python:3.12-slim` builds wheel
  (`pip wheel . --no-deps`), stage 2 `python:3.12-slim` installs wheel, sets
  `ENV WAZUH_LOGTEST_SOCKET=/var/ossec/queue/sockets/logtest`, `ENTRYPOINT ["wlogtest"]`,
  non-root not required (root needed for socket perms), image tagged `wlogtest-runner`.
- `docker/docker-compose.yml` — services:
  - `manager`: image `wazuh/wazuh-manager:4.14.7`; volumes:
    `./config/ossec.conf:/wazuh-config-mount/etc/ossec.conf:ro`,
    `../../examples/decoders:/var/ossec/etc/decoders:ro`,
    `../../examples/rules:/var/ossec/etc/rules:ro`,
    `wazuh-queue:/var/ossec/queue`; healthcheck:
    `test -S /var/ossec/queue/sockets/logtest` (start_period 60s).
  - `runner`: build `.` (context repo root, dockerfile docker/Dockerfile); volumes:
    `wazuh-queue:/var/ossec/queue:ro`, `../../examples:/data:ro`; `depends_on: manager:
    condition: service_healthy`; default command `run /data/datasets/basic.json`.
- `docker/config/ossec.conf` — default 4.14.7 manager ossec.conf (fetch from
  wazuh/wazuh-docker v4.14.7 `single-node/config/wazuh_cluster/wazuh_manager.conf`) with
  `<rule_test><enabled>yes</enabled><threads>2</threads><max_sessions>64</max_sessions>
  <session_timeout>15m</session_timeout></rule_test>` ensured; ruleset keeps
  `etc/decoders` + `etc/rules` dirs.
- `docker/test.sh` — `docker compose up -d manager` → wait for socket (timeout 120s) →
  `docker compose build runner` → `docker compose run --rm runner run /data/datasets/basic.json` +
  correlation dataset → `docker compose run --rm -e WAZUH_LOGTEST_SOCKET=... -v
  $(pwd):/src runner sh -c "pytest"` (unit+integration inside docker) → teardown. Exit code
  reflects test results. Print fresh output of every step.
- `Makefile` — `test` (python3 -m pytest), `test-docker` (docker/test.sh), `build`,
  `up`, `down`, `cov` (pytest --cov with gate check).
- `docker/README.md` — offline usage instructions for students (pull once, then run
  with `--network none` style instructions; note docker is unavailable on this dev host).

## README.md (root, Russian)
Student-facing: what it is, quickstart (docker compose), CLI examples, dataset format
spec with matcher reference table, correlation explanation, how to add own decoders/rules.
