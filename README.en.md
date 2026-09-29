# Wazuh Logtester

[Русский](README.md) · **English**

An offline sandbox for debugging Wazuh decoders and rules, plus a dataset
runner that replays log corpora and produces correlation verdicts. Everything
runs in Docker with zero network at runtime.

## What's inside

- **`wlogtest`** — a Python package (stdlib only): a client for the logtest
  protocol (socket `/var/ossec/queue/sockets/logtest`), the dataset model, a
  verdict engine, a runner with stateful sessions (frequency /
  if_matched_sid / firedtimes), reporters (console / JSON / JUnit) and the
  `wlogtest` CLI.
- **`manager`** — the `wlogtest-manager:4.14.7` image (built from
  `docker/Dockerfile`, `manager` stage): real analysisd 4.14.7 from the
  wazuh-manager RPM, without framework/API/wodles — only the log-processing
  engine (decoders → rules → correlation). Student decoders/rules are mounted
  at `/var/ossec/etc/decoders` and `/var/ossec/etc/rules`.
- **`runner`** — a `python:3.12-slim` container with the `wlogtest` package;
  it talks to the manager through the shared `/var/ossec/queue` volume (where
  the logtest unix socket lives).
- **`examples/`** — reference decoders/rules and datasets: `basic` (all
  green), `correlation` (stateful session, frequency rule), `fail_demo`
  (educational FAIL).
- **`vendor/wazuh/`** — sources forked from Wazuh v4.14.7 (GPL-2.0) as the
  protocol reference.
- **`skills/`** — AI-agent skills for this project (from skills.sh plus our own).

## Quick start (step by step)

Prerequisites: **docker + compose v2**
(https://docs.docker.com/engine/install/).

### Apple Silicon (arm64)

The `wazuh-manager` RPM ships for x86_64 only, so on Apple Silicon (and other
arm64 hosts) a build without the platform flag fails with
`package wazuh-manager-4.14.7-1.x86_64 is intended for a different
architecture`. Set the amd64 platform before running the stack — the image
will be built and executed under emulation (Rosetta in Docker Desktop):

```bash
export DOCKER_DEFAULT_PLATFORM=linux/amd64   # once per shell session
docker compose -f docker/docker-compose.yml build
```

or prefix every `docker compose ...` command with
`DOCKER_DEFAULT_PLATFORM=linux/amd64`. Nothing to set on x86 hosts; `runner`
and `runner-test` are also built for amd64 — not critical for them, but keep
the whole stack on one platform.

```bash
# 1) Clone the project
git clone https://github.com/JrScriptKiddie/wazuh-logtester.git
cd wazuh-logtester

# 2) Build the images (once, needs network: wazuh-manager RPM ~513 MB)
docker compose -f docker/docker-compose.yml build

# 3) Start the engine (analysisd) — wait for the healthcheck (logtest socket appears)
docker compose -f docker/docker-compose.yml up -d manager

# 4) First run: basic.json dataset — 3/3 PASS
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/basic.json

# 5) Correlation: frequency rule on a stateful session — 3/3 PASS
docker compose -f docker/docker-compose.yml run --rm runner run /data/datasets/correlation.json

# 6) One event by hand (3-phase output, like the original wazuh-logtest)
docker compose -f docker/docker-compose.yml run --rm runner \
  logtest -e "Aug 27 10:00:00 myserver myapp[1234]: login user=alice status=failed"
```

All subsequent runs work offline. The `logtest` output shows the same three
phases as the original `wazuh-logtest` (pre-decoding → decoding → rule
matching):

```
**Phase 1: Completed pre-decoding.
	full event: 'Aug 27 10:00:00 myserver myapp[1234]: login user=alice status=failed'
	timestamp: 'Aug 27 10:00:00'
	hostname: 'myserver'
	program_name: 'myapp'

**Phase 2: Completed decoding.
	name: 'myapp_decoder'
	dstuser: 'alice'
	status: 'failed'

**Phase 3: Completed filtering (rules).
	id: '100101'
	level: '6'
	description: 'myapp: user login failed.'
	groups: '['hw', 'local']'
	firedtimes: '1'
	mail: 'False'
**Alert to be generated.
```

The `--json` flag prints the raw protocol JSON (useful for debugging); the
`--debug` flag enables per-rule tracing (`**Rule debugging:` in the output).

Interactive mode with a persistent session:

```bash
docker compose -f docker/docker-compose.yml run --rm runner logtest -i
```

## Dataset format

```json
{
  "name": "hw1",
  "description": "correlation homework check",
  "session_mode": "per_test",        // or "shared" — one session for all cases
  "default_location": "stdin",
  "default_log_format": "syslog",
  "tests": [
    {
      "name": "ssh failed password",
      "event": "Aug 27 10:00:00 myserver sshd[1234]: Failed password ...",
      "location": "auth.log",         // overrides the default (optional)
      "session": "bruteforce",        // named session (optional)
      "skip": false,
      "expect": {
        "decoder.name": "sshd",
        "data.srcip": "1.2.3.4",
        "rule.id": "5710",
        "alert": true
      }
    }
  ]
}
```

`expect` checks logtest response fields: `decoder.name`, `rule.id`,
`rule.level`, `rule.description`, `rule.firedtimes`, `data.<field>`,
`full_log`, `alert`, `messages`, `token`.

### Matchers

| Format | Semantics |
|---|---|
| `"value"` / number / `true` / `null` | exact equality (`null` — field absent) |
| `{"eq": v}` / `{"ne": v}` | equals / not equals |
| `{"gt": n}` / `{"gte": n}` / `{"lt": n}` / `{"lte": n}` | comparisons |
| `{"in": [...]}` / `{"nin": [...]}` | in list / not in list |
| `{"contains": "string"}` | substring (or item/substring in the `messages` list) |
| `{"regex": "pattern"}` | `re.search` against the string form |
| `{"exists": true\|false}` | field present / absent |
| `{"any": [m1, m2]}` / `{"all": [m1, m2]}` | OR / AND over nested matchers |

A plain value (no matcher object) for `messages` behaves like `contains` over
any list item — e.g. `"messages": "No decoder matched"`.

### Correlation

Stateful rules (`<frequency>`, `if_matched_sid`, the firedtimes counter) only
work when the cases share a session. Use `"session_mode": "shared"` — the
runner obtains one token and replays all events through it (see
`examples/datasets/correlation.json`: the frequency rule 100102 fires on the
third identical event). Named sessions (`"session": "name"`) work in any mode
and let you run several independent correlation chains within one dataset.

Output: a console report with `[PASS]/[FAIL]/[ERROR]` lines and mismatch
reasons; `--json` — the full report; `--junit` — XML for CI; `-o report.txt`
writes to a file. Exit code: 0 — all cases PASS, 1 — any FAIL/ERROR.

## Your own decoders and rules

Drop files into `examples/decoders/` and `examples/rules/` (or mount your own
directories in `docker/docker-compose.yml`), then restart the manager:

```bash
docker compose -f docker/docker-compose.yml restart manager
```

XML errors appear in the `messages` field of the response (e.g.
`ERROR: (1203): Invalid configuration ...`) and in the report as `error`
status.

## Fully offline (air-gapped classroom)

1. On a networked machine: `docker compose -f docker/docker-compose.yml build manager runner runner-test`
   (the manager stage downloads the wazuh-manager 4.14.7 RPM ~513 MB — once).
2. `docker save wlogtest-manager:4.14.7 wlogtest-runner wlogtest-runner-builder python:3.12-slim | gzip > wlogtest-images.tar.gz`
3. In the classroom: `docker load < wlogtest-images.tar.gz` — done.

## Development and tests

```bash
make test          # unit tests (python3 -m pytest), no Docker needed
make cov           # wlogtest coverage (>= 85% gate)
make test-docker   # full in-docker validation (build, compose, pytest, datasets)
make build up down # stack management
```

`tests/integration/` activate automatically when the logtest socket is
reachable (`WAZUH_LOGTEST_SOCKET` env); `docker/test.sh` runs unit and
integration tests inside the containers and checks all example datasets.

## Project layout

See `AGENTS.md` (AI-agent rules) and `docs/DESIGN.md` (API and protocol
contracts). Vendored Wazuh sources: `vendor/wazuh/README.md`.
