---
name: wazuh-logtest-domain
description: Wazuh 4.14.7 logtest protocol facts: unix socket path, 4-byte little-endian framing, request envelope, log_processing and remove_session commands, stateful token sessions, and response/error semantics. Use whenever writing or debugging the wlogtest protocol client, decoder/rule XML, or anything that talks to the logtest socket.
---

# Wazuh logtest domain

Reference facts for the Wazuh 4.14.7 logtest service (analysisd's rule-test engine).
These are verified against `vendor/wazuh/` sources — do not re-derive, and do not edit
`vendor/wazuh/**` (GPL-2.0; attribution lives in `vendor/wazuh/README.md`).

## Transport and framing

- Socket: AF_UNIX stream at `/var/ossec/queue/sockets/logtest`.
  `WAZUH_LOGTEST_SOCKET` env var overrides the path.
- Framing: `struct.pack("<I", len(payload)) + payload`, payload is UTF-8 JSON.
  Max payload 65536 bytes.
- One connection per request/response; the server closes after each reply.

## Request envelope and commands

```json
{"version": 1, "origin": {"name": "Logtest", "module": "framework"},
 "command": "<str>", "parameters": {<dict>}}
```

- `log_processing` parameters:
  - `event` (str or dict, required)
  - `location` (str, required)
  - `log_format` (str, required)
  - `token` (optional, 8 hex chars)
  - `options` (optional dict; only `rules_debug` bool is honored)
- `remove_session` parameters: `{"token": <str>}`

## Sessions are stateful

- A session token is 8 hex chars, returned in the response `data.token`.
- Correlation operators (`frequency`, `if_matched_sid`, `firedtimes`) accumulate
  state per session: cases that should correlate must share the same token.
- Finish sessions with `remove_session` so state doesn't leak across runs.

## Response and error semantics

```json
{"error": <int>, "data": {<...>}, "message"?: <str>}
```

- `error == 0` means ok; on `error != 0` the caller raises (see `wlogtest/client.py`).
- `data` fields: `token`, `messages` (list of strings), `output` (the alert dict:
  rule/decoder/data/full_log/...), `alert` (bool), `codemsg`:
  - `-1` error (raise `LogtestProcessingError`)
  - `0` ok
  - `1` warn (processed, with warnings)

## Configuration and custom content

- `<rule_test>` must be enabled in the manager's ossec.conf for the logtest socket
  to exist. Useful defaults: `<enabled>yes</enabled> <threads>2</threads>
  <max_sessions>64</max_sessions> <session_timeout>15m</session_timeout>`.
- Custom decoders are loaded from `/var/ossec/etc/decoders/*.xml`.
- Custom rules are loaded from `/var/ossec/etc/rules/*.xml`.
- Decoder/rules XML authoring and logtest usage patterns: see the vendored
  `implementing-endpoint-detection-with-wazuh` skill.
- Protocol reference source of truth: `vendor/wazuh/` (logtest server and client
  sources from wazuh/wazuh v4.14.7).

## Checks when debugging

- Payload larger than 65536 bytes fails before the server sees it — treat as
  transport error.
- Broken framing / non-JSON replies are protocol errors, not analysis errors.
- A missing `token` in `data` means the session was not created; frequency-based
  rules will never fire without a shared token.
