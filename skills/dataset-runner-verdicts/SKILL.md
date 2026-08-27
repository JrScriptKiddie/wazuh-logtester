---
name: dataset-runner-verdicts
description: Dataset JSON schema, matcher operators, and pass/fail/error verdict semantics for wlogtest, including per_test/shared/named session modes. Use when writing or changing wlogtest/dataset.py, verdict.py, runner.py, example datasets, or their tests.
---

# Dataset runner verdicts

Contract for the dataset → verdict pipeline in `wlogtest/`. `docs/DESIGN.md` is the
single source of truth; this skill is the condensed version implementers and
test-engineers follow.

## Dataset JSON format

Top level:

| key | type | default | notes |
|---|---|---|---|
| `name` | str | required | non-empty |
| `description` | str | `""` | |
| `default_location` | str | `"stdin"` | per-case override possible |
| `default_log_format` | str | `"syslog"` | per-case override possible |
| `session_mode` | str | `"per_test"` | `"per_test"` or `"shared"` |
| `tests` | list | required | list of case objects |

Case object:

| key | type | default | notes |
|---|---|---|---|
| `name` | str | required | |
| `event` | str | required | |
| `expect` | dict | `{}` | matcher map; empty means "just run it" |
| `location` | str | dataset default | |
| `log_format` | str | dataset default | |
| `session` | str | `None` | named session for correlation |
| `skip` | bool | `false` | |

JSON is always supported; YAML only when PyYAML is importable (optional dev
convenience). Validation failures raise `DatasetError` with path + reason; unknown
matcher keys raise too, naming the offending path.

## Matcher operators

Field paths are dotted, evaluated against this view dict:

```python
view = {"alert": data["alert"], "token": data["token"],
        "messages": data["messages"], **data.get("output", {})}
```

`messages` is a list: matchers against it use `contains` (membership of any item)
unless an explicit matcher object is given.

| form | semantics |
|---|---|
| plain scalar / str / number / bool | exact equality |
| `null` | field is absent or null |
| `{"eq": v}` | equal |
| `{"ne": v}` | not equal |
| `{"gt": n}` / `{"gte": n}` / `{"lt": n}` / `{"lte": n}` | ordering |
| `{"in": [...]}` / `{"nin": [...]}` | membership / non-membership |
| `{"contains": s}` | substring; list membership when actual is a list |
| `{"regex": "pattern"}` | `re.search` on `str(actual)` |
| `{"exists": bool}` | path present and not None (true) or absent (false) |
| `{"any": [m1, m2, ...]}` | at least one nested matcher holds |
| `{"all": [m1, m2, ...]}` | all nested matchers hold |

## Verdict semantics

- `CheckResult(path, expected, actual, matched, reason="")`.
- `Verdict(case_name, status, checks, error, actual)` with
  `status` in `"pass" | "fail" | "error"`:
  - `pass` — every check matched (empty `expect` passes vacuously, no checks);
  - `fail` — one or more checks did not match;
  - `error` — logtest raised for the case; `error` string carries the message.
- `evaluate(case_name, expect, actual_data)` takes `actual_data = response["data"]`
  from `LogtestClient.run_log`.

## Session modes (DatasetRunner)

- `"per_test"`: fresh token per case, removed afterwards.
- `"shared"`: one token for all unnamed cases in order.
- Named sessions (`case.session` set): honored in BOTH modes — one token per
  session key, reused across cases with that key, in order.
- `CaseResult` records the `session` key and `token` used for each case.
- On `LogtestError`/`LogtestTransportError` mid-case: verdict `"error"`, then
  continue with the next case. A fresh token carried by a
  `LogtestProcessingError` (server rotated the session) replaces the stored
  token for that session key.
- After the run: `remove_session` for every live token, best effort.
- `RunReport.passed` is true only when every verdict is `"pass"`; `summary` returns
  `{"total", "passed", "failed", "errors"}`; `to_dict()` returns
  `{"dataset", "summary", "duration_ms", "results"}`.

## Example expectations

```json
{"expect": {"alert": true, "rule.id": "100100", "output.full_log": {"contains": "myapp"}}}
```

Frequency rules only fire with a shared session token: put the correlated cases in
a `"shared"` dataset or give them the same `"session"` key.
