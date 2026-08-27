from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - depends on optional dependency
    yaml = None

from wlogtest.verdict import validate_expectations


class DatasetError(Exception):
    """Invalid dataset file; message includes path + reason."""


@dataclass
class TestCase:
    name: str
    event: str
    expect: dict
    location: str | None = None
    log_format: str | None = None
    session: str | None = None
    skip: bool = False


@dataclass
class Dataset:
    name: str
    description: str = ""
    default_location: str = "stdin"
    default_log_format: str = "syslog"
    session_mode: str = "per_test"
    tests: list = field(default_factory=list)


def _parse_test(item: object, path: str, index: int) -> TestCase:
    case_path = f"{path}:tests[{index}]"
    if not isinstance(item, dict):
        raise DatasetError(f"{case_path}: test case must be an object")
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        raise DatasetError(f"{case_path}: 'name' must be a non-empty string")
    event = item.get("event")
    if not isinstance(event, str):
        raise DatasetError(f"{case_path}: 'event' must be a string")
    expect = item.get("expect", {})
    if not isinstance(expect, dict):
        raise DatasetError(f"{case_path}: 'expect' must be an object")
    try:
        validate_expectations(expect, f"{case_path}.expect")
    except ValueError as exc:
        raise DatasetError(str(exc)) from exc
    location = item.get("location")
    if location is not None and not isinstance(location, str):
        raise DatasetError(f"{case_path}: 'location' must be a string or null")
    log_format = item.get("log_format")
    if log_format is not None and not isinstance(log_format, str):
        raise DatasetError(f"{case_path}: 'log_format' must be a string or null")
    session = item.get("session")
    if session is not None and not isinstance(session, str):
        raise DatasetError(f"{case_path}: 'session' must be a string or null")
    skip = item.get("skip", False)
    if not isinstance(skip, bool):
        raise DatasetError(f"{case_path}: 'skip' must be a boolean")
    return TestCase(
        name=name,
        event=event,
        expect=expect,
        location=location,
        log_format=log_format,
        session=session,
        skip=skip,
    )


def _from_raw(raw: object, path: str) -> Dataset:
    if not isinstance(raw, dict):
        raise DatasetError(f"{path}: dataset must be a JSON/YAML object")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise DatasetError(f"{path}: 'name' must be a non-empty string")
    description = raw.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise DatasetError(f"{path}: 'description' must be a string")
    default_location = raw.get("default_location", "stdin")
    if not isinstance(default_location, str) or not default_location:
        raise DatasetError(f"{path}: 'default_location' must be a non-empty string")
    default_log_format = raw.get("default_log_format", "syslog")
    if not isinstance(default_log_format, str) or not default_log_format:
        raise DatasetError(f"{path}: 'default_log_format' must be a non-empty string")
    session_mode = raw.get("session_mode", "per_test")
    if session_mode not in ("per_test", "shared"):
        raise DatasetError(f"{path}: 'session_mode' must be 'per_test' or 'shared'")
    raw_tests = raw.get("tests")
    if not isinstance(raw_tests, list):
        raise DatasetError(f"{path}: 'tests' must be a list")
    tests = [_parse_test(item, path, index) for index, item in enumerate(raw_tests)]
    return Dataset(
        name=name,
        description=description,
        default_location=default_location,
        default_log_format=default_log_format,
        session_mode=session_mode,
        tests=tests,
    )


def load_dataset(path: str) -> Dataset:
    """Load a dataset from a JSON (always) or YAML (if PyYAML installed) file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise DatasetError(f"{path}: cannot read file: {exc}") from exc
    try:
        raw = json.loads(text)
    except ValueError:
        if yaml is None:
            raise DatasetError(
                f"{path}: not valid JSON (install PyYAML to load YAML datasets)"
            ) from None
        try:
            raw = yaml.safe_load(text)
        except Exception as exc:
            raise DatasetError(f"{path}: not valid JSON or YAML: {exc}") from exc
    return _from_raw(raw, path)
