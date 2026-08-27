from __future__ import annotations

import re
from dataclasses import dataclass, field

_MISSING = object()

MATCHER_KEYS = frozenset(
    {
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "nin",
        "contains",
        "regex",
        "exists",
        "any",
        "all",
    }
)


@dataclass
class CheckResult:
    path: str
    expected: object
    actual: object
    matched: bool
    reason: str = ""


@dataclass
class Verdict:
    case_name: str
    status: str
    checks: list = field(default_factory=list)
    error: str = ""
    actual: dict = field(default_factory=dict)


def _lookup(view: dict, path: str):
    if not path:
        return view
    current = view
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _validate_matcher(matcher: object, path: str) -> None:
    if not isinstance(matcher, dict):
        return
    if len(matcher) != 1:
        raise ValueError(
            f"invalid matcher at {path}: expected exactly one key, got {sorted(matcher)!r}"
        )
    op, value = next(iter(matcher.items()))
    if op not in MATCHER_KEYS:
        raise ValueError(f"unknown matcher key {op!r} at {path}")
    if op in ("any", "all"):
        if not isinstance(value, list):
            raise ValueError(f"matcher {op!r} at {path}: value must be a list")
        for index, sub in enumerate(value):
            _validate_matcher(sub, f"{path}[{index}]")


def validate_expectations(expect: dict, base: str = "expect") -> None:
    """Validate every matcher in an expect map, raising ValueError on bad keys."""
    for path, matcher in expect.items():
        _validate_matcher(matcher, f"{base}.{path}")


def _contains(actual, value: str) -> bool:
    if isinstance(actual, str):
        return value in actual
    if isinstance(actual, list):
        if value in actual:
            return True
        return any(isinstance(item, str) and value in item for item in actual)
    return value in str(actual)


def _match_value(matcher: object, actual) -> bool:
    """Evaluate one matcher against a possibly-missing actual value."""
    if isinstance(matcher, dict):
        if len(matcher) != 1:
            raise ValueError(
                f"matcher dict must have exactly one key, got {sorted(matcher)!r}"
            )
        op, value = next(iter(matcher.items()))
        if op not in MATCHER_KEYS:
            raise ValueError(f"unknown matcher key {op!r}")
        if op == "exists":
            present = actual is not _MISSING and actual is not None
            return present == bool(value)
        if op == "any":
            return any(_match_value(sub, actual) for sub in value)
        if op == "all":
            return all(_match_value(sub, actual) for sub in value)
        if actual is _MISSING:
            if op == "ne":
                return value is not None
            if op == "eq":
                return value is None
            if op == "nin":
                return True
            return False
        if op == "eq":
            return actual == value
        if op == "ne":
            return actual != value
        if op == "contains":
            return _contains(actual, value)
        if op == "regex":
            return re.search(value, str(actual)) is not None
        if op == "in":
            try:
                return actual in value
            except TypeError:
                return False
        if op == "nin":
            try:
                return actual not in value
            except TypeError:
                return False
        try:
            if op == "gt":
                return actual > value
            if op == "gte":
                return actual >= value
            if op == "lt":
                return actual < value
            if op == "lte":
                return actual <= value
        except TypeError:
            return False
    if matcher is None:
        return actual is _MISSING or actual is None
    if actual is _MISSING:
        return False
    return actual == matcher


def _check_path(path: str, matcher: object, view: dict) -> CheckResult:
    actual = _lookup(view, path)
    if isinstance(matcher, dict):
        matched = _match_value(matcher, actual)
    elif path == "messages" and isinstance(actual, list):
        matched = _contains(actual, matcher)
    else:
        matched = _match_value(matcher, actual)
    shown = None if actual is _MISSING else actual
    if matched:
        return CheckResult(path=path, expected=matcher, actual=shown, matched=True)
    if actual is _MISSING:
        reason = "field missing"
    else:
        reason = f"expected {matcher!r}, got {actual!r}"
    return CheckResult(
        path=path, expected=matcher, actual=shown, matched=False, reason=reason
    )


def evaluate(case_name: str, expect: dict, actual_data: dict) -> Verdict:
    """Compare expect matchers against a logtest response's data dict."""
    data = dict(actual_data or {})
    verdict = Verdict(case_name=case_name, status="pass", actual=data)
    output = data.get("output")
    view = dict(output) if isinstance(output, dict) else {}
    view["alert"] = data.get("alert")
    view["token"] = data.get("token")
    view["messages"] = data.get("messages", [])
    for path, matcher in (expect or {}).items():
        check = _check_path(path, matcher, view)
        verdict.checks.append(check)
        if not check.matched:
            verdict.status = "fail"
    return verdict
