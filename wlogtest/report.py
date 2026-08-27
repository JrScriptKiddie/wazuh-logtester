from __future__ import annotations

import json
from xml.sax.saxutils import escape

_ATTR_ENTITIES = {'"': "&quot;"}


def _escape_attr(value) -> str:
    return escape(str(value), _ATTR_ENTITIES)


def render_console(report, verbose: bool = False) -> str:
    lines = []
    summary = report.summary
    lines.append(
        f"Dataset: {report.dataset_name} "
        f"({summary['total']} tests, {report.duration_ms:.1f} ms)"
    )
    for index, result in enumerate(report.results, 1):
        verdict = result.verdict
        lines.append(f"[{index}] {verdict.status.upper()} {verdict.case_name}")
        if verdict.error:
            lines.append(f"    error: {verdict.error}")
        for check in verdict.checks:
            if verbose or not check.matched:
                line = (
                    f"    {check.path}: expected {check.expected!r}, "
                    f"actual {check.actual!r}"
                )
                if check.reason and not check.matched:
                    line += f" ({check.reason})"
                lines.append(line)
    lines.append(
        f"Summary: {summary['total']} total, {summary['passed']} passed, "
        f"{summary['failed']} failed, {summary['errors']} errors"
    )
    return "\n".join(lines)


def render_json(report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def render_junit_xml(report) -> str:
    summary = report.summary
    parts = []
    parts.append('<?xml version="1.0" encoding="utf-8"?>')
    parts.append(
        f'<testsuite name="{_escape_attr(report.dataset_name)}" '
        f'tests="{summary["total"]}" failures="{summary["failed"]}" '
        f'errors="{summary["errors"]}" skipped="0" '
        f'time="{report.duration_ms / 1000.0:.6f}">'
    )
    for result in report.results:
        verdict = result.verdict
        name = _escape_attr(verdict.case_name)
        classname = _escape_attr(report.dataset_name)
        if verdict.status == "pass":
            parts.append(
                f'  <testcase classname="{classname}" name="{name}" />'
            )
        elif verdict.status == "fail":
            reasons = [c.reason for c in verdict.checks if not c.matched]
            text = escape("\n".join(reasons) if reasons else "checks failed")
            parts.append(
                f'  <testcase classname="{classname}" name="{name}">'
            )
            parts.append(f'    <failure message="checks failed">{text}</failure>')
            parts.append("  </testcase>")
        else:
            text = escape(verdict.error or "logtest error")
            parts.append(
                f'  <testcase classname="{classname}" name="{name}">'
            )
            parts.append(f'    <error message="logtest error">{text}</error>')
            parts.append("  </testcase>")
    parts.append("</testsuite>")
    return "\n".join(parts) + "\n"
