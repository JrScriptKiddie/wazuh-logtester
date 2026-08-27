from __future__ import annotations

import json
from xml.sax.saxutils import escape

_ATTR_ENTITIES = {'"': "&quot;"}


def _escape_attr(value) -> str:
    return escape(str(value), _ATTR_ENTITIES)


def _phase_info(phase_data: dict, show_first: list | None = None, prefix: str = "") -> list:
    """Replica of wazuh-logtest's show_phase_info: ordered fields first, then the
    rest sorted; nested dicts recurse with a dotted prefix."""
    lines = []
    show_first = show_first or []
    remaining = dict(phase_data)
    for field in show_first:
        if field in remaining:
            lines.append("\t%s: '%s'" % (field, remaining.pop(field)))
    for field in sorted(remaining):
        value = remaining[field]
        if isinstance(value, dict):
            lines.extend(_phase_info(value, [], prefix + field + "."))
        else:
            lines.append("\t%s: '%s'" % (prefix + field, value))
    return lines


def render_phases(data: dict) -> str:
    """Render a logtest response the way the official wazuh-logtest CLI does:
    three phases (pre-decoding, decoding, rule filtering) plus the alert note."""
    response = dict(data or {})
    output = dict(response.get("output") or {})
    lines = []
    lines.append("**Phase 1: Completed pre-decoding.")
    if "full_log" in output:
        lines.append("\tfull event: '%s'" % output["full_log"])
    predecoder = output.get("predecoder")
    if isinstance(predecoder, dict):
        lines.extend(_phase_info(predecoder, ["timestamp", "hostname", "program_name"]))
    lines.append("")
    lines.append("**Phase 2: Completed decoding.")
    decoder = output.get("decoder")
    if decoder:
        lines.extend(_phase_info(decoder, ["name", "parent"]))
        if isinstance(output.get("data"), dict):
            lines.extend(_phase_info(output["data"]))
    else:
        lines.append("\tNo decoder matched.")
    if response.get("rules_debug"):
        lines.append("")
        lines.append("**Rule debugging:")
        for debug_msg in response["rules_debug"]:
            prefix = "\t\t" if str(debug_msg).startswith("*") else "\t"
            lines.append(prefix + str(debug_msg))
    rule = output.get("rule")
    if rule:
        lines.append("")
        lines.append("**Phase 3: Completed filtering (rules).")
        lines.extend(_phase_info(rule, ["id", "level", "description", "groups", "firedtimes"]))
    if response.get("alert"):
        lines.append("**Alert to be generated.")
    return "\n".join(lines)


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
                if check.reason and not check.matched and not check.reason.startswith("expected "):
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
