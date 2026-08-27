from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from wlogtest.report import render_console, render_json, render_junit_xml
from wlogtest.runner import CaseResult, RunReport
from wlogtest.verdict import CheckResult, Verdict


def make_report():
    pass_verdict = Verdict(
        case_name="ok case",
        status="pass",
        checks=[CheckResult(path="alert", expected=True, actual=True, matched=True)],
        actual={"alert": True},
    )
    fail_verdict = Verdict(
        case_name="bad case",
        status="fail",
        checks=[
            CheckResult(path="alert", expected=True, actual=True, matched=True),
            CheckResult(
                path="rule.id",
                expected="100100",
                actual="100999",
                matched=False,
                reason="expected '100100', got '100999'",
            ),
        ],
        actual={"alert": True},
    )
    error_verdict = Verdict(
        case_name="err case", status="error", error="server exploded"
    )
    return RunReport(
        dataset_name="my dataset",
        duration_ms=1234.5,
        results=[
            CaseResult(verdict=pass_verdict, session="__case_0", token="aaa"),
            CaseResult(verdict=fail_verdict, session="shared", token="bbb"),
            CaseResult(verdict=error_verdict, session="__case_2", token=""),
        ],
    )


def test_console_contains_status_lines_and_reasons():
    out = render_console(make_report())
    assert "[1] PASS ok case" in out
    assert "[2] FAIL bad case" in out
    assert "[3] ERROR err case" in out
    assert "expected '100100', got '100999'" in out
    assert "error: server exploded" in out
    assert "Dataset: my dataset (3 tests, 1234.5 ms)" in out
    assert "Summary: 3 total, 1 passed, 1 failed, 1 errors" in out


def test_console_verbose_includes_matched_checks():
    out = render_console(make_report(), verbose=True)
    assert "alert: expected True, actual True" in out
    out = render_console(make_report(), verbose=False)
    assert "alert: expected True, actual True" not in out


def test_console_does_not_add_reason_to_matched_checks():
    verdict = Verdict(
        case_name="v",
        status="pass",
        checks=[CheckResult("x", 1, 1, True, reason="ignored")],
    )
    report = RunReport(dataset_name="d", results=[CaseResult(verdict, "s", "t")])
    out = render_console(report, verbose=True)
    assert "(ignored)" not in out


def test_json_renders_parseable_dict_with_summary():
    out = render_json(make_report())
    data = json.loads(out)
    assert data["dataset"] == "my dataset"
    assert data["summary"] == {"total": 3, "passed": 1, "failed": 1, "errors": 1}
    assert data["results"][1]["status"] == "fail"
    assert data["results"][1]["checks"][1]["reason"].startswith("expected")
    assert data["results"][2]["error"] == "server exploded"


def test_junit_xml_is_well_formed():
    out = render_junit_xml(make_report())
    root = ET.fromstring(out)
    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "3"
    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "1"
    assert root.attrib["name"] == "my dataset"
    cases = root.findall("testcase")
    assert len(cases) == 3
    assert cases[0].attrib["name"] == "ok case"
    assert len(cases[0]) == 0
    failure = cases[1].find("failure")
    assert failure is not None
    assert "expected '100100', got '100999'" in (failure.text or "")
    error = cases[2].find("error")
    assert error is not None
    assert "server exploded" in (error.text or "")


def test_junit_failure_without_reasons_has_placeholder():
    verdict = Verdict(case_name="f", status="fail", checks=[])
    report = RunReport(dataset_name="d", results=[CaseResult(verdict, "s", "t")])
    root = ET.fromstring(render_junit_xml(report))
    failure = root.find("testcase/failure")
    assert (failure.text or "").strip() == "checks failed"


def test_junit_error_without_message_has_placeholder():
    verdict = Verdict(case_name="e", status="error")
    report = RunReport(dataset_name="d", results=[CaseResult(verdict, "s", "t")])
    root = ET.fromstring(render_junit_xml(report))
    error = root.find("testcase/error")
    assert (error.text or "").strip() == "logtest error"


def test_junit_escapes_special_characters():
    verdict = Verdict(case_name='a <b> & "c"', status="pass")
    report = RunReport(dataset_name='ds & "x"', results=[CaseResult(verdict, "s", "t")])
    root = ET.fromstring(render_junit_xml(report))
    assert root.attrib["name"] == 'ds & "x"'
    assert root.find("testcase").attrib["name"] == 'a <b> & "c"'
