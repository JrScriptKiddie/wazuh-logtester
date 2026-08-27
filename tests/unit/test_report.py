from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from wlogtest.report import render_console, render_json, render_junit_xml, render_phases
from wlogtest.runner import CaseResult, RunReport
from wlogtest.verdict import CheckResult, Verdict

REALISTIC_DATA = {
    "token": "8cd2d6d1",
    "messages": ["INFO: (7202): Session initialized with token '8cd2d6d1'"],
    "output": {
        "timestamp": "2026-08-27T10:00:00.000+0000",
        "rule": {
            "level": 6,
            "description": "myapp: user login failed.",
            "id": "100101",
            "firedtimes": 1,
            "mail": False,
            "groups": ["hw", "local"],
        },
        "full_log": "Aug 27 10:00:01 myserver myapp[1234]: login user=bob status=failed",
        "predecoder": {
            "program_name": "myapp",
            "timestamp": "Aug 27 10:00:01",
            "hostname": "myserver",
        },
        "decoder": {"name": "myapp_decoder"},
        "data": {"dstuser": "bob", "status": "failed"},
        "location": "stdin",
    },
    "alert": True,
    "codemsg": 0,
}


def test_phases_three_phase_structure_in_official_order():
    out = render_phases(REALISTIC_DATA)
    assert "**Phase 1: Completed pre-decoding." in out
    assert "**Phase 2: Completed decoding." in out
    assert "**Phase 3: Completed filtering (rules)." in out
    assert "**Alert to be generated." in out
    assert out.index("Phase 1") < out.index("Phase 2") < out.index("Phase 3")


def test_phases_phase1_full_event_and_ordered_predecoder_fields():
    out = render_phases(REALISTIC_DATA)
    assert "\tfull event: 'Aug 27 10:00:01 myserver myapp[1234]: login user=bob status=failed'" in out
    assert out.index("\ttimestamp: 'Aug 27 10:00:01'") < out.index("\thostname: 'myserver'")
    assert out.index("\thostname: 'myserver'") < out.index("\tprogram_name: 'myapp'")


def test_phases_phase2_decoder_and_sorted_data_fields():
    out = render_phases(REALISTIC_DATA)
    assert "\tname: 'myapp_decoder'" in out
    assert out.index("\tdstuser: 'bob'") < out.index("\tstatus: 'failed'")


def test_phases_phase3_rule_fields_in_official_order():
    out = render_phases(REALISTIC_DATA)
    assert (
        out.index("\tid: '100101'")
        < out.index("\tlevel: '6'")
        < out.index("\tdescription: 'myapp: user login failed.'")
        < out.index("\tgroups: '['hw', 'local']'")
        < out.index("\tfiredtimes: '1'")
    )


def test_phases_no_decoder_message():
    data = {"output": {"rule": {"id": "1002"}}, "alert": False, "codemsg": 1}
    out = render_phases(data)
    assert "\tNo decoder matched." in out
    assert "**Alert to be generated." not in out


def test_phases_no_rule_skips_phase3():
    data = {"output": {"full_log": "hello"}, "alert": False, "codemsg": 1}
    out = render_phases(data)
    assert "**Phase 3:" not in out
    assert "**Phase 2: Completed decoding." in out


def test_phases_rules_debug_block_and_indentation():
    data = dict(REALISTIC_DATA)
    data["rules_debug"] = ["* Rule 100101 matched.", "Rule 100100 matched."]
    out = render_phases(data)
    assert "**Rule debugging:" in out
    assert "\t\t* Rule 100101 matched." in out
    assert "\tRule 100100 matched." in out


def test_phases_nested_dict_uses_dotted_prefix():
    data = {"output": {"decoder": {"name": "d", "parent": "p"}, "data": {"nested": {"x": "1"}}}, "alert": False}
    out = render_phases(data)
    assert "\tparent: 'p'" in out
    assert "\tnested.x: '1'" in out


def test_phases_does_not_mutate_input():
    import copy

    data = copy.deepcopy(REALISTIC_DATA)
    render_phases(data)
    assert data == REALISTIC_DATA


def test_phases_handles_empty_and_none():
    assert render_phases({}) == "**Phase 1: Completed pre-decoding.\n\n**Phase 2: Completed decoding.\n\tNo decoder matched."
    assert render_phases(None) == render_phases({})


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
