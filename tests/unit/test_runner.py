from __future__ import annotations

import pytest

from wlogtest.client import LogtestError, LogtestProcessingError, LogtestTransportError
from wlogtest.dataset import Dataset, TestCase

TestCase.__test__ = False
from wlogtest.runner import CaseResult, DatasetRunner, RunReport


def response(token="tok00001", alert=True, rule_id="100100", codemsg=0):
    return {
        "token": token,
        "messages": ["processed"],
        "output": {"rule": {"id": rule_id}},
        "alert": alert,
        "codemsg": codemsg,
    }


def make_dataset(session_mode="per_test", tests=None, **kwargs):
    return Dataset(name="ds", session_mode=session_mode, tests=tests or [], **kwargs)


def make_case(name="case", event="event", expect=None, session=None, skip=False):
    return TestCase(
        name=name, event=event, expect=expect or {}, session=session, skip=skip
    )


def test_per_test_sessions_get_distinct_tokens(fake_client):
    client = fake_client(
        [
            response(token="aaa00001"),
            response(token="bbb00002"),
        ]
    )
    dataset = make_dataset(
        tests=[
            make_case("first", "e1", expect={"alert": True}),
            make_case("second", "e2", expect={"rule.id": "100100"}),
        ]
    )
    report = DatasetRunner(client, dataset).run()
    assert [call["token"] for call in client.calls] == [None, None]
    assert [result.token for result in report.results] == ["aaa00001", "bbb00002"]
    assert [result.session for result in report.results] == ["__case_0", "__case_1"]
    assert client.removed == ["aaa00001", "bbb00002"]
    assert report.passed


def test_named_sessions_honored_in_per_test_mode(fake_client):
    client = fake_client(
        [
            response(token="corrA001"),
            response(token="corrA001"),
            response(token="lonely02"),
        ]
    )
    dataset = make_dataset(
        session_mode="per_test",
        tests=[
            make_case("c1", "e1", session="corr-a", expect={"alert": True}),
            make_case("c2", "e2", session="corr-a", expect={"alert": True}),
            make_case("c3", "e3", expect={"alert": True}),
        ],
    )
    report = DatasetRunner(client, dataset).run()
    assert [call["token"] for call in client.calls] == [None, "corrA001", None]
    assert [result.session for result in report.results] == ["corr-a", "corr-a", "__case_2"]
    assert [result.token for result in report.results] == ["corrA001", "corrA001", "lonely02"]
    assert sorted(client.removed) == ["corrA001", "lonely02"]


def test_processing_error_token_recovered_for_session(fake_client):
    client = fake_client(
        [
            LogtestProcessingError(-1, "bad rule syntax", token="rotated01"),
            response(token="rotated01"),
        ]
    )
    dataset = make_dataset(
        session_mode="shared",
        tests=[
            make_case("bad", "e1", expect={"alert": True}),
            make_case("good", "e2", expect={"alert": True}),
        ],
    )
    report = DatasetRunner(client, dataset).run()
    assert [result.verdict.status for result in report.results] == ["error", "pass"]
    assert client.calls[1]["token"] == "rotated01"
    assert client.removed == ["rotated01"]


def test_shared_session_mode_reuses_one_token(fake_client):
    client = fake_client(
        [
            response(token="shared01"),
            response(token="shared01"),
            response(token="shared01"),
        ]
    )
    dataset = make_dataset(
        session_mode="shared",
        tests=[make_case(f"c{i}", f"e{i}", expect={"alert": True}) for i in range(3)],
    )
    report = DatasetRunner(client, dataset).run()
    assert [call["token"] for call in client.calls] == [None, "shared01", "shared01"]
    assert [result.token for result in report.results] == ["shared01"] * 3
    assert [result.session for result in report.results] == ["shared"] * 3
    assert client.removed == ["shared01"]
    assert report.passed


def test_named_sessions_group_tokens(fake_client):
    client = fake_client(
        [
            response(token="grpA001"),
            response(token="grpB001"),
            response(token="grpA001"),
            response(token="grpB001"),
        ]
    )
    dataset = make_dataset(
        session_mode="shared",
        tests=[
            make_case("a1", "e1", session="grp-a", expect={"alert": True}),
            make_case("b1", "e2", session="grp-b", expect={"alert": True}),
            make_case("a2", "e3", session="grp-a", expect={"alert": True}),
            make_case("b2", "e4", session="grp-b", expect={"alert": True}),
        ],
    )
    report = DatasetRunner(client, dataset).run()
    assert [call["token"] for call in client.calls] == [None, None, "grpA001", "grpB001"]
    assert [result.session for result in report.results] == ["grp-a", "grp-b", "grp-a", "grp-b"]
    assert [result.token for result in report.results] == ["grpA001", "grpB001", "grpA001", "grpB001"]
    assert sorted(client.removed) == ["grpA001", "grpB001"]


def test_logtest_error_mid_run_sets_error_verdict_and_continues(fake_client):
    client = fake_client(
        [
            LogtestError(5, "rule compilation failed"),
            response(token="tok00002"),
            LogtestError(5, "another failure"),
        ]
    )
    dataset = make_dataset(
        tests=[
            make_case("boom", "bad", expect={"alert": True}),
            make_case("fine", "good", expect={"alert": True}),
            make_case("boom2", "bad2", expect={"alert": True}),
        ]
    )
    report = DatasetRunner(client, dataset).run()
    statuses = [result.verdict.status for result in report.results]
    assert statuses == ["error", "pass", "error"]
    assert report.results[0].verdict.error == "rule compilation failed"
    assert report.results[2].verdict.error == "another failure"
    assert report.results[0].token == ""
    assert report.results[1].token == "tok00002"
    assert client.removed == ["tok00002"]
    assert len(client.calls) == 3


def test_shared_session_continues_after_error(fake_client):
    client = fake_client(
        [
            response(token="shared01"),
            LogtestError(1, "boom"),
            response(token="shared01"),
        ]
    )
    dataset = make_dataset(
        session_mode="shared",
        tests=[
            make_case("one", "e1", expect={"alert": True}),
            make_case("bad", "e2", expect={"alert": True}),
            make_case("two", "e3", expect={"alert": True}),
        ],
    )
    report = DatasetRunner(client, dataset).run()
    assert [r.verdict.status for r in report.results] == ["pass", "error", "pass"]
    assert [call["token"] for call in client.calls] == [None, "shared01", "shared01"]
    assert client.removed == ["shared01"]


def test_transport_error_sets_error_verdict_and_continues(fake_client):
    client = fake_client(
        [
            LogtestTransportError("cannot connect"),
            response(token="tok00002"),
        ]
    )
    dataset = make_dataset(
        tests=[
            make_case("down", "bad", expect={"alert": True}),
            make_case("fine", "good", expect={"alert": True}),
        ]
    )
    report = DatasetRunner(client, dataset).run()
    statuses = [result.verdict.status for result in report.results]
    assert statuses == ["error", "pass"]
    assert report.results[0].verdict.error == "cannot connect"


def test_remove_session_failure_is_best_effort(fake_client):
    client = fake_client([response(token="tok00001")], fail_remove=True)
    dataset = make_dataset(tests=[make_case("c", "e", expect={"alert": True})])
    report = DatasetRunner(client, dataset).run()
    assert report.passed
    assert report.results[0].token == "tok00001"


def test_shared_cleanup_remove_failure_is_best_effort(fake_client):
    client = fake_client([response(token="s1")], fail_remove=True)
    dataset = make_dataset(
        session_mode="shared", tests=[make_case("c", "e", expect={"alert": True})]
    )
    report = DatasetRunner(client, dataset).run()
    assert report.passed


def test_skipped_cases_are_excluded(fake_client):
    client = fake_client([response(token="tok00001")])
    dataset = make_dataset(
        tests=[
            make_case("skipped", "never", skip=True),
            make_case("ran", "e1", expect={"alert": True}),
            make_case("also skipped", "never2", skip=True),
        ]
    )
    report = DatasetRunner(client, dataset).run()
    assert len(report.results) == 1
    assert report.results[0].verdict.case_name == "ran"
    assert len(client.calls) == 1


def test_all_cases_skipped_gives_empty_pass(fake_client):
    client = fake_client([])
    dataset = make_dataset(tests=[make_case("s", "e", skip=True)])
    report = DatasetRunner(client, dataset).run()
    assert report.results == []
    assert report.summary == {"total": 0, "passed": 0, "failed": 0, "errors": 0}
    assert report.passed


def test_empty_expect_passes_vacuously(fake_client):
    client = fake_client([response()])
    dataset = make_dataset(tests=[make_case("no checks", "e1")])
    report = DatasetRunner(client, dataset).run()
    verdict = report.results[0].verdict
    assert verdict.status == "pass"
    assert verdict.checks == []


def test_failed_expectation_marks_fail(fake_client):
    client = fake_client([response(rule_id="100100")])
    dataset = make_dataset(tests=[make_case("wrong", "e1", expect={"rule.id": "100999"})])
    report = DatasetRunner(client, dataset).run()
    assert report.results[0].verdict.status == "fail"
    assert not report.passed


def test_run_log_receives_case_location_and_format(fake_client):
    client = fake_client([response()])
    dataset = make_dataset(
        tests=[make_case("c", "e1")],
        default_location="agent-9",
        default_log_format="json",
    )
    DatasetRunner(client, dataset).run()
    call = client.calls[0]
    assert call["location"] == "agent-9"
    assert call["log_format"] == "json"
    assert call["options"] is None


def test_case_overrides_dataset_defaults(fake_client):
    client = fake_client([response()])
    case = make_case("c", "e1")
    case.location = "custom"
    case.log_format = "audit"
    dataset = make_dataset(tests=[case])
    DatasetRunner(client, dataset).run()
    call = client.calls[0]
    assert call["location"] == "custom"
    assert call["log_format"] == "audit"


def test_non_dict_response_treated_as_empty(fake_client):
    client = fake_client([None])
    dataset = make_dataset(tests=[make_case("c", "e1")])
    report = DatasetRunner(client, dataset).run()
    assert report.results[0].verdict.status == "pass"
    assert report.results[0].token == ""


def test_duration_ms_is_positive(fake_client):
    client = fake_client([response(), response()])
    dataset = make_dataset(
        tests=[make_case("a", "e1"), make_case("b", "e2")],
    )
    report = DatasetRunner(client, dataset).run()
    assert report.duration_ms > 0
    assert report.dataset_name == "ds"


def test_summary_counts(fake_client):
    client = fake_client(
        [
            response(alert=True),
            response(alert=False),
            LogtestError(1, "boom"),
        ]
    )
    dataset = make_dataset(
        tests=[
            make_case("pass case", "e1", expect={"alert": True}),
            make_case("fail case", "e2", expect={"alert": True}),
            make_case("error case", "e3", expect={"alert": True}),
        ]
    )
    report = DatasetRunner(client, dataset).run()
    assert report.summary == {"total": 3, "passed": 1, "failed": 1, "errors": 1}
    assert not report.passed


def test_to_dict_shape(fake_client):
    client = fake_client([response(rule_id="100100")])
    dataset = make_dataset(tests=[make_case("c", "e1", expect={"rule.id": "100100"})])
    report = DatasetRunner(client, dataset).run()
    data = report.to_dict()
    assert set(data) == {"dataset", "summary", "duration_ms", "results"}
    assert data["dataset"] == "ds"
    assert data["summary"] == {"total": 1, "passed": 1, "failed": 0, "errors": 0}
    result = data["results"][0]
    assert set(result) == {"name", "session", "token", "status", "error", "checks", "actual"}
    assert result["status"] == "pass"
    assert result["name"] == "c"
    check = result["checks"][0]
    assert set(check) == {"path", "expected", "actual", "matched", "reason"}


def test_to_dict_for_error_verdict(fake_client):
    client = fake_client([LogtestError(2, "bad token")])
    dataset = make_dataset(tests=[make_case("err", "e1")])
    data = DatasetRunner(client, dataset).run().to_dict()
    result = data["results"][0]
    assert result["status"] == "error"
    assert result["error"] == "bad token"
    assert result["checks"] == []


def test_case_result_construction():
    from wlogtest.verdict import Verdict

    verdict = Verdict(case_name="x", status="pass")
    result = CaseResult(verdict=verdict, session="s", token="t")
    assert result.session == "s"
    assert result.token == "t"


def test_run_report_construction():
    report = RunReport(dataset_name="empty")
    assert report.results == []
    assert report.duration_ms == 0.0
    assert report.passed
