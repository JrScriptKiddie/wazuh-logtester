from __future__ import annotations

import pytest

from wlogtest.verdict import (
    CheckResult,
    Verdict,
    _contains,
    _lookup,
    _validate_matcher,
    evaluate,
    validate_expectations,
)


def make_data(**overrides):
    data = {
        "token": "abc12345",
        "messages": ["line one", "line two"],
        "alert": True,
        "output": {
            "rule": {"id": "100100", "firedtimes": 1},
            "decoder": {"name": "myapp_decoder"},
            "data": {"srcip": "1.2.3.4", "user": "alice", "status": "ok"},
            "full_log": "Aug 27 myapp[1]: login user=alice",
        },
    }
    data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# plain equality / null
# ---------------------------------------------------------------------------

def test_plain_str_equality():
    verdict = evaluate("case", {"rule.id": "100100"}, make_data())
    assert verdict.status == "pass"
    assert verdict.checks == [
        CheckResult(path="rule.id", expected="100100", actual="100100", matched=True)
    ]


def test_plain_int_equality():
    assert evaluate("c", {"rule.firedtimes": 1}, make_data()).status == "pass"


def test_plain_bool_equality():
    assert evaluate("c", {"alert": True}, make_data()).status == "pass"


def test_plain_str_mismatch_fails_with_reason():
    verdict = evaluate("case", {"rule.id": "100999"}, make_data())
    assert verdict.status == "fail"
    check = verdict.checks[0]
    assert check.matched is False
    assert check.reason == "expected '100999', got '100100'"


def test_null_expectation_matches_absent_field():
    verdict = evaluate("c", {"no.such.field": None}, make_data())
    assert verdict.status == "pass"
    assert verdict.checks[0].actual is None


def test_null_expectation_matches_explicit_null_field():
    data = make_data(output={"maybe": None, "rule": {}})
    assert evaluate("c", {"maybe": None}, data).status == "pass"


def test_null_expectation_fails_when_field_has_value():
    verdict = evaluate("c", {"rule.id": None}, make_data())
    assert verdict.status == "fail"


# ---------------------------------------------------------------------------
# comparison operators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "matcher,actual,expected_match",
    [
        ({"eq": "100100"}, "100100", True),
        ({"eq": "100100"}, "100999", False),
        ({"ne": "100100"}, "100999", True),
        ({"ne": "100100"}, "100100", False),
        ({"gt": 0}, 1, True),
        ({"gt": 1}, 1, False),
        ({"gte": 1}, 1, True),
        ({"gte": 2}, 1, False),
        ({"lt": 2}, 1, True),
        ({"lt": 1}, 1, False),
        ({"lte": 1}, 1, True),
        ({"lte": 0}, 1, False),
    ],
)
def test_comparison_operators(matcher, actual, expected_match):
    if isinstance(actual, str):
        data = make_data(output={"rule": {"id": actual}})
        path = "rule.id"
    else:
        data = make_data(output={"rule": {"id": "100100", "firedtimes": actual}})
        path = "rule.firedtimes"
    verdict = evaluate("c", {path: matcher}, data)
    assert verdict.status == ("pass" if expected_match else "fail")


def test_ordering_on_incomparable_types_fails_not_raises():
    data = make_data(output={"rule": {"id": "100100"}})
    assert evaluate("c", {"rule.id": {"gt": 5}}, data).status == "fail"


@pytest.mark.parametrize(
    "matcher,actual,expected_match",
    [
        ({"in": ["100100", "100101"]}, "100100", True),
        ({"in": ["100200"]}, "100100", False),
        ({"nin": ["100200"]}, "100100", True),
        ({"nin": ["100100"]}, "100100", False),
    ],
)
def test_in_nin(matcher, actual, expected_match):
    data = make_data(output={"rule": {"id": actual}})
    assert evaluate("c", {"rule.id": matcher}, data).status == ("pass" if expected_match else "fail")


def test_in_with_non_iterable_value_fails_not_raises():
    data = make_data()
    assert evaluate("c", {"rule.id": {"in": 5}}, data).status == "fail"


def test_nin_with_non_iterable_value_fails():
    data = make_data()
    assert evaluate("c", {"rule.id": {"nin": 5}}, data).status == "fail"


def test_missing_field_with_ne_holds_when_value_not_none():
    assert evaluate("c", {"nope": {"ne": "x"}}, make_data()).status == "pass"


def test_missing_field_with_eq_holds_only_for_none():
    assert evaluate("c", {"nope": {"eq": None}}, make_data()).status == "pass"
    assert evaluate("c", {"nope": {"eq": "x"}}, make_data()).status == "fail"


def test_missing_field_with_nin_holds():
    assert evaluate("c", {"nope": {"nin": ["x"]}}, make_data()).status == "pass"


def test_missing_field_with_contains_fails():
    assert evaluate("c", {"nope": {"contains": "x"}}, make_data()).status == "fail"


# ---------------------------------------------------------------------------
# contains
# ---------------------------------------------------------------------------

def test_contains_on_string():
    data = make_data()
    verdict = evaluate("c", {"full_log": {"contains": "myapp"}}, data)
    assert verdict.status == "pass"


def test_contains_on_string_mismatch():
    assert evaluate("c", {"full_log": {"contains": "nginx"}}, make_data()).status == "fail"


def test_contains_on_messages_exact_item():
    data = make_data(messages=["decoded", "fired 100100"])
    assert evaluate("c", {"messages": {"contains": "decoded"}}, data).status == "pass"


def test_contains_on_messages_substring_of_item():
    data = make_data(messages=["rule 100100 fired"])
    assert evaluate("c", {"messages": {"contains": "100100"}}, data).status == "pass"


def test_contains_on_messages_mismatch():
    data = make_data(messages=["decoded"])
    assert evaluate("c", {"messages": {"contains": "nope"}}, data).status == "fail"


def test_contains_fallback_str_on_non_string_actual():
    assert _contains(42, "42") is True
    assert _contains({"a": 1}, "a") is True


# ---------------------------------------------------------------------------
# regex / exists
# ---------------------------------------------------------------------------

def test_regex_match():
    assert evaluate("c", {"rule.id": {"regex": r"1001\d\d"}}, make_data()).status == "pass"


def test_regex_no_match():
    assert evaluate("c", {"rule.id": {"regex": r"9\d{5}"}}, make_data()).status == "fail"


def test_regex_matches_stringified_actual():
    data = make_data(output={"rule": {"id": "100100", "firedtimes": 3}})
    assert evaluate("c", {"rule.firedtimes": {"regex": r"^3$"}}, data).status == "pass"


def test_exists_true_when_present_and_not_none():
    assert evaluate("c", {"rule.id": {"exists": True}}, make_data()).status == "pass"


def test_exists_true_fails_when_absent():
    assert evaluate("c", {"nope": {"exists": True}}, make_data()).status == "fail"


def test_exists_true_fails_when_null():
    data = make_data(output={"maybe": None, "rule": {}})
    assert evaluate("c", {"maybe": {"exists": True}}, data).status == "fail"


def test_exists_false_when_absent():
    assert evaluate("c", {"nope": {"exists": False}}, make_data()).status == "pass"


def test_exists_false_fails_when_present():
    assert evaluate("c", {"rule.id": {"exists": False}}, make_data()).status == "fail"


# ---------------------------------------------------------------------------
# any / all nesting
# ---------------------------------------------------------------------------

def test_any_matches_when_one_submatcher_holds():
    data = make_data()
    expect = {"rule.firedtimes": {"any": [{"gt": 100}, {"eq": 1}]}}
    assert evaluate("c", expect, data).status == "pass"


def test_any_fails_when_no_submatcher_holds():
    data = make_data()
    expect = {"rule.firedtimes": {"any": [{"gt": 100}, {"eq": 99}]}}
    assert evaluate("c", expect, data).status == "fail"


def test_all_matches_when_every_submatcher_holds():
    data = make_data()
    expect = {"rule.firedtimes": {"all": [{"gte": 1}, {"lte": 1}]}}
    assert evaluate("c", expect, data).status == "pass"


def test_all_fails_when_one_submatcher_fails():
    data = make_data()
    expect = {"rule.firedtimes": {"all": [{"gte": 1}, {"lte": 0}]}}
    assert evaluate("c", expect, data).status == "fail"


def test_any_of_empty_list_is_false_all_of_empty_is_true():
    data = make_data()
    assert evaluate("c", {"rule.id": {"any": []}}, data).status == "fail"
    assert evaluate("c", {"rule.id": {"all": []}}, data).status == "pass"


def test_nested_any_inside_all():
    data = make_data()
    expect = {"rule.id": {"all": [{"any": [{"eq": "100100"}, {"eq": "x"}]}, {"ne": "y"}]}}
    assert evaluate("c", expect, data).status == "pass"


def test_any_with_missing_field_uses_submatcher_semantics():
    data = make_data()
    assert evaluate("c", {"nope": {"any": [{"eq": None}]}}, data).status == "pass"


# ---------------------------------------------------------------------------
# paths and messages
# ---------------------------------------------------------------------------

def test_dotted_deep_paths():
    data = make_data()
    expect = {
        "rule.id": "100100",
        "data.srcip": "1.2.3.4",
        "decoder.name": "myapp_decoder",
    }
    verdict = evaluate("deep", expect, data)
    assert verdict.status == "pass"
    assert len(verdict.checks) == 3


def test_dotted_path_through_non_dict_yields_missing():
    data = make_data(output={"rule": "not-a-dict"})
    assert evaluate("c", {"rule.id": {"exists": False}}, data).status == "pass"


def test_lookup_empty_path_returns_view():
    view = {"a": 1}
    assert _lookup(view, "") is view


def test_messages_plain_expectation_uses_contains_semantics():
    data = make_data(messages=["INFO: rule 100100 fired", "WARNING: foo"])
    assert evaluate("c", {"messages": "rule 100100 fired"}, data).status == "pass"
    assert evaluate("c", {"messages": "INFO: rule 100100 fired"}, data).status == "pass"
    assert evaluate("c", {"messages": "no such text"}, data).status == "fail"


def test_messages_plain_matcher_object_still_uses_contains_op():
    data = make_data(messages=["one", "two"])
    assert evaluate("c", {"messages": {"contains": "two"}}, data).status == "pass"


def test_plain_scalar_expectation_on_missing_field_fails():
    assert evaluate("c", {"nope": "x"}, make_data()).status == "fail"


# ---------------------------------------------------------------------------
# matcher validation / errors
# ---------------------------------------------------------------------------

def test_unknown_matcher_key_raises_value_error_naming_key():
    with pytest.raises(ValueError, match="unknown matcher key 'bogus'"):
        evaluate("c", {"rule.id": {"bogus": 1}}, make_data())


def test_validate_expectations_reports_path_for_unknown_key():
    with pytest.raises(ValueError, match=r"unknown matcher key 'bogus' at expect\.rule\.id"):
        validate_expectations({"rule.id": {"bogus": 1}})


def test_validate_expectations_reports_nested_path():
    with pytest.raises(ValueError, match=r"at expect\.x\[0\]"):
        validate_expectations({"x": {"all": [{"bogus": 1}]}})


def test_matcher_with_multiple_keys_raises():
    with pytest.raises(ValueError, match="exactly one key"):
        evaluate("c", {"rule.id": {"eq": "a", "ne": "b"}}, make_data())


def test_validate_matcher_any_value_must_be_list():
    with pytest.raises(ValueError, match="must be a list"):
        validate_expectations({"x": {"any": {"eq": 1}}})


def test_validate_matcher_ignores_plain_values():
    _validate_matcher("plain", "expect.x")
    _validate_matcher(None, "expect.x")
    _validate_matcher(5, "expect.x")


# ---------------------------------------------------------------------------
# verdict aggregation / construction
# ---------------------------------------------------------------------------

def test_multiple_checks_aggregate_to_fail_on_single_mismatch():
    data = make_data()
    expect = {
        "rule.id": "100100",
        "data.user": "bob",
        "alert": True,
    }
    verdict = evaluate("c", expect, data)
    assert verdict.status == "fail"
    assert sum(1 for check in verdict.checks if check.matched) == 2
    assert sum(1 for check in verdict.checks if not check.matched) == 1


def test_all_checks_pass_gives_pass():
    data = make_data()
    expect = {"rule.id": "100100", "data.user": "alice", "alert": True}
    assert evaluate("c", expect, data).status == "pass"


def test_empty_expect_passes_vacuously_with_no_checks():
    verdict = evaluate("c", {}, make_data())
    assert verdict.status == "pass"
    assert verdict.checks == []
    assert verdict.error == ""


def test_evaluate_copies_actual_data():
    data = make_data()
    verdict = evaluate("c", {}, data)
    assert verdict.actual == data
    assert verdict.actual is not data


def test_evaluate_with_none_data_uses_empty_dict():
    verdict = evaluate("c", {}, None)
    assert verdict.status == "pass"
    assert verdict.actual == {}


def test_evaluate_ignores_non_dict_output():
    data = make_data()
    data["output"] = "not a dict"
    verdict = evaluate("c", {"alert": True}, data)
    assert verdict.status == "pass"


def test_error_verdict_construction():
    verdict = Verdict(case_name="boom case", status="error", error="server said no")
    assert verdict.case_name == "boom case"
    assert verdict.status == "error"
    assert verdict.error == "server said no"
    assert verdict.checks == []
    assert verdict.actual == {}


def test_missing_field_reason_is_field_missing():
    verdict = evaluate("c", {"nope": {"exists": True}}, make_data())
    assert verdict.checks[0].reason == "field missing"
