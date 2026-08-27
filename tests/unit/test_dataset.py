from __future__ import annotations

import json

import pytest

from wlogtest import dataset as dataset_module
from wlogtest.dataset import Dataset, DatasetError, TestCase, load_dataset

TestCase.__test__ = False


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


VALID_FULL = {
    "name": "full dataset",
    "description": "has every optional field",
    "default_location": "agent-1",
    "default_log_format": "json",
    "session_mode": "shared",
    "tests": [
        {
            "name": "case one",
            "event": "event one",
            "expect": {"rule.id": "100100", "alert": True},
            "location": "custom-loc",
            "log_format": "custom-fmt",
            "session": "group-a",
            "skip": True,
        },
        {"name": "case two", "event": "event two"},
    ],
}


def test_valid_json_roundtrip_with_all_optional_fields(tmp_path):
    path = write(tmp_path, "full.json", json.dumps(VALID_FULL))
    dataset = load_dataset(path)
    assert dataset.name == "full dataset"
    assert dataset.description == "has every optional field"
    assert dataset.default_location == "agent-1"
    assert dataset.default_log_format == "json"
    assert dataset.session_mode == "shared"
    assert len(dataset.tests) == 2
    case = dataset.tests[0]
    assert case == TestCase(
        name="case one",
        event="event one",
        expect={"rule.id": "100100", "alert": True},
        location="custom-loc",
        log_format="custom-fmt",
        session="group-a",
        skip=True,
    )
    second = dataset.tests[1]
    assert second.location is None
    assert second.log_format is None
    assert second.session is None
    assert second.skip is False
    assert second.expect == {}


def test_minimal_dataset_defaults(tmp_path):
    raw = {"name": "min", "tests": [{"name": "t", "event": "e"}]}
    dataset = load_dataset(write(tmp_path, "min.json", json.dumps(raw)))
    assert dataset.description == ""
    assert dataset.default_location == "stdin"
    assert dataset.default_log_format == "syslog"
    assert dataset.session_mode == "per_test"


def test_null_description_coerced_to_empty_string(tmp_path):
    raw = {"name": "d", "description": None, "tests": [{"name": "t", "event": "e"}]}
    dataset = load_dataset(write(tmp_path, "n.json", json.dumps(raw)))
    assert dataset.description == ""


def test_file_not_found_raises_dataset_error(tmp_path):
    missing = str(tmp_path / "missing.json")
    with pytest.raises(DatasetError) as excinfo:
        load_dataset(missing)
    assert missing in str(excinfo.value)
    assert "cannot read file" in str(excinfo.value)


def test_dataset_must_be_object(tmp_path):
    path = write(tmp_path, "list.json", "[1, 2, 3]")
    with pytest.raises(DatasetError, match="dataset must be a JSON/YAML object"):
        load_dataset(path)


def test_missing_name_raises_dataset_error(tmp_path):
    raw = {"tests": [{"name": "t", "event": "e"}]}
    with pytest.raises(DatasetError, match="'name' must be a non-empty string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_empty_name_raises_dataset_error(tmp_path):
    raw = {"name": "   ", "tests": []}
    with pytest.raises(DatasetError, match="'name' must be a non-empty string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_missing_tests_list_raises_dataset_error(tmp_path):
    raw = {"name": "d"}
    with pytest.raises(DatasetError, match="'tests' must be a list"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_invalid_session_mode_raises_dataset_error(tmp_path):
    raw = {"name": "d", "session_mode": "weird", "tests": []}
    with pytest.raises(DatasetError, match="'session_mode' must be 'per_test' or 'shared'"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_invalid_default_location_raises_dataset_error(tmp_path):
    raw = {"name": "d", "default_location": "", "tests": []}
    with pytest.raises(DatasetError, match="'default_location' must be a non-empty string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_invalid_default_log_format_raises_dataset_error(tmp_path):
    raw = {"name": "d", "default_log_format": 5, "tests": []}
    with pytest.raises(DatasetError, match="'default_log_format' must be a non-empty string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_non_string_description_raises_dataset_error(tmp_path):
    raw = {"name": "d", "description": 5, "tests": []}
    with pytest.raises(DatasetError, match="'description' must be a string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_case_must_be_object(tmp_path):
    raw = {"name": "d", "tests": ["nope"]}
    with pytest.raises(DatasetError, match="test case must be an object"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_case_missing_name_raises_dataset_error(tmp_path):
    raw = {"name": "d", "tests": [{"event": "e"}]}
    with pytest.raises(DatasetError, match=r"tests\[0\]: 'name' must be a non-empty string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_case_missing_event_raises_dataset_error(tmp_path):
    raw = {"name": "d", "tests": [{"name": "t"}]}
    with pytest.raises(DatasetError, match=r"tests\[0\]: 'event' must be a string"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_case_non_dict_expect_raises_dataset_error(tmp_path):
    raw = {"name": "d", "tests": [{"name": "t", "event": "e", "expect": ["wrong"]}]}
    with pytest.raises(DatasetError, match=r"tests\[0\]: 'expect' must be an object"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_unknown_matcher_key_in_expect_raises_dataset_error_with_path(tmp_path):
    raw = {
        "name": "d",
        "tests": [{"name": "t", "event": "e", "expect": {"rule.id": {"bogus": 1}}}],
    }
    with pytest.raises(DatasetError) as excinfo:
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))
    message = str(excinfo.value)
    assert "unknown matcher key 'bogus'" in message
    assert "expect.rule.id" in message


def test_multi_key_matcher_in_expect_raises_dataset_error(tmp_path):
    raw = {
        "name": "d",
        "tests": [{"name": "t", "event": "e", "expect": {"a": {"eq": 1, "ne": 2}}}],
    }
    with pytest.raises(DatasetError, match="exactly one key"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


@pytest.mark.parametrize("key,value", [("location", 5), ("log_format", []), ("session", {})])
def test_case_invalid_string_override_raises_dataset_error(tmp_path, key, value):
    raw = {"name": "d", "tests": [{"name": "t", "event": "e", key: value}]}
    with pytest.raises(DatasetError, match=f"'{key}' must be a string or null"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


def test_case_non_bool_skip_raises_dataset_error(tmp_path):
    raw = {"name": "d", "tests": [{"name": "t", "event": "e", "skip": "yes"}]}
    with pytest.raises(DatasetError, match="'skip' must be a boolean"):
        load_dataset(write(tmp_path, "d.json", json.dumps(raw)))


# ---------------------------------------------------------------------------
# YAML branch
# ---------------------------------------------------------------------------

def test_yaml_dataset_loads_when_pyyaml_available(tmp_path):
    pytest.importorskip("yaml")
    content = """
# a comment makes this invalid JSON
name: yaml dataset
session_mode: shared
tests:
  - name: yaml case
    event: hello from yaml
    expect:
      alert: true
      rule.id: "100100"
"""
    dataset = load_dataset(write(tmp_path, "d.yaml", content))
    assert dataset.name == "yaml dataset"
    assert dataset.session_mode == "shared"
    assert dataset.tests[0].expect == {"alert": True, "rule.id": "100100"}


def test_invalid_json_without_yaml_raises_hint(monkeypatch, tmp_path):
    monkeypatch.setattr(dataset_module, "yaml", None)
    path = write(tmp_path, "d.yaml", "name: not: json")
    with pytest.raises(DatasetError, match="not valid JSON \\(install PyYAML"):
        load_dataset(path)


def test_invalid_yaml_raises_dataset_error(monkeypatch, tmp_path):
    class FakeYaml:
        def safe_load(self, text):
            raise ValueError("yaml exploded")

    monkeypatch.setattr(dataset_module, "yaml", FakeYaml())
    path = write(tmp_path, "d.yaml", "not: [valid json")
    with pytest.raises(DatasetError, match="not valid JSON or YAML: yaml exploded"):
        load_dataset(path)


def test_yaml_non_object_document_raises_dataset_error(monkeypatch, tmp_path):
    class FakeYaml:
        def safe_load(self, text):
            return ["a", "list"]

    monkeypatch.setattr(dataset_module, "yaml", FakeYaml())
    path = write(tmp_path, "d.yaml", "not json at all")
    with pytest.raises(DatasetError, match="dataset must be a JSON/YAML object"):
        load_dataset(path)


def test_dataset_error_includes_path_in_message(tmp_path):
    path = write(tmp_path, "bad.json", "{")
    with pytest.raises(DatasetError) as excinfo:
        load_dataset(path)
    assert path in str(excinfo.value)
