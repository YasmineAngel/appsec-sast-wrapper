from pathlib import Path

from sast_wrapper.models import Severity
from sast_wrapper.parsers.bandit import _extract_cwe, load_bandit_file, parse_bandit

FIXTURE = Path(__file__).parent / "fixtures" / "bandit_sample.json"


def test_reads_all_results():
    assert len(load_bandit_file(FIXTURE)) == 3


def test_first_finding_fields():
    f = load_bandit_file(FIXTURE)[0]
    assert f.tool == "bandit"
    assert f.rule_id == "B608 hardcoded_sql_expressions"
    assert f.file == "app/db.py"
    assert f.line == 12
    assert f.severity == Severity.MEDIUM
    assert f.cwe == ["CWE-89"]


def test_hardcoded_password_is_low():
    f = load_bandit_file(FIXTURE)[1]
    assert f.severity == Severity.LOW
    assert f.cwe == ["CWE-259"]


def test_missing_cwe_and_undefined_severity():
    f = load_bandit_file(FIXTURE)[2]
    assert f.cwe == []
    assert f.severity == Severity.INFO


def test_empty_output():
    assert parse_bandit({}) == []


def test_cwe_zero_means_none():
    assert _extract_cwe({"id": 0, "link": ""}) == []