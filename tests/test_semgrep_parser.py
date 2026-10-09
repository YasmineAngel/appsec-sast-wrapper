from pathlib import Path

from sast_wrapper.models import Severity
from sast_wrapper.parsers.semgrep import _extract_cwes, load_semgrep_file, parse_semgrep

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_sample.json"


def test_reads_all_results():
    assert len(load_semgrep_file(FIXTURE)) == 3


def test_first_finding_fields():
    f = load_semgrep_file(FIXTURE)[0]
    assert f.tool == "semgrep"
    assert f.file == "routes/login.ts"
    assert f.line == 34
    assert f.severity == Severity.HIGH
    assert f.cwe == ["CWE-89"]


def test_cwe_as_single_string():
    f = load_semgrep_file(FIXTURE)[1]
    assert f.cwe == ["CWE-798"]
    assert f.severity == Severity.MEDIUM


def test_missing_metadata_does_not_crash():
    f = load_semgrep_file(FIXTURE)[2]
    assert f.cwe == []
    assert f.severity == Severity.INFO


def test_empty_output():
    assert parse_semgrep({}) == []


def test_extract_cwes_removes_duplicates():
    assert _extract_cwes(["CWE-79: one", "CWE-79: two"]) == ["CWE-79"]