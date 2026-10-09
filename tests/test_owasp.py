from sast_wrapper.models import Finding, Severity
from sast_wrapper.owasp import OWASP_2025, UNMAPPED, apply_owasp, cwe_to_owasp, rank


def make(severity, cwe=None, file="a.py", line=1):
    """Small helper so each test can build a Finding in one line."""
    return Finding("semgrep", "rule", "msg", file, line, severity, cwe or [])


def test_there_are_ten_categories():
    assert len(OWASP_2025) == 10


def test_sql_injection_is_a05():
    assert cwe_to_owasp("CWE-89") == "A05:2025 Injection"


def test_unknown_cwe_returns_none():
    assert cwe_to_owasp("CWE-99999") is None


def test_first_known_cwe_wins():
    f = apply_owasp([make(Severity.HIGH, ["CWE-99999", "CWE-79"])])[0]
    assert f.owasp == "A05:2025 Injection"


def test_no_cwe_is_unmapped():
    f = apply_owasp([make(Severity.LOW)])[0]
    assert f.owasp == UNMAPPED


def test_supply_chain_finding_from_juice_shop():
    f = apply_owasp([make(Severity.MEDIUM, ["CWE-1357", "CWE-353"])])[0]
    assert f.owasp == "A03:2025 Software Supply Chain Failures"


def test_rank_puts_worst_first():
    low, critical = make(Severity.LOW), make(Severity.CRITICAL)
    assert rank([low, critical])[0] is critical


def test_rank_same_severity_groups_by_category():
    injection = make(Severity.HIGH, ["CWE-89"])
    access = make(Severity.HIGH, ["CWE-22"])
    ranked = rank(apply_owasp([injection, access]))
    assert ranked[0] is access # A01 comes before A05