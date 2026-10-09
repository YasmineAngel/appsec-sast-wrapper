from sast_wrapper.models import Finding, Severity
from sast_wrapper.report import build_report, redact

SECRET = "django-insecure-abc123xyz"


def make(severity, cwe, message="msg", rule="rule.id"):
    return Finding("bandit", rule, message, "a.py", 1, severity, cwe)


def test_redact_keeps_first_four_chars():
    assert redact(f"Possible hardcoded password: '{SECRET}'") == "Possible hardcoded password: 'djan****'"


def test_redact_leaves_short_strings():
    assert redact("Do not use 'eval'") == "Do not use 'eval'"


def test_secret_never_appears_in_report():
    f = make(Severity.LOW, ["CWE-259"], f"Possible hardcoded password: '{SECRET}'")
    assert SECRET not in build_report([f], "test")


def test_normal_messages_are_not_redacted():
    f = make(Severity.HIGH, ["CWE-89"], "Query built from 'user_input_value'")
    assert "'user_input_value'" in build_report([f], "test")


def test_summary_and_sections():
    report = build_report([make(Severity.HIGH, ["CWE-89"])], "test")
    assert "# SAST report: test" in report
    assert "| A05:2025 Injection |" in report
    assert "## A05:2025 Injection" in report


def test_categories_in_owasp_order():
    report = build_report([make(Severity.HIGH, ["CWE-89"]), make(Severity.LOW, ["CWE-22"])], "test")
    assert report.index("## A01:2025") < report.index("## A05:2025")


def test_unmapped_comes_last():
    report = build_report([make(Severity.HIGH, []), make(Severity.LOW, ["CWE-22"])], "test")
    assert report.index("## A01:2025") < report.index("## Unmapped")


def test_empty_report():
    assert "No findings" in build_report([], "test")