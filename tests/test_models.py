from sast_wrapper.models import Finding, Severity


def test_severity_order():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_semgrep_words_are_translated():
    assert Severity.from_text("ERROR") == Severity.HIGH
    assert Severity.from_text("WARNING") == Severity.MEDIUM
    assert Severity.from_text("info") == Severity.INFO


def test_unknown_word_becomes_info():
    assert Severity.from_text("banana") == Severity.INFO


def test_finding_holds_its_data():
    f = Finding(tool="bandit", rule_id="B105", message="Hardcoded password",
                file="app.py", line=3, severity=Severity.LOW, cwe=["CWE-259"])
    assert f.cwe == ["CWE-259"]
    assert f.owasp is None


def test_findings_sort_worst_first():
    low = Finding("semgrep", "r1", "m", "a.py", 1, Severity.LOW)
    critical = Finding("semgrep", "r2", "m", "b.py", 1, Severity.CRITICAL)
    ranked = sorted([low, critical], key=lambda f: f.severity, reverse=True)
    assert ranked[0] is critical