from sast_wrapper import cli, runners

BANDIT_DATA = {
    "results": [{
        "filename": "app/x.py", "line_number": 3, "issue_severity": "HIGH",
        "issue_cwe": {"id": 78}, "issue_text": "subprocess call with shell=True",
        "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
    }],
    "metrics": {"app/x.py": {}, "_totals": {}},
}


def use_fake_bandit(monkeypatch, data=BANDIT_DATA):
    monkeypatch.setattr(cli, "run_bandit", lambda target, excludes: data)


def scan(tmp_path, *extra):
    return cli.main(["scan", str(tmp_path), "--tool", "bandit", "--out", str(tmp_path / "r.md"), *extra])


def test_scan_writes_report(monkeypatch, tmp_path):
    use_fake_bandit(monkeypatch)
    assert scan(tmp_path) == 0
    assert "A05:2025 Injection" in (tmp_path / "r.md").read_text(encoding="utf-8")


def test_fail_on_high_returns_1(monkeypatch, tmp_path):
    use_fake_bandit(monkeypatch)
    assert scan(tmp_path, "--fail-on", "high") == 1


def test_fail_on_critical_returns_0(monkeypatch, tmp_path):
    use_fake_bandit(monkeypatch)  # the finding is only HIGH
    assert scan(tmp_path, "--fail-on", "critical") == 0


def test_scan_error_returns_2(monkeypatch, tmp_path):
    def broken(target, excludes):
        raise runners.ScanError("Docker is not running")
    monkeypatch.setattr(cli, "run_bandit", broken)
    assert scan(tmp_path) == 2


def test_zero_files_scanned_warns(monkeypatch, tmp_path, capsys):
    use_fake_bandit(monkeypatch, {"results": [], "metrics": {"_totals": {}}})
    scan(tmp_path)
    assert "0 files were scanned" in capsys.readouterr().err


def test_count_scanned():
    assert runners.count_scanned("semgrep", {"paths": {"scanned": ["a", "b"]}}) == 2
    assert runners.count_scanned("bandit", BANDIT_DATA) == 1