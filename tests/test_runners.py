import json

import pytest

from sast_wrapper import runners
from sast_wrapper.models import Finding, Severity


class FakeProc:
    """Pretends to be the result of subprocess.run."""

    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def install_fake(monkeypatch, proc, calls):
    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return proc
    monkeypatch.setattr(runners.subprocess, "run", fake_run)


def test_bandit_exit_1_means_issues_not_crash(monkeypatch, tmp_path):
    calls = []
    install_fake(monkeypatch, FakeProc(1, json.dumps({"results": []})), calls)
    assert runners.run_bandit(tmp_path) == {"results": []}
    assert "-r" in calls[0]


def test_crash_raises_scan_error(monkeypatch, tmp_path):
    install_fake(monkeypatch, FakeProc(2, stderr="boom"), [])
    with pytest.raises(runners.ScanError):
        runners.run_bandit(tmp_path)


def test_bad_json_raises_scan_error(monkeypatch, tmp_path):
    install_fake(monkeypatch, FakeProc(0, "this is not json"), [])
    with pytest.raises(runners.ScanError):
        runners.run_bandit(tmp_path)


def test_missing_tool_raises_scan_error(monkeypatch, tmp_path):
    def not_installed(cmd, **kwargs):
        raise FileNotFoundError
    monkeypatch.setattr(runners.subprocess, "run", not_installed)
    with pytest.raises(runners.ScanError):
        runners.run_semgrep(tmp_path)


def test_missing_folder_raises_scan_error(tmp_path):
    with pytest.raises(runners.ScanError):
        runners.run_bandit(tmp_path / "does-not-exist")


def test_semgrep_command_uses_docker(monkeypatch, tmp_path):
    calls = []
    install_fake(monkeypatch, FakeProc(0, json.dumps({"results": []})), calls)
    runners.run_semgrep(tmp_path)
    cmd = calls[0]
    assert cmd[0] == "docker"
    assert "p/owasp-top-ten" in cmd
    assert cmd[-1] == "/src"


def test_relative_paths(tmp_path):
    semgrep_f = Finding("semgrep", "r", "m", "/src/routes/login.ts", 1, Severity.LOW)
    bandit_f = Finding("bandit", "r", "m", str(tmp_path / "app" / "x.py"), 1, Severity.LOW)
    runners.relative_paths([semgrep_f, bandit_f], tmp_path)
    assert semgrep_f.file == "routes/login.ts"
    assert bandit_f.file == "app/x.py"