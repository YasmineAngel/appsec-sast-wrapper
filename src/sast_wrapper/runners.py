"""Run Semgrep (via Docker) or Bandit, and return their JSON output as dicts."""

import json
import os
import subprocess
import sys
from pathlib import Path

from sast_wrapper.models import Finding

DEFAULT_SEMGREP_CONFIGS = ["p/owasp-top-ten", "p/secrets"]
DEFAULT_EXCLUDES = [".venv", "venv", "node_modules", ".git", "__pycache__"]


class ScanError(Exception):
    """The scanner could not run, crashed, or returned garbage."""


def _run(cmd: list[str], ok_codes: set[int], env: dict | None = None) -> dict:
    """Launch a command, check how it ended, and read its JSON output."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", env=env)
    except FileNotFoundError:
        raise ScanError(f"Command not found: {cmd[0]}. Is it installed and on your PATH?")
    if proc.returncode not in ok_codes:
        raise ScanError(f"{cmd[0]} failed (exit code {proc.returncode}): {proc.stderr.strip()[:500]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise ScanError(f"{cmd[0]} did not return valid JSON.")


def _check_folder(target) -> Path:
    target = Path(target).resolve()
    if not target.is_dir():
        raise ScanError(f"Folder not found: {target}")
    return target


def run_bandit(target, excludes=DEFAULT_EXCLUDES) -> dict:
    target = _check_folder(target)
    skip = ",".join(str(target / name) for name in excludes)
    cmd = [sys.executable, "-m", "bandit", "-r", str(target), "-f", "json", "-q", "-x", skip]
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}  # Windows: keep accents readable
    return _run(cmd, ok_codes={0, 1}, env=env)  # 1 = issues found, not a crash


def run_semgrep(target, configs=DEFAULT_SEMGREP_CONFIGS, excludes=DEFAULT_EXCLUDES) -> dict:
    target = _check_folder(target)
    cmd = ["docker", "run", "--rm", "-v", f"{target}:/src",
           "semgrep/semgrep", "semgrep", "scan", "--json", "--quiet"]
    for config in configs:
        cmd += ["--config", config]
    for name in excludes:
        cmd += ["--exclude", name]
    cmd.append("/src")
    return _run(cmd, ok_codes={0, 1})


def relative_paths(findings: list[Finding], base) -> list[Finding]:
    """Show paths relative to the scanned folder: backend/settings.py, not C:\\Users\\..."""
    base = Path(base).resolve()
    for f in findings:
        if f.file.startswith("/src/"):  # Semgrep sees the folder as /src inside Docker
            f.file = f.file[len("/src/"):]
        else:
            try:
                f.file = Path(f.file).resolve().relative_to(base).as_posix()
            except ValueError:
                pass  # not inside base: leave it as it is
    return findings

def count_scanned(tool: str, data: dict) -> int:
    """How many files did the scanner actually look at?"""
    if tool == "semgrep":
        return len(data.get("paths", {}).get("scanned", []))
    # Bandit: one entry per file in "metrics", plus a "_totals" entry
    return len([name for name in data.get("metrics", {}) if name != "_totals"])