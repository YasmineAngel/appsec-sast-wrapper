"""Read Bandit's JSON output and turn it into Finding objects."""

import json
from pathlib import Path

from sast_wrapper.models import Finding, Severity


def _extract_cwe(raw) -> list[str]:
    """Bandit writes the CWE as a box like {"id": 89, "link": "..."}.
    We turn it into ["CWE-89"], or [] if it's missing."""
    if not isinstance(raw, dict):
        return []
    cwe_id = raw.get("id")
    if not cwe_id:  # missing, None or 0
        return []
    return [f"CWE-{cwe_id}"]


def parse_bandit(data: dict) -> list[Finding]:
    """Turn Bandit's JSON (already loaded as a dict) into a list of Findings."""
    findings = []
    for result in data.get("results", []):
        test_id = result.get("test_id", "unknown")
        test_name = result.get("test_name", "")
        findings.append(
            Finding(
                tool="bandit",
                rule_id=f"{test_id} {test_name}".strip(),
                message=result.get("issue_text", "").strip(),
                file=result.get("filename", "unknown"),
                line=result.get("line_number", 0),
                severity=Severity.from_text(result.get("issue_severity", "INFO")),
                cwe=_extract_cwe(result.get("issue_cwe")),
            )
        )
    return findings


def load_bandit_file(path: str | Path) -> list[Finding]:
    """Open a Bandit JSON file and parse it."""
    with open(path, encoding="utf-8-sig") as f:
        return parse_bandit(json.load(f))