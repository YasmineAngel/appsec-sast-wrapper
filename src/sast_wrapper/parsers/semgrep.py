"""Read Semgrep's JSON output and turn it into Finding objects."""

import json
import re
from pathlib import Path

from sast_wrapper.models import Finding, Severity

CWE_PATTERN = re.compile(r"CWE-\d+")


def _extract_cwes(raw) -> list[str]:
    """Semgrep writes CWEs like 'CWE-89: Improper Neutralization...'.
    It can be one string or a list. We keep only the short 'CWE-89' part."""
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    cwes = []
    for item in raw:
        match = CWE_PATTERN.search(str(item))
        if match and match.group() not in cwes:
            cwes.append(match.group())
    return cwes


def parse_semgrep(data: dict) -> list[Finding]:
    """Turn Semgrep's JSON (already loaded as a dict) into a list of Findings."""
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        findings.append(
            Finding(
                tool="semgrep",
                rule_id=result.get("check_id", "unknown"),
                message=extra.get("message", "").strip(),
                file=result.get("path", "unknown"),
                line=result.get("start", {}).get("line", 0),
                severity=Severity.from_text(extra.get("severity", "INFO")),
                cwe=_extract_cwes(metadata.get("cwe")),
            )
        )
    return findings


def load_semgrep_file(path: str | Path) -> list[Finding]:
    """Open a Semgrep JSON file and parse it."""
    with open(path, encoding="utf-8-sig") as f:
        return parse_semgrep(json.load(f))