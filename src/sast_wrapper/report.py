"""Turn a list of Findings into a readable Markdown report."""

import re
from collections import Counter
from datetime import date
from pathlib import Path

from sast_wrapper.models import Finding, Severity
from sast_wrapper.owasp import OWASP_2025, UNMAPPED, apply_owasp, owasp_label, rank

SEVERITIES = sorted(Severity, reverse=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO

# Findings about secrets.
SECRET_CWES = {"CWE-259", "CWE-321", "CWE-540", "CWE-798"}
SECRET_WORDS = ("secret", "password", "token", "apikey", "api-key", "credential")

# A quoted value of 8+ characters, with no quotes inside it.
QUOTED = re.compile(r"""(['"])([^'"]{8,})\1""")


def looks_like_secret(f: Finding) -> bool:
    """Is this finding about a secret (so its message might contain one)?"""
    if SECRET_CWES & set(f.cwe):
        return True
    rule = f.rule_id.lower()
    return any(word in rule for word in SECRET_WORDS)


def redact(text: str) -> str:
    """Hide quoted values of 8+ characters, keeping the first 4: 'djan****'."""
    return QUOTED.sub(lambda m: f"{m.group(1)}{m.group(2)[:4]}****{m.group(1)}", text)


def clean_message(f: Finding) -> str:
    message = " ".join(f.message.split())
    if looks_like_secret(f):
        message = redact(message)
    return message


def category_order() -> list[str]:
    """A01 ... A10, then Unmapped last."""
    return [owasp_label(cid) for cid in OWASP_2025] + [UNMAPPED]


def build_report(findings: list[Finding], title: str, generated: str | None = None) -> str:
    findings = rank(apply_owasp(findings))
    generated = generated or date.today().isoformat()
    tools = ", ".join(sorted({f.tool for f in findings})) or "none"

    lines = [
        f"# SAST report: {title}",
        "",
        f"Generated {generated} · Tools: {tools} · Findings: {len(findings)}",
        "",
    ]

    if not findings:
        lines.append("No findings. This means the scanner's rules matched nothing; "
                     "it does not prove the code is secure.")
        return "\n".join(lines) + "\n"

    # Summary table: category x severity
    counts = Counter((f.owasp, f.severity) for f in findings)
    lines += ["## Summary", ""]
    lines.append("| OWASP 2025 category | " + " | ".join(s.name.title() for s in SEVERITIES) + " | Total |")
    lines.append("|" + " --- |" * (len(SEVERITIES) + 2))
    for cat in category_order():
        row = [counts[(cat, s)] for s in SEVERITIES]
        if sum(row):
            lines.append(f"| {cat} | " + " | ".join(str(n) for n in row) + f" | {sum(row)} |")
    lines.append("")

    # One section per category, findings worst first
    for cat in category_order():
        in_cat = [f for f in findings if f.owasp == cat]
        if not in_cat:
            continue
        lines += [f"## {cat}", ""]
        for f in in_cat:
            short_rule = f.rule_id.rsplit(".", 1)[-1]
            cwe = ", ".join(f.cwe) or "none"
            lines += [
                f"### [{f.severity.name}] {short_rule}",
                "",
                f"- **Where:** `{f.file}` line {f.line}",
                f"- **Rule:** `{f.rule_id}` ({f.tool}) · **CWE:** {cwe}",
                f"- **What:** {clean_message(f)}",
                "",
            ]

    return "\n".join(lines)


def write_report(path: str | Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")