"""Map findings to OWASP Top 10 2025 categories (via CWE) and rank them."""

from sast_wrapper.models import Finding

OWASP_2025 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

UNMAPPED = "Unmapped"

# Starter table: common CWEs -> OWASP 2025 category.
# Not OWASP's full official list. When a real finding shows up as
# "Unmapped", check its CWE on owasp.org and add a line here.
CWE_TO_OWASP = {
    # A01 Broken Access Control (SSRF joined A01 in 2025)
    "CWE-22": "A01", "CWE-23": "A01", "CWE-200": "A01", "CWE-284": "A01",
    "CWE-285": "A01", "CWE-352": "A01", "CWE-601": "A01", "CWE-639": "A01",
    "CWE-862": "A01", "CWE-863": "A01", "CWE-918": "A01",
    # A02 Security Misconfiguration
    "CWE-16": "A02", "CWE-489": "A02", "CWE-611": "A02", "CWE-614": "A02",
    "CWE-942": "A02", "CWE-1004": "A02",
    # A03 Software Supply Chain Failures
    "CWE-1104": "A03", "CWE-1357": "A03", "CWE-1395": "A03",
    # A04 Cryptographic Failures
    "CWE-319": "A04", "CWE-321": "A04", "CWE-326": "A04", "CWE-327": "A04",
    "CWE-328": "A04", "CWE-330": "A04", "CWE-338": "A04", "CWE-916": "A04",
    # A05 Injection (includes XSS)
    "CWE-74": "A05", "CWE-77": "A05", "CWE-78": "A05", "CWE-79": "A05",
    "CWE-89": "A05", "CWE-94": "A05", "CWE-95": "A05", "CWE-917": "A05",
    "CWE-943": "A05", "CWE-1336": "A05",
    # A06 Insecure Design
    "CWE-434": "A06",
    # A07 Authentication Failures
    "CWE-259": "A07", "CWE-287": "A07", "CWE-307": "A07", "CWE-384": "A07",
    "CWE-521": "A07", "CWE-613": "A07", "CWE-798": "A07",
    # A08 Software or Data Integrity Failures
    "CWE-345": "A08", "CWE-353": "A08", "CWE-494": "A08", "CWE-502": "A08",
    # A09 Security Logging and Alerting Failures
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
    # A10 Mishandling of Exceptional Conditions
    "CWE-209": "A10", "CWE-248": "A10", "CWE-390": "A10", "CWE-391": "A10",
    "CWE-703": "A10", "CWE-755": "A10",
}


def owasp_label(category_id: str) -> str:
    """'A05' -> 'A05:2025 Injection' (the official way to write it)."""
    return f"{category_id}:2025 {OWASP_2025[category_id]}"


def cwe_to_owasp(cwe: str) -> str | None:
    """'CWE-89' -> 'A05:2025 Injection', or None if we don't know this CWE."""
    category_id = CWE_TO_OWASP.get(cwe)
    if category_id is None:
        return None
    return owasp_label(category_id)


def apply_owasp(findings: list[Finding]) -> list[Finding]:
    """Fill in .owasp on every finding. The first CWE we recognise wins."""
    for f in findings:
        f.owasp = UNMAPPED
        for cwe in f.cwe:
            label = cwe_to_owasp(cwe)
            if label:
                f.owasp = label
                break
    return findings


def rank(findings: list[Finding]) -> list[Finding]:
    """Worst first. Same severity -> grouped by OWASP family, then file, then line."""
    return sorted(findings, key=lambda f: (-f.severity, f.owasp or UNMAPPED, f.file, f.line))