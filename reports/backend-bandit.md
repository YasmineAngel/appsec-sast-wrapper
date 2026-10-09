# SAST report: backend (bandit)

Generated 2026-10-09 · Tools: bandit · Findings: 1

## Summary

| OWASP 2025 category | Critical | High | Medium | Low | Info | Total |
| --- | --- | --- | --- | --- | --- | --- |
| A07:2025 Authentication Failures | 0 | 0 | 0 | 1 | 0 | 1 |

## A07:2025 Authentication Failures

### [LOW] B105 hardcoded_password_string

- **Where:** `backend/settings.py` line 23
- **Rule:** `B105 hardcoded_password_string` (bandit) · **CWE:** CWE-259
- **What:** Possible hardcoded password: 'djan****'
