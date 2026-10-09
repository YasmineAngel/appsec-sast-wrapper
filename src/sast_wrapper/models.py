from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_text(cls, text: str) -> "Severity":
        aliases = {
            "INFO": cls.INFO,
            "LOW": cls.LOW,
            "MEDIUM": cls.MEDIUM,
            "WARNING": cls.MEDIUM,
            "HIGH": cls.HIGH,
            "ERROR": cls.HIGH,
            "CRITICAL": cls.CRITICAL,
        }
        return aliases.get(text.strip().upper(), cls.INFO)


@dataclass
class Finding:

    tool: str  # "semgrep" or "bandit"
    rule_id: str
    message: str
    file: str
    line: int
    severity: Severity
    cwe: list[str] = field(default_factory=list)
    owasp: str | None = None