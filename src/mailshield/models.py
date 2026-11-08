from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    title: str
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity.label,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
        }
