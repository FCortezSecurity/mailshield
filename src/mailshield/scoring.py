from __future__ import annotations

from collections.abc import Iterable

from mailshield.models import Finding, Severity

DEDUCTIONS = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 25,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


def score(findings: Iterable[Finding]) -> int:
    return max(0, 100 - sum(DEDUCTIONS[f.severity] for f in findings))


def grade(value: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if value >= threshold:
            return letter
    return "F"
