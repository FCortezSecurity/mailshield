from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.headers import analyze_headers

WEIGHTS = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 30,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
    Severity.INFO: 0,
}
LIKELY_PHISHING = 60
SUSPICIOUS = 25
DISCLAIMER = (
    "Heuristic result from header analysis only. A message with no findings can still be "
    "malicious, and a finding is a reason to look closer, not proof."
)


def risk_score(findings: Sequence[Finding]) -> int:
    return min(100, sum(WEIGHTS[f.severity] for f in findings))


def verdict_for(risk: int) -> str:
    if risk >= LIKELY_PHISHING:
        return "likely phishing"
    if risk >= SUSPICIOUS:
        return "suspicious"
    return "no strong indicators"


@dataclass
class TriageReport:
    subject: str
    sender: str
    risk: int
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "sender": self.sender,
            "risk": self.risk,
            "verdict": self.verdict,
            "facts": self.facts,
            "findings": [f.to_dict() for f in self.findings],
            "note": DISCLAIMER,
        }


def triage_message(
    msg: EmailMessage,
    protected_names: Sequence[str] = (),
    trusted_domains: Sequence[str] = (),
) -> TriageReport:
    findings, facts = analyze_headers(msg, protected_names, trusted_domains)
    findings.sort(key=lambda f: f.severity, reverse=True)
    risk = risk_score(findings)
    sender = facts["from"][0] if facts["from"] else ""
    return TriageReport(
        subject=clean(msg.get("Subject", "") or "", 200),
        sender=sender,
        risk=risk,
        verdict=verdict_for(risk),
        findings=findings,
        facts=facts,
    )
