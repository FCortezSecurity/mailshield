from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.attachments import inspect_attachments
from mailshield.triage.body import extract_bodies
from mailshield.triage.content import analyze_content
from mailshield.triage.domains import domain_of
from mailshield.triage.headers import addresses, analyze_headers
from mailshield.triage.lookalike import check_lookalikes
from mailshield.triage.urls import analyze_urls

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
    "Heuristic result from headers, links, attachments and wording. Links were never visited "
    "and attachments were never opened. A message with no findings can still be malicious, and "
    "a finding is a reason to look closer, not proof."
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
    subject = clean(msg.get("Subject", "") or "", 200)
    body = extract_bodies(msg)
    url_result = analyze_urls(body)
    attachment_findings, attachment_facts = inspect_attachments(msg)
    candidates = [("sender address", domain_of(a)) for _, a in addresses(msg, "From")[:1]]
    candidates += [("Reply-To address", domain_of(a)) for _, a in addresses(msg, "Reply-To")[:1]]
    candidates += [("links", host) for host in url_result.hosts]
    findings += url_result.findings
    findings += attachment_findings
    findings += check_lookalikes(candidates, trusted_domains)
    findings += analyze_content(subject, body)
    facts["urls"] = url_result.urls
    facts["attachments"] = attachment_facts
    findings.sort(key=lambda f: f.severity, reverse=True)
    risk = risk_score(findings)
    sender = facts["from"][0] if facts["from"] else ""
    return TriageReport(
        subject=subject,
        sender=sender,
        risk=risk,
        verdict=verdict_for(risk),
        findings=findings,
        facts=facts,
    )
