from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace

from mailshield.dns_auth.dkim import DkimResult, audit_dkim
from mailshield.dns_auth.dmarc import ENFORCING, DmarcResult, audit_dmarc
from mailshield.dns_auth.resolver import Resolver
from mailshield.dns_auth.spf import SpfResult, audit_spf, is_null_sender_policy
from mailshield.models import Finding, Severity
from mailshield.scoring import grade, score

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(raw: str) -> str:
    domain = raw.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"'{raw}' does not look like a valid domain name")
    return domain


@dataclass
class AuditReport:
    domain: str
    score: int
    grade: str
    spf: SpfResult
    dmarc: DmarcResult
    dkim: DkimResult
    null_sender: bool = False

    @property
    def findings(self) -> list[Finding]:
        return sorted(
            [*self.spf.findings, *self.dmarc.findings, *self.dkim.findings],
            key=lambda f: f.severity,
            reverse=True,
        )

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "spf": {"record": self.spf.record, "lookups": self.spf.lookups},
            "dmarc": {"record": self.dmarc.record, "policy": self.dmarc.policy},
            "dkim": {
                "selectors_probed": len(self.dkim.probed),
                "selectors_found": [k.selector for k in self.dkim.keys],
            },
            "null_sender": self.null_sender,
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_domain(raw_domain: str, resolver: Resolver, selectors: Sequence[str] = ()) -> AuditReport:
    domain = normalize_domain(raw_domain)
    spf = audit_spf(domain, resolver)
    dmarc = audit_dmarc(domain, resolver)
    dkim = audit_dkim(domain, resolver, selectors)
    if dmarc.policy in ENFORCING:
        # Softfail is fine when DMARC enforces, so it should not cost points.
        spf.findings = [
            replace(f, severity=Severity.INFO, fix="No action needed while DMARC enforces.")
            if f.id == "SPF-SOFTFAIL"
            else f
            for f in spf.findings
        ]
    null_sender = (
        spf.record is not None and is_null_sender_policy(spf.record) and dmarc.policy in ENFORCING
    )
    if null_sender:
        # A domain that declares "I send no mail" doesn't need reporting or DKIM.
        irrelevant = {"DMARC-NO-RUA", "DMARC-STRICT-ADKIM", "DMARC-STRICT-ASPF", "DKIM-NOT-FOUND"}
        dmarc.findings = [f for f in dmarc.findings if f.id not in irrelevant]
        dkim.findings = [f for f in dkim.findings if f.id not in irrelevant]
        spf.findings.append(
            Finding(
                "NULL-SENDER-DOMAIN",
                Severity.INFO,
                "Domain publishes a no-mail policy",
                "SPF is '-all' with no authorized senders and DMARC enforces, so this domain "
                "declares that it sends no email. Reporting and DKIM checks do not apply.",
                "No action needed. Keep both records in place to prevent spoofing.",
            )
        )
    value = score([*spf.findings, *dmarc.findings, *dkim.findings])
    return AuditReport(domain, value, grade(value), spf, dmarc, dkim, null_sender)
