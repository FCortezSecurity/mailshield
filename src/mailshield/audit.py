from __future__ import annotations

import re
from dataclasses import dataclass

from mailshield.dns_auth.dmarc import DmarcResult, audit_dmarc
from mailshield.dns_auth.resolver import Resolver
from mailshield.dns_auth.spf import SpfResult, audit_spf
from mailshield.models import Finding
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

    @property
    def findings(self) -> list[Finding]:
        return sorted(
            [*self.spf.findings, *self.dmarc.findings],
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
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_domain(raw_domain: str, resolver: Resolver) -> AuditReport:
    domain = normalize_domain(raw_domain)
    spf = audit_spf(domain, resolver)
    dmarc = audit_dmarc(domain, resolver)
    value = score([*spf.findings, *dmarc.findings])
    return AuditReport(domain, value, grade(value), spf, dmarc)
