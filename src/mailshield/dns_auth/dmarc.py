from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailshield.dns_auth.resolver import DnsError, Resolver
from mailshield.models import Finding, Severity

_DMARC_RE = re.compile(r"^v=DMARC1\s*(;|$)", re.IGNORECASE)
VALID_POLICIES = {"none", "quarantine", "reject"}
ENFORCING = {"quarantine", "reject"}


@dataclass
class DmarcResult:
    domain: str
    record: str | None
    policy: str | None
    findings: list[Finding] = field(default_factory=list)


def parse_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags.setdefault(key.strip().lower(), value.strip())
    return tags


def audit_dmarc(domain: str, resolver: Resolver) -> DmarcResult:
    name = f"_dmarc.{domain}"
    findings: list[Finding] = []
    try:
        records = [r for r in resolver.txt(name) if _DMARC_RE.match(r.strip())]
    except DnsError as exc:
        findings.append(
            Finding(
                "DMARC-DNS-ERROR",
                Severity.MEDIUM,
                "DNS lookup failed while reading DMARC",
                f"Could not query TXT for {name} ({exc}). Results may be incomplete.",
                "Retry later; check that the domain's nameservers respond.",
            )
        )
        return DmarcResult(domain, None, None, findings)

    if not records:
        findings.append(
            Finding(
                "DMARC-MISSING",
                Severity.HIGH,
                "No DMARC record",
                f"{name} has no DMARC record, so receivers have no policy for spoofed mail "
                "and you get no reports about abuse.",
                'Publish a TXT record at _dmarc such as "v=DMARC1; p=none; rua=mailto:you@example.com" '
                "and tighten the policy over time.",
            )
        )
        return DmarcResult(domain, None, None, findings)

    if len(records) > 1:
        findings.append(
            Finding(
                "DMARC-MULTIPLE",
                Severity.HIGH,
                "Multiple DMARC records",
                f"{name} has {len(records)} DMARC records; receivers ignore all of them.",
                "Keep exactly one DMARC record.",
            )
        )
        return DmarcResult(domain, records[0], None, findings)

    record = records[0]
    tags = parse_tags(record)
    policy = tags.get("p", "").lower()
    if policy not in VALID_POLICIES:
        findings.append(
            Finding(
                "DMARC-INVALID",
                Severity.HIGH,
                "DMARC policy missing or invalid",
                f"The p= tag is {'absent' if not policy else repr(policy)}; "
                "receivers will likely ignore the record.",
                "Set p=none, p=quarantine or p=reject.",
            )
        )
        return DmarcResult(domain, record, None, findings)

    if policy == "none":
        findings.append(
            Finding(
                "DMARC-P-NONE",
                Severity.MEDIUM,
                "DMARC is monitor-only (p=none)",
                "Spoofed mail is still delivered. p=none is fine as a first step, "
                "but it does not stop impersonation.",
                "Review reports, then move to p=quarantine and finally p=reject.",
            )
        )
    elif policy == "quarantine":
        findings.append(
            Finding(
                "DMARC-P-QUARANTINE",
                Severity.INFO,
                "DMARC quarantines failures (p=quarantine)",
                "Failing mail goes to spam. p=reject gives the strongest protection.",
                "Consider p=reject once reports look clean.",
            )
        )

    if policy in ENFORCING:
        try:
            pct = int(tags.get("pct", "100"))
        except ValueError:
            pct = 100
        if pct < 100:
            findings.append(
                Finding(
                    "DMARC-PCT",
                    Severity.MEDIUM,
                    "DMARC applies to only part of the mail",
                    f"pct={pct} means {100 - pct}% of failing mail is not subject to the policy.",
                    "Raise pct to 100 when you are confident in your senders.",
                )
            )
        sp = tags.get("sp", "").lower()
        if sp == "none":
            findings.append(
                Finding(
                    "DMARC-SP-WEAK",
                    Severity.MEDIUM,
                    "Subdomains are not protected (sp=none)",
                    "Attackers can spoof subdomains even though the main domain enforces.",
                    "Remove sp= or set it to quarantine/reject.",
                )
            )

    if not tags.get("rua", ""):
        findings.append(
            Finding(
                "DMARC-NO-RUA",
                Severity.LOW,
                "No aggregate reporting address (rua)",
                "Without rua you cannot see who is sending mail as your domain.",
                "Add rua=mailto:<address> to receive daily aggregate reports.",
            )
        )

    for tag, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        if tags.get(tag, "r").lower() == "s":
            findings.append(
                Finding(
                    f"DMARC-STRICT-{tag.upper()}",
                    Severity.INFO,
                    f"Strict {label} alignment",
                    f"{tag}=s requires an exact domain match, which can break mail from subdomains "
                    "or third-party senders.",
                    "Keep it only if you need exact-match alignment.",
                )
            )

    return DmarcResult(domain, record, policy, findings)
