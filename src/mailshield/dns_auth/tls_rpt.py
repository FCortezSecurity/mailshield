from __future__ import annotations

from dataclasses import dataclass, field

from mailshield.dns_auth.dmarc import parse_tags
from mailshield.dns_auth.resolver import DnsError, Resolver
from mailshield.models import Finding, Severity


@dataclass
class TlsRptResult:
    domain: str
    record: str | None = None
    findings: list[Finding] = field(default_factory=list)


def audit_tls_rpt(
    domain: str, resolver: Resolver, mta_sts_present: bool, mta_sts_active: bool
) -> TlsRptResult:
    result = TlsRptResult(domain)
    findings = result.findings
    name = f"_smtp._tls.{domain}"
    try:
        records = [r for r in resolver.txt(name) if r.strip().lower().startswith("v=tlsrptv1")]
    except DnsError as exc:
        findings.append(
            Finding(
                "TLSRPT-DNS-ERROR",
                Severity.INFO,
                "DNS lookup failed while reading TLS-RPT",
                f"Could not query TXT for {name} ({exc}).",
                "Retry later.",
            )
        )
        return result

    if not records:
        if mta_sts_present:
            findings.append(
                Finding(
                    "TLSRPT-MISSING",
                    Severity.LOW if mta_sts_active else Severity.INFO,
                    "No TLS-RPT record",
                    "Without TLS-RPT you will not receive reports about failed secure "
                    "deliveries, which makes MTA-STS problems hard to notice.",
                    'Publish a TXT record at _smtp._tls such as "v=TLSRPTv1; rua=mailto:you@example.com".',
                )
            )
        return result

    result.record = records[0]
    tags = parse_tags(records[0]) if len(records) == 1 else {}
    targets = [t.strip() for t in tags.get("rua", "").split(",") if t.strip()]
    valid = bool(targets) and all(t.lower().startswith(("mailto:", "https:")) for t in targets)
    if len(records) > 1 or not valid:
        findings.append(
            Finding(
                "TLSRPT-INVALID",
                Severity.LOW,
                "TLS-RPT record is invalid",
                f"{name} needs exactly one record with rua= pointing to mailto: or https: "
                "addresses, otherwise no reports are sent.",
                'Use the form "v=TLSRPTv1; rua=mailto:you@example.com".',
            )
        )
    return result
