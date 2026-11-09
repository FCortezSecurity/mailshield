from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailshield.dns_auth.dmarc import parse_tags
from mailshield.dns_auth.resolver import DnsError, Resolver
from mailshield.fetch import PolicyFetcher
from mailshield.models import Finding, Severity

POLICY_PATH = "/.well-known/mta-sts.txt"
MAX_AGE_LIMIT = 31557600
RECOMMENDED_MAX_AGE = 604800  # one week
ACTIVE_MODES = {"enforce", "testing"}
_ID_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")


@dataclass
class MtaStsResult:
    domain: str
    txt_id: str | None = None
    mode: str | None = None
    max_age: int | None = None
    mx: list[str] = field(default_factory=list)
    fetched: bool = False
    findings: list[Finding] = field(default_factory=list)


def parse_policy(text: str) -> tuple[dict, list[str]]:
    """Parse an MTA-STS policy file. Returns (fields, problems)."""
    version = mode = None
    max_age: int | None = None
    mx: list[str] = []
    problems: list[str] = []
    bad_max_age = False
    for line in text.splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            problems.append(f"unparseable line: {line.strip()[:40]!r}")
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "version":
            version = value
        elif key == "mode":
            mode = value.lower()
        elif key == "max_age":
            try:
                max_age = int(value)
            except ValueError:
                bad_max_age = True
                problems.append("max_age is not a number")
        elif key == "mx" and value:
            mx.append(value.lower().rstrip("."))
    if version != "STSv1":
        problems.append("version must be STSv1")
    if mode not in {"enforce", "testing", "none"}:
        problems.append("mode must be enforce, testing or none")
    if max_age is None and not bad_max_age:
        problems.append("max_age is missing")
    elif max_age is not None and not 0 <= max_age <= MAX_AGE_LIMIT:
        problems.append(f"max_age must be between 0 and {MAX_AGE_LIMIT}")
    if mode != "none" and not mx:
        problems.append("at least one mx entry is required")
    return {"version": version, "mode": mode, "max_age": max_age, "mx": mx}, problems


def mx_matches(pattern: str, host: str) -> bool:
    """RFC 8461 matching: exact, or '*.example.com' matching exactly one leftmost label."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        label = host[: -len(suffix)] if host.endswith(suffix) else ""
        return bool(label) and "." not in label
    return pattern == host


def audit_mta_sts(
    domain: str, resolver: Resolver, fetcher: PolicyFetcher | None = None
) -> MtaStsResult:
    result = MtaStsResult(domain)
    findings = result.findings
    name = f"_mta-sts.{domain}"
    try:
        records = [r for r in resolver.txt(name) if r.strip().lower().startswith("v=stsv1")]
    except DnsError as exc:
        findings.append(
            Finding(
                "MTA-STS-DNS-ERROR",
                Severity.INFO,
                "DNS lookup failed while reading MTA-STS",
                f"Could not query TXT for {name} ({exc}).",
                "Retry later.",
            )
        )
        return result

    if not records:
        findings.append(
            Finding(
                "MTA-STS-MISSING",
                Severity.INFO,
                "No MTA-STS policy",
                "MTA-STS makes sending servers require TLS when delivering mail to you, "
                "which blocks downgrade attacks. It is optional hardening.",
                "Publish a _mta-sts TXT record and a policy file at "
                f"https://mta-sts.{domain}{POLICY_PATH}.",
            )
        )
        return result

    tags = parse_tags(records[0]) if len(records) == 1 else {}
    sts_id = tags.get("id", "")
    if len(records) > 1 or tags.get("v") != "STSv1" or not _ID_RE.match(sts_id):
        findings.append(
            Finding(
                "MTA-STS-TXT-INVALID",
                Severity.MEDIUM,
                "MTA-STS DNS record is invalid",
                f"{name} must be a single record like 'v=STSv1; id=<up to 32 letters/digits>'. "
                "Senders ignore invalid records, so MTA-STS is not in effect.",
                "Publish exactly one valid record and change the id whenever the policy changes.",
            )
        )
        return result
    result.txt_id = sts_id

    if fetcher is None:
        findings.append(
            Finding(
                "MTA-STS-NOT-FETCHED",
                Severity.INFO,
                "MTA-STS policy file was not fetched",
                "Network fetching was disabled, so only the DNS record was checked.",
                "Run without --no-fetch to validate the policy file.",
            )
        )
        return result

    host = f"mta-sts.{domain}"
    response = fetcher.fetch(host, POLICY_PATH)
    url = f"https://{host}{POLICY_PATH}"

    def unreachable(reason: str, severity: Severity = Severity.MEDIUM, fid: str | None = None):
        findings.append(
            Finding(
                fid or "MTA-STS-POLICY-UNREACHABLE",
                severity,
                "MTA-STS policy file cannot be used",
                f"{url}: {reason}. Senders cannot load the policy, so MTA-STS is not enforced.",
                "Serve the policy over HTTPS with a valid certificate, no redirects, and status 200.",
            )
        )

    if response.error:
        unreachable(response.error)
        return result
    if response.status is not None and 300 <= response.status < 400:
        unreachable(
            f"it redirects (HTTP {response.status}), which RFC 8461 forbids",
            fid="MTA-STS-REDIRECT",
        )
        return result
    if response.status != 200:
        unreachable(f"HTTP status {response.status}")
        return result
    if not response.content_type.lower().startswith("text/plain"):
        findings.append(
            Finding(
                "MTA-STS-CONTENT-TYPE",
                Severity.LOW,
                "MTA-STS policy has the wrong content type",
                f"{url} is served as '{response.content_type or 'none'}'; RFC 8461 requires text/plain.",
                "Serve the file with Content-Type: text/plain.",
            )
        )

    fields, problems = parse_policy(response.body)
    if problems:
        findings.append(
            Finding(
                "MTA-STS-POLICY-INVALID",
                Severity.MEDIUM,
                "MTA-STS policy file is invalid",
                f"{url}: " + "; ".join(problems) + ".",
                "Fix the policy file so senders can parse it.",
            )
        )
        return result

    result.fetched = True
    result.mode, result.max_age, result.mx = fields["mode"], fields["max_age"], fields["mx"]
    if result.mode == "testing":
        findings.append(
            Finding(
                "MTA-STS-TESTING",
                Severity.LOW,
                "MTA-STS is in testing mode",
                "Senders report TLS failures but still deliver mail, so downgrade attacks are "
                "not blocked yet.",
                "Switch to mode: enforce once TLS-RPT reports look clean.",
            )
        )
    elif result.mode == "none":
        findings.append(
            Finding(
                "MTA-STS-DISABLED",
                Severity.LOW,
                "MTA-STS policy is set to mode none",
                "mode: none tells senders to stop applying MTA-STS.",
                "Use mode: enforce if you want TLS to be required.",
            )
        )
    elif result.max_age is not None and result.max_age < RECOMMENDED_MAX_AGE:
        findings.append(
            Finding(
                "MTA-STS-MAXAGE-SHORT",
                Severity.LOW,
                "MTA-STS max_age is short",
                f"max_age is {result.max_age} seconds; senders cache the policy for that long, "
                "so a short value weakens protection.",
                f"Use at least {RECOMMENDED_MAX_AGE} seconds (one week); weeks are typical.",
            )
        )

    if result.mode in ACTIVE_MODES:
        try:
            actual = resolver.mx(domain)
        except DnsError:
            actual = []
        missing = [h for h in actual if not any(mx_matches(p, h) for p in result.mx)]
        if missing:
            enforcing = result.mode == "enforce"
            findings.append(
                Finding(
                    "MTA-STS-MX-MISMATCH",
                    Severity.HIGH if enforcing else Severity.MEDIUM,
                    "Mail servers are missing from the MTA-STS policy",
                    f"MX hosts not covered by the policy: {', '.join(missing)}. "
                    + (
                        "In enforce mode, MTA-STS-aware senders will refuse to deliver to them."
                        if enforcing
                        else "They would be refused once the mode becomes enforce."
                    ),
                    "Add every MX host (or a matching *.domain pattern) to the mx lines.",
                )
            )
    return result
