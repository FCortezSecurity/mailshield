from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailshield.dns_auth.resolver import DnsError, Resolver
from mailshield.models import Finding, Severity

LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
KNOWN_MECHANISMS = LOOKUP_MECHANISMS | {"all", "ip4", "ip6"}
MAX_LOOKUPS = 10
MAX_DEPTH = 10

_MODIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*=")
_MECH_RE = re.compile(r"^([A-Za-z0-9]+)(?::(.*))?")


@dataclass(frozen=True)
class Term:
    kind: str  # "mechanism" or "modifier"
    qualifier: str  # "+", "-", "~", "?" (empty for modifiers)
    name: str
    value: str
    raw: str


@dataclass
class SpfResult:
    domain: str
    record: str | None
    lookups: int
    findings: list[Finding] = field(default_factory=list)


def is_spf(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def parse_terms(record: str) -> list[Term]:
    terms: list[Term] = []
    for token in record.split()[1:]:
        if _MODIFIER_RE.match(token):
            key, _, val = token.partition("=")
            terms.append(Term("modifier", "", key.lower(), val, token))
            continue
        qualifier = "+"
        rest = token
        if token[0] in "+-~?":
            qualifier, rest = token[0], token[1:]
        match = _MECH_RE.match(rest)
        if not match:
            terms.append(Term("mechanism", qualifier, rest.lower(), "", token))
            continue
        terms.append(
            Term("mechanism", qualifier, match.group(1).lower(), match.group(2) or "", token)
        )
    return terms


class _Walker:
    def __init__(self, resolver: Resolver) -> None:
        self.resolver = resolver
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, finding: Finding) -> None:
        key = (finding.id, finding.detail)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)

    def fetch(self, domain: str, *, included: bool = False) -> str | None:
        try:
            records = [r for r in self.resolver.txt(domain) if is_spf(r)]
        except DnsError as exc:
            self.add(
                Finding(
                    "SPF-DNS-ERROR",
                    Severity.MEDIUM,
                    "DNS lookup failed while reading SPF",
                    f"Could not query TXT for {domain} ({exc}). Results may be incomplete.",
                    "Retry later; check that the domain's nameservers respond.",
                )
            )
            return None
        if not records:
            if included:
                self.add(
                    Finding(
                        "SPF-INCLUDE-INVALID",
                        Severity.HIGH,
                        "Included/redirected domain has no SPF record",
                        f"{domain} is referenced but publishes no SPF record, "
                        "which makes the whole policy evaluate to PermError.",
                        f"Remove the reference to {domain} or fix its SPF record.",
                    )
                )
            return None
        if len(records) > 1:
            self.add(
                Finding(
                    "SPF-MULTIPLE",
                    Severity.HIGH,
                    "Multiple SPF records",
                    f"{domain} publishes {len(records)} SPF records. "
                    "Receivers return PermError, so SPF effectively fails.",
                    "Merge everything into a single TXT record starting with v=spf1.",
                )
            )
        return records[0]

    def walk(self, domain: str, record: str, chain: list[str]) -> int:
        count = 0
        for term in parse_terms(record):
            if term.kind == "mechanism" and term.name not in KNOWN_MECHANISMS:
                self.add(
                    Finding(
                        "SPF-SYNTAX",
                        Severity.MEDIUM,
                        "Unknown SPF mechanism",
                        f"'{term.raw}' in {domain} is not a valid mechanism.",
                        "Fix or remove the term; receivers may treat the record as PermError.",
                    )
                )
                continue
            is_lookup = (term.kind == "mechanism" and term.name in LOOKUP_MECHANISMS) or (
                term.kind == "modifier" and term.name == "redirect"
            )
            if is_lookup:
                count += 1
            if term.kind == "mechanism" and term.name == "ptr":
                self.add(
                    Finding(
                        "SPF-PTR",
                        Severity.MEDIUM,
                        "Deprecated ptr mechanism",
                        f"'{term.raw}' in {domain} uses ptr, which is slow, unreliable and "
                        "discouraged by RFC 7208.",
                        "Replace ptr with explicit ip4/ip6/include entries.",
                    )
                )
            is_recursive = (term.kind == "mechanism" and term.name == "include") or (
                term.kind == "modifier" and term.name == "redirect"
            )
            if not is_recursive:
                continue
            target = term.value.strip().lower().rstrip(".")
            if not target:
                self.add(
                    Finding(
                        "SPF-SYNTAX",
                        Severity.MEDIUM,
                        "Empty include/redirect target",
                        f"'{term.raw}' in {domain} has no domain.",
                        "Add a domain or remove the term.",
                    )
                )
                continue
            if "%" in target:
                continue  # macro; cannot be resolved statically
            if target in chain:
                self.add(
                    Finding(
                        "SPF-LOOP",
                        Severity.HIGH,
                        "SPF include loop",
                        f"{' -> '.join([*chain, target])} loops back on itself.",
                        "Break the circular include.",
                    )
                )
                continue
            if len(chain) > MAX_DEPTH:
                continue
            sub = self.fetch(target, included=True)
            if sub is not None:
                count += self.walk(target, sub, [*chain, target])
        return count


def _check_all(terms: list[Term], add) -> None:
    mechs = [t for t in terms if t.kind == "mechanism"]
    all_idx = [i for i, t in enumerate(mechs) if t.name == "all"]
    has_redirect = any(t.kind == "modifier" and t.name == "redirect" for t in terms)
    if not all_idx:
        if not has_redirect:
            add(
                Finding(
                    "SPF-NO-ALL",
                    Severity.MEDIUM,
                    "SPF record has no 'all' terminator",
                    "Without an 'all' term (or redirect), unlisted senders get a neutral result.",
                    "End the record with -all (or ~all while you are still validating senders).",
                )
            )
        return
    first = mechs[all_idx[0]]
    if all_idx[0] != len(mechs) - 1:
        add(
            Finding(
                "SPF-ALL-NOT-LAST",
                Severity.LOW,
                "Terms after 'all' are ignored",
                "Anything written after the 'all' mechanism is never evaluated.",
                "Move 'all' to the end of the record.",
            )
        )
    if first.qualifier == "+":
        add(
            Finding(
                "SPF-ALL-PLUS",
                Severity.CRITICAL,
                "SPF allows every sender (+all)",
                f"'{first.raw}' authorizes any server on the internet to send as this domain.",
                "Replace with -all (or ~all while testing).",
            )
        )
    elif first.qualifier == "?":
        add(
            Finding(
                "SPF-ALL-NEUTRAL",
                Severity.HIGH,
                "SPF is neutral (?all)",
                "Unlisted senders are neither passed nor failed, so SPF gives no protection.",
                "Replace ?all with -all (or ~all while testing).",
            )
        )
    elif first.qualifier == "~":
        add(
            Finding(
                "SPF-SOFTFAIL",
                Severity.LOW,
                "SPF uses softfail (~all)",
                "Unlisted senders are marked suspicious rather than rejected. "
                "This is acceptable when DMARC enforces, otherwise it is weak.",
                "Move to -all once all legitimate senders are listed.",
            )
        )


def is_null_sender_policy(record: str) -> bool:
    """True for 'v=spf1 -all': no server is allowed to send as this domain."""
    terms = parse_terms(record)
    mechs = [t for t in terms if t.kind == "mechanism"]
    has_redirect = any(t.kind == "modifier" and t.name == "redirect" for t in terms)
    return (
        len(mechs) == 1
        and mechs[0].name == "all"
        and mechs[0].qualifier == "-"
        and not has_redirect
    )


def audit_spf(domain: str, resolver: Resolver) -> SpfResult:
    walker = _Walker(resolver)
    record = walker.fetch(domain)
    if record is None:
        if not walker.findings:
            walker.add(
                Finding(
                    "SPF-MISSING",
                    Severity.HIGH,
                    "No SPF record",
                    f"{domain} publishes no SPF record, so anyone can spoof it more easily.",
                    'Publish a TXT record such as "v=spf1 include:<your mail provider> -all".',
                )
            )
        return SpfResult(domain, None, 0, walker.findings)

    _check_all(parse_terms(record), walker.add)
    lookups = walker.walk(domain, record, [domain])
    if lookups > MAX_LOOKUPS:
        walker.add(
            Finding(
                "SPF-LOOKUP-LIMIT",
                Severity.HIGH,
                "SPF exceeds the 10 DNS lookup limit",
                f"The policy needs {lookups} lookups; RFC 7208 allows 10. "
                "Receivers return PermError and SPF fails.",
                "Remove unused includes or flatten them into ip4/ip6 ranges.",
            )
        )
    elif lookups >= MAX_LOOKUPS - 1:
        walker.add(
            Finding(
                "SPF-LOOKUP-NEAR",
                Severity.LOW,
                "SPF is close to the 10 lookup limit",
                f"The policy uses {lookups} of 10 lookups; one more include may break it.",
                "Audit includes and remove vendors you no longer use.",
            )
        )
    return SpfResult(domain, record, lookups, walker.findings)
