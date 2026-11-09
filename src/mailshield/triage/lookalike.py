"""Look-alike domain detection against domains you declare as your own."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.domains import org_domain

CONFUSABLES = {
    "0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "$": "s",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "l", "\u0455": "s",
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u03bd": "v", "\u03b9": "l",
}  # fmt: skip
MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))
MAX_FINDINGS = 5


def _unicode(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


def skeleton(domain: str) -> str:
    """Collapse characters that look alike so that look-alike domains compare equal."""
    text = "".join(CONFUSABLES.get(c, c) for c in _unicode(domain).lower())
    for old, new in MULTI:
        text = text.replace(old, new)
    return text


def edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _split(org: str) -> tuple[str, str]:
    label, _, tld = org.partition(".")
    return label, tld


def check_lookalikes(
    candidates: Iterable[tuple[str, str]], trusted_domains: Sequence[str]
) -> list[Finding]:
    trusted = list(dict.fromkeys(org_domain(d.lower()) for d in trusted_domains if d))
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for origin, domain in candidates:
        domain = domain.lower().rstrip(".")
        org = org_domain(domain)
        if not domain or org in trusted:
            continue
        for real in trusted:
            if (org, real) in seen:
                continue
            label, tld = _split(org)
            real_label, real_tld = _split(real)
            found: tuple[str, Severity, str] | None = None
            if label == real_label and tld != real_tld:
                found = (
                    "LOOK-TLD-SWAP",
                    Severity.HIGH,
                    "uses the same name with a different ending",
                )
            elif skeleton(org) == skeleton(real):
                found = ("LOOK-HOMOGLYPH", Severity.HIGH, "uses look-alike characters")
            elif tld == real_tld and len(real_label) >= 5:
                distance = edit_distance(label, real_label)
                if distance == 1:
                    found = ("LOOK-EDIT-DISTANCE", Severity.HIGH, "differs by a single character")
                elif distance == 2:
                    found = ("LOOK-EDIT-DISTANCE", Severity.MEDIUM, "differs by two characters")
            if found is None and len(real_label) >= 4:
                if real_label in domain.replace("-", ".").split("."):
                    found = ("LOOK-EMBEDDED", Severity.MEDIUM, "contains your domain name")
            if found is None:
                continue
            seen.add((org, real))
            fid, severity, how = found
            findings.append(
                Finding(
                    fid,
                    severity,
                    "Domain imitates one of your domains",
                    f"{clean(domain, 100)} (from the {origin}) {how}: it resembles {clean(real, 100)}.",
                    "Compare the real domain character by character, and report it if unexpected.",
                )
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings
