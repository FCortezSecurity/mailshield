from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from dataclasses import dataclass, field

from mailshield.dns_auth.dmarc import parse_tags
from mailshield.dns_auth.resolver import DnsError, Resolver
from mailshield.models import Finding, Severity

# DKIM selectors cannot be listed through DNS, so we probe names that are common
# defaults for popular mail providers. A miss does NOT mean DKIM is absent.
COMMON_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "key1",
    "key2",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "everlytickey1",
    "cm",
)


def probe_summary(probed: Sequence[str], noun: str = "selectors") -> str:
    common = sum(1 for s in probed if s in COMMON_SELECTORS)
    custom = len(probed) - common
    text = f"{common} common {noun}"
    return f"{text} + {custom} custom" if custom else text


@dataclass
class DkimKey:
    selector: str
    key_type: str
    bits: int | None
    revoked: bool
    testing: bool


@dataclass
class DkimResult:
    domain: str
    probed: list[str]
    keys: list[DkimKey] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Read one DER element. Returns (tag, content_start, content_end)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, pos, end


def _bit_length(modulus: bytes) -> int:
    stripped = modulus.lstrip(b"\x00")
    if not stripped:
        raise ValueError("empty modulus")
    return (len(stripped) - 1) * 8 + stripped[0].bit_length()


def rsa_key_bits(der: bytes) -> int:
    """Return the RSA modulus size in bits from a DER SubjectPublicKeyInfo or PKCS#1 key."""
    try:
        tag, start, _ = _tlv(der, 0)
        if tag != 0x30:
            raise ValueError("not a DER sequence")
        child_tag, child_start, child_end = _tlv(der, start)
        if child_tag == 0x02:  # PKCS#1: SEQUENCE { INTEGER n, INTEGER e }
            return _bit_length(der[child_start:child_end])
        if child_tag != 0x30:  # SPKI: SEQUENCE { algorithm, BIT STRING { PKCS#1 } }
            raise ValueError("unrecognized key structure")
        bit_tag, bit_start, bit_end = _tlv(der, child_end)
        if bit_tag != 0x03:
            raise ValueError("missing bit string")
        inner = der[bit_start + 1 : bit_end]
        inner_tag, inner_start, _ = _tlv(inner, 0)
        if inner_tag != 0x30:
            raise ValueError("bad inner key")
        n_tag, n_start, n_end = _tlv(inner, inner_start)
        if n_tag != 0x02:
            raise ValueError("missing modulus")
        return _bit_length(inner[n_start:n_end])
    except IndexError as exc:
        raise ValueError("truncated DER") from exc


def audit_dkim(domain: str, resolver: Resolver, extra_selectors: Sequence[str] = ()) -> DkimResult:
    selectors = list(
        dict.fromkeys(s.strip().lower() for s in (*extra_selectors, *COMMON_SELECTORS) if s.strip())
    )
    result = DkimResult(domain, selectors)
    findings = result.findings
    errors = 0

    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        try:
            texts = resolver.txt(name)
        except DnsError:
            errors += 1
            continue
        candidates = [t for t in texts if "p" in parse_tags(t)]
        if not candidates:
            continue
        tags = parse_tags(candidates[0])
        key_type = tags.get("k", "rsa").lower()
        public_key = "".join(tags.get("p", "").split())
        flags = [f.strip() for f in tags.get("t", "").lower().split(":")]
        key = DkimKey(selector, key_type, None, public_key == "", "y" in flags)
        result.keys.append(key)

        if key.revoked:
            continue  # reported once, as a group, after the loop

        if key_type == "rsa":
            try:
                key.bits = rsa_key_bits(base64.b64decode(public_key, validate=True))
            except (binascii.Error, ValueError):
                findings.append(
                    Finding(
                        "DKIM-INVALID",
                        Severity.MEDIUM,
                        f"DKIM key for '{selector}' could not be parsed",
                        f"The p= value at {name} is not a valid RSA public key.",
                        "Re-publish the key exactly as your mail provider gave it to you.",
                    )
                )
            else:
                if key.bits < 1024:
                    findings.append(
                        Finding(
                            "DKIM-KEY-WEAK",
                            Severity.HIGH,
                            f"DKIM key for '{selector}' is only {key.bits} bits",
                            "Keys under 1024 bits can be factored and used to forge signatures.",
                            "Generate a 2048-bit key and rotate the selector.",
                        )
                    )
                elif key.bits < 2048:
                    findings.append(
                        Finding(
                            "DKIM-KEY-SHORT",
                            Severity.LOW,
                            f"DKIM key for '{selector}' is {key.bits} bits",
                            "1024-bit keys are still accepted but 2048 bits is the recommended size.",
                            "Rotate to a 2048-bit key when convenient.",
                        )
                    )

        if key.testing:
            findings.append(
                Finding(
                    "DKIM-TESTING",
                    Severity.LOW,
                    f"DKIM selector '{selector}' is in testing mode (t=y)",
                    "Some receivers treat testing-mode signatures as unsigned mail.",
                    "Remove t=y once you have confirmed signing works.",
                )
            )

    revoked = [k.selector for k in result.keys if k.revoked]
    if revoked:
        shown = ", ".join(revoked[:5]) + (
            f" and {len(revoked) - 5} more" if len(revoked) > 5 else ""
        )
        everything = len(revoked) == len(selectors)
        findings.append(
            Finding(
                "DKIM-REVOKED",
                Severity.INFO,
                f"{len(revoked)} DKIM selector{'s are' if len(revoked) != 1 else ' is'} revoked",
                (
                    "Every probed selector has an empty p= tag, which is typical of a wildcard "
                    "revocation used by domains that send no mail. "
                    if everything
                    else ""
                )
                + f"Revoked: {shown}.",
                "Nothing to do unless you still send mail with these selectors.",
            )
        )

    if not result.keys:
        findings.append(
            Finding(
                "DKIM-NOT-FOUND",
                Severity.INFO,
                "No DKIM key found among probed selectors"
                if len(selectors) != len(COMMON_SELECTORS)
                else "No DKIM key found among common selectors",
                f"Probed {probe_summary(selectors, 'selector names')}. DKIM selectors cannot be "
                "listed via DNS, so the domain may still use a custom selector.",
                "Re-run with --selector <name> using the selector from a real message header.",
            )
        )
    if errors:
        findings.append(
            Finding(
                "DKIM-DNS-ERROR",
                Severity.INFO,
                "Some DKIM lookups failed",
                f"{errors} of {len(selectors)} selector lookups failed, so results may be incomplete.",
                "Retry later.",
            )
        )
    return result
