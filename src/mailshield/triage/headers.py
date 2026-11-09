"""Header-level phishing indicators. Pure analysis of one parsed message; no network."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.domains import domain_of, org_domain, same_org

FREEMAIL = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "mail.com",
    "yandex.com",
}
KNOWN_TLDS = {"com", "net", "org", "gov", "edu", "io", "co", "info", "biz", "us", "mx", "uk", "de"}

_EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_DOMAIN_IN_TEXT = re.compile(
    r"\b((?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(KNOWN_TLDS)) + r"))\b", re.IGNORECASE
)
_AR_RE = re.compile(r"(?<![\w.-])(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
CLOCK_TOLERANCE = timedelta(minutes=5)
DATE_SKEW = timedelta(days=2)

_AUTH_SEVERITY = {
    "spf": {"fail": Severity.HIGH, "softfail": Severity.MEDIUM},
    "dkim": {"fail": Severity.HIGH},
    "dmarc": {"fail": Severity.HIGH},
}
_AUTH_DEFAULT = Severity.LOW  # none, neutral, permerror, temperror, policy
_AUTH_MEANING = {
    "spf": "the sending server is not authorized by the envelope domain's SPF policy",
    "dkim": "the message has no valid DKIM signature",
    "dmarc": "the message did not pass DMARC alignment for the From domain",
}


def _addresses(msg: EmailMessage, name: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for raw in msg.get_all(name, []):
        for display, addr in getaddresses([str(raw)]):
            if addr:
                found.append((display.strip(), addr.strip()))
    return found


def _normalize_name(name: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9 ]+", " ", name.lower()).split())


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    """Parse the topmost Authentication-Results header (written by the receiving server)."""
    results: dict[str, str] = {}
    headers = msg.get_all("Authentication-Results", [])
    if headers:
        for method, result in _AR_RE.findall(str(headers[0])):
            results.setdefault(method.lower(), result.lower())
    received_spf = str(msg.get("Received-SPF", "")).strip()
    if "spf" not in results and received_spf:
        token = received_spf.split()[0].lower()
        if token.isalpha():
            results["spf"] = token
    return results


def _received_times(msg: EmailMessage) -> list[datetime]:
    times: list[datetime] = []
    for raw in msg.get_all("Received", []):
        stamp = str(raw).rpartition(";")[2].strip()
        try:
            moment = parsedate_to_datetime(stamp)
        except (TypeError, ValueError, IndexError):
            continue
        times.append(moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc))
    return times


def analyze_headers(
    msg: EmailMessage,
    protected_names: Sequence[str] = (),
    trusted_domains: Sequence[str] = (),
) -> tuple[list[Finding], dict]:
    if protected_names and not trusted_domains:
        raise ValueError("--protected-name needs at least one --trusted-domain")

    findings: list[Finding] = []
    add = findings.append
    from_addrs = _addresses(msg, "From")
    reply_to = _addresses(msg, "Reply-To")
    return_path = _addresses(msg, "Return-Path")
    auth = _auth_results(msg)
    received = msg.get_all("Received", [])

    # --- From ---------------------------------------------------------------------
    if len(msg.get_all("From", [])) > 1:
        add(
            Finding(
                "HDR-MULTIPLE-FROM",
                Severity.HIGH,
                "Message has more than one From header",
                "RFC 5322 allows exactly one From header. Duplicates are a known trick to make "
                "different software display and validate different senders.",
                "Treat the message as malicious unless you can explain the duplicate.",
            )
        )
    sender_display, sender_addr = from_addrs[0] if from_addrs else ("", "")
    sender_domain = domain_of(sender_addr)
    if not sender_addr:
        add(
            Finding(
                "HDR-NO-FROM",
                Severity.MEDIUM,
                "Message has no usable From address",
                "Legitimate mail always has a From address.",
                "Treat the sender as unknown.",
            )
        )

    # --- Reply-To -----------------------------------------------------------------
    for _, addr in reply_to[:1]:
        reply_domain = domain_of(addr)
        if sender_domain and reply_domain and not same_org(sender_domain, reply_domain):
            freemail = (
                org_domain(reply_domain) in FREEMAIL and org_domain(sender_domain) not in FREEMAIL
            )
            add(
                Finding(
                    "HDR-REPLYTO-FREEMAIL" if freemail else "HDR-REPLYTO-MISMATCH",
                    Severity.HIGH if freemail else Severity.MEDIUM,
                    "Replies go to a free mailbox instead of the sender's domain"
                    if freemail
                    else "Reply-To domain differs from the From domain",
                    f"From is {clean(sender_domain, 100)} but replies go to "
                    f"{clean(addr, 100)}. Redirecting replies is how business email compromise "
                    "keeps the victim talking to the attacker.",
                    "Confirm the request through a channel you already trust, not by replying.",
                )
            )

    # --- Return-Path (envelope sender) ---------------------------------------------
    if return_path and sender_domain:
        rp_domain = domain_of(return_path[0][1])
        if rp_domain and not same_org(sender_domain, rp_domain):
            add(
                Finding(
                    "HDR-RETURNPATH-MISMATCH",
                    Severity.LOW,
                    "Envelope sender domain differs from the From domain",
                    f"Return-Path is {clean(rp_domain, 100)} while From is "
                    f"{clean(sender_domain, 100)}. Mail services do this legitimately, so it is "
                    "a weak signal on its own.",
                    "Weigh it together with the authentication results.",
                )
            )

    # --- Authentication results ----------------------------------------------------
    if not auth:
        add(
            Finding(
                "HDR-NO-AUTH-RESULTS",
                Severity.INFO,
                "No authentication results in the headers",
                "No Authentication-Results or Received-SPF header was found, so SPF, DKIM and "
                "DMARC outcomes are unknown. Saved or forwarded copies often lose them.",
                "If possible, re-export the message from the receiving mailbox with full headers.",
            )
        )
    for method in ("spf", "dkim", "dmarc"):
        result = auth.get(method)
        if result is None or result == "pass":
            continue
        severity = _AUTH_SEVERITY[method].get(result, _AUTH_DEFAULT)
        add(
            Finding(
                f"HDR-{method.upper()}-{result.upper()}",
                severity,
                f"{method.upper()} result: {result}",
                f"The receiving server recorded {method}={result}: {_AUTH_MEANING[method]}. "
                "This header is written by the receiving server and cannot be verified here.",
                "Do not trust the sender's identity.",
            )
        )

    # --- Received chain and dates --------------------------------------------------
    if not received:
        add(
            Finding(
                "HDR-NO-RECEIVED",
                Severity.LOW,
                "No Received headers",
                "Delivered mail always carries at least one Received header. This may be a "
                "hand-built message or a copy with trimmed headers.",
                "Re-export the original message with full headers if you can.",
            )
        )
    times = _received_times(msg)
    backwards = [i for i in range(len(times) - 1) if times[i] < times[i + 1] - CLOCK_TOLERANCE]
    if backwards:
        add(
            Finding(
                "HDR-RECEIVED-TIME-ANOMALY",
                Severity.MEDIUM,
                "Received timestamps are out of order",
                "A later hop is stamped earlier than the hop before it by more than five "
                "minutes. Forged or injected Received headers often look like this.",
                "Treat the lower Received headers as unreliable.",
            )
        )
    if times and msg.get("Date"):
        try:
            sent = parsedate_to_datetime(str(msg["Date"]))
            sent = sent if sent.tzinfo else sent.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            sent = None
        if sent is not None and abs(sent - times[-1]) > DATE_SKEW:
            add(
                Finding(
                    "HDR-DATE-SKEW",
                    Severity.LOW,
                    "Date header is far from the first Received timestamp",
                    "The claimed send date differs from the first server timestamp by more "
                    "than two days.",
                    "Check whether the message was backdated or replayed.",
                )
            )

    # --- Display-name spoofing -----------------------------------------------------
    if sender_display and sender_domain:
        embedded = _EMAIL_IN_TEXT.search(sender_display)
        if embedded and not same_org(embedded.group(1), sender_domain):
            add(
                Finding(
                    "HDR-DISPLAYNAME-EMAIL",
                    Severity.HIGH,
                    "Display name contains a different email address",
                    f"The name shows '{clean(sender_display, 100)}' but the real sender is "
                    f"{clean(sender_addr, 100)}. Many mail apps show only the display name.",
                    "Look at the actual address, not the name.",
                )
            )
        else:
            stripped = _EMAIL_IN_TEXT.sub(" ", sender_display)
            named = _DOMAIN_IN_TEXT.search(stripped)
            if named and not same_org(named.group(1), sender_domain):
                add(
                    Finding(
                        "HDR-DISPLAYNAME-DOMAIN",
                        Severity.MEDIUM,
                        "Display name mentions a different domain",
                        f"The name shows '{clean(sender_display, 100)}' but the real sender "
                        f"domain is {clean(sender_domain, 100)}.",
                        "Look at the actual address, not the name.",
                    )
                )

    # --- Impersonation of protected people ------------------------------------------
    trusted = {org_domain(d.lower()) for d in trusted_domains}
    normalized_display = _normalize_name(sender_display)
    for name in protected_names:
        wanted = _normalize_name(name)
        if wanted and wanted in normalized_display and org_domain(sender_domain) not in trusted:
            add(
                Finding(
                    "HDR-IMPERSONATION",
                    Severity.HIGH,
                    f"Sender uses the name of {clean(name, 60)} from an untrusted domain",
                    f"The display name matches a protected person but the mail comes from "
                    f"{clean(sender_domain or 'an unknown domain', 100)}, which is not one of "
                    "your trusted domains. Executive impersonation is the usual opening of "
                    "wire-fraud attempts.",
                    "Verify the request with the real person by phone or in person.",
                )
            )
            break

    facts = {
        "from": [clean(f"{d} <{a}>".strip(), 200) for d, a in from_addrs],
        "reply_to": [clean(a, 200) for _, a in reply_to],
        "return_path": clean(return_path[0][1], 200) if return_path else None,
        "authentication": auth,
        "received_hops": len(received),
    }
    return findings, facts
