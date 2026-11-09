"""Wording signals: payment-detail changes, closing wire requests, urgency and secrecy.

These patterns are deliberately conservative and always quote the phrase that matched so a
human can judge it. Legitimate finance mail can match, so a hit is a reason to verify, not
proof of fraud."""

from __future__ import annotations

import html as html_module
import re
from dataclasses import dataclass

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.body import Body

MAX_SCAN_CHARS = 20_000


@dataclass(frozen=True)
class Signal:
    id: str
    severity: Severity
    title: str
    explanation: str
    fix: str
    patterns: tuple[re.Pattern, ...]
    min_hits: int = 1


def _p(*regexes: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(r, re.IGNORECASE) for r in regexes)


# "wire" as money transfer, not as a verb ("wire me the photos").
_MONEY_WIRE = (
    r"(?:\bwire\s+(?:instructions|transfer|funds|details|information|payment)\b"
    r"|\b(?:the|a|this|your|our)\s+wire\b|\brouting\s+number\b|\baccount\s+number\b)"
)

SIGNALS = (
    Signal(
        "TXT-PAYMENT-CHANGE",
        Severity.HIGH,
        "Message asks to change payment or banking details",
        "Changing where money is sent is the core move of invoice and vendor fraud.",
        "Verify by phoning a number you already have on file, not one from this message.",
        _p(
            r"\b(?:updated?|updating|new|changed?|changing|revised)\s+(?:(?:our|my|the|your)\s+)?"
            r"(?:wire|bank|banking|payment|ach|remittance)\s+(?:instructions|details|information|account)",
            r"\bchange[ds]?\s+(?:of\s+)?(?:our|my|the)\s+(?:bank|banking|account|payment)",
            r"\bnew\s+account\s+(?:number|details|information)\b",
            r"\b(?:routing|aba)\s+(?:number|no\.?)\b.{0,100}\baccount\s+(?:number|no\.?)\b",
            r"\baccount\s+(?:number|no\.?)\b.{0,100}\b(?:routing|aba)\s+(?:number|no\.?)\b",
            r"\bplease\s+(?:update|change)\s+(?:your|the)\s+(?:vendor|payment|bank|remittance)",
        ),
    ),
    Signal(
        "TXT-CLOSING-WIRE",
        Severity.HIGH,
        "Message mixes a closing or escrow with wire details",
        "Fraudulent wire instructions sent just before a property closing are a leading "
        "real estate scam.",
        "Confirm wire instructions by phone with the title or escrow company directly.",
        _p(
            r"\b(?:escrow|closing|title\s+company|settlement)\b.{0,80}" + _MONEY_WIRE,
            _MONEY_WIRE + r".{0,80}\b(?:escrow|closing|title\s+company|settlement)\b",
        ),
    ),
    Signal(
        "TXT-GIFT-CARD",
        Severity.HIGH,
        "Message asks for gift cards",
        "Requests to buy gift cards are a hallmark of impersonation scams.",
        "Do not buy anything. Verify with the supposed sender in person or by phone.",
        _p(r"\bgift\s*cards?\b", r"\b(?:itunes|google\s+play|steam|amazon)\s+cards?\b"),
    ),
    Signal(
        "TXT-CREDENTIAL-LURE",
        Severity.MEDIUM,
        "Message pressures you to verify or sign in to an account",
        "Account-warning wording is the usual bait for fake login pages.",
        "Open the service from a bookmark instead of this message.",
        _p(
            r"\bverify\s+your\s+(?:account|password|identity|email)\b",
            r"\bpassword\s+(?:will\s+)?(?:expire|expires|expired)\b",
            r"\byour\s+account\s+(?:has\s+been|will\s+be|is)\s+(?:suspended|locked|disabled|limited)\b",
            r"\bunusual\s+(?:sign-?in|activity|login)\b",
            r"\bre-?activate\s+your\b",
        ),
    ),
    Signal(
        "TXT-URGENCY-SECRECY",
        Severity.MEDIUM,
        "Message combines urgency with pressure or secrecy",
        "Pushing for speed and silence keeps victims from checking with anyone.",
        "Slow down and verify through another channel before acting.",
        _p(
            r"\burgent(?:ly)?\b",
            r"\bimmediately\b",
            r"\b(?:asap|right\s+away)\b",
            r"\bbefore\s+(?:the\s+)?(?:end\s+of\s+(?:the\s+)?(?:day|business)|close\s+of\s+business|cob|eod)\b",
            r"\b(?:confidential|keep\s+this\s+(?:between\s+us|private|quiet)|do\s+not\s+(?:tell|share|discuss))\b",
            r"\b(?:in\s+a\s+meeting|can'?t\s+(?:talk|take\s+calls?|call)|unable\s+to\s+(?:talk|call))\b",
            r"\bdon'?t\s+call\b",
        ),
        min_hits=2,
    ),
)


def _plain_text(body: Body) -> str:
    html_text = html_module.unescape(re.sub(r"<[^>]*>", " ", body.html[: MAX_SCAN_CHARS * 5]))
    return f"{body.text}\n{html_text}"


def analyze_content(subject: str, body: Body) -> list[Finding]:
    text = f"{subject}\n{_plain_text(body)}"[:MAX_SCAN_CHARS]
    text = " ".join(text.replace("\u2019", "'").split())
    findings: list[Finding] = []
    for signal in SIGNALS:
        hits: list[str] = []
        for pattern in signal.patterns:
            match = pattern.search(text)
            if match:
                snippet = match.group(0)
                if len(snippet) > 60:  # keep proximity matches readable
                    snippet = f"{snippet[:28]} ... {snippet[-28:]}"
                hits.append(clean(snippet, 80))
        if len(hits) >= signal.min_hits:
            quoted = "; ".join(f"'{h}'" for h in hits[:3])
            findings.append(
                Finding(
                    signal.id,
                    signal.severity,
                    signal.title,
                    f"{signal.explanation} Matched: {quoted}.",
                    signal.fix,
                )
            )
    return findings
