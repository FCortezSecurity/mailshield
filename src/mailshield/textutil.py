"""Helpers for handling untrusted text (DNS records, email headers, remote files)."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Bidi overrides and zero-width characters can reverse or hide text, so show them escaped.
_HIDDEN = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


def clean(value: object, limit: int | None = None) -> str:
    """Replace control characters (including terminal escape sequences) and truncate.

    Untrusted text must be cleaned before it is shown in a terminal, otherwise it can
    clear the screen, retitle the window or hide other output.
    """
    text = _CONTROL.sub(" ", str(value))
    text = _HIDDEN.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
    if limit is not None and len(text) > limit:
        text = text[: limit - 3] + "..."
    return text
