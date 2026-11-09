"""Helpers for handling untrusted text (DNS records, email headers, remote files)."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(value: object, limit: int | None = None) -> str:
    """Replace control characters (including terminal escape sequences) and truncate.

    Untrusted text must be cleaned before it is shown in a terminal, otherwise it can
    clear the screen, retitle the window or hide other output.
    """
    text = _CONTROL.sub(" ", str(value))
    if limit is not None and len(text) > limit:
        text = text[: limit - 3] + "..."
    return text
