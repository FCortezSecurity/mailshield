"""Extract text and HTML bodies. Attachments are skipped; nothing is rendered or executed."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage

MAX_BODY_CHARS = 1_000_000


@dataclass
class Body:
    text: str = ""
    html: str = ""


def extract_bodies(msg: EmailMessage) -> Body:
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        kind = part.get_content_type()
        if kind not in ("text/plain", "text/html"):
            continue
        try:
            content = str(part.get_content())
        except Exception:  # unknown charsets and broken encodings raise many error types
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "replace")
        (texts if kind == "text/plain" else htmls).append(content[:MAX_BODY_CHARS])
    return Body("\n".join(texts)[:MAX_BODY_CHARS], "\n".join(htmls)[:MAX_BODY_CHARS])
