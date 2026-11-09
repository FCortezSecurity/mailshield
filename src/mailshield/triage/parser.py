"""Safe .eml loading. Nothing here opens attachments or follows links."""

from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

MAX_EML_BYTES = 10 * 1024 * 1024


class EmlError(ValueError):
    """The file could not be read as an email message."""


def parse_eml(data: bytes) -> EmailMessage:
    if len(data) > MAX_EML_BYTES:
        raise EmlError(f"file is larger than {MAX_EML_BYTES // (1024 * 1024)} MB")
    if not data.strip():
        raise EmlError("file is empty")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # the stdlib parser can raise many types on hostile input
        raise EmlError(f"could not parse message ({exc.__class__.__name__})") from exc
    if not msg.keys():
        raise EmlError("no email headers found; is this an .eml file?")
    return msg  # type: ignore[return-value]


def read_eml(path: str | Path) -> EmailMessage:
    target = Path(path)
    try:
        size = target.stat().st_size
        if size > MAX_EML_BYTES:
            raise EmlError(f"file is larger than {MAX_EML_BYTES // (1024 * 1024)} MB")
        data = target.read_bytes()
    except OSError as exc:
        raise EmlError(f"cannot read {path}: {exc.strerror or exc.__class__.__name__}") from exc
    return parse_eml(data)
