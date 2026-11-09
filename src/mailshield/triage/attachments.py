"""Attachment inspection. Attachments are decoded to bytes only to hash them and look at
the first bytes. They are never written to disk, opened, or executed."""

from __future__ import annotations

import hashlib
from email.message import EmailMessage

from mailshield.models import Finding, Severity
from mailshield.textutil import clean

MAX_HASH_BYTES = 25 * 1024 * 1024
DANGEROUS = {
    "exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "hta", "msi", "jar", "lnk", "iso", "img", "dll", "cpl", "reg", "chm", "pif",
}  # fmt: skip
MACRO_OFFICE = {"docm", "xlsm", "pptm", "dotm", "xlam", "xltm", "ppsm"}
ARCHIVES = {"zip", "rar", "7z", "gz", "tar", "cab", "ace", "z"}
HTMLISH = {"html", "htm", "shtml", "svg", "xhtml"}
DOC_LIKE = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt"}
NATIVE_EXECUTABLE = {"exe", "dll", "scr", "com", "sys", "cpl", "ocx", "so", "elf", "bin", "out"}
HIDDEN_CHARS = ("\u202e", "\u202d", "\u2066", "\u2067", "\u200b")

_RULES = (
    ("ATT-DOUBLE-EXTENSION", Severity.HIGH, "Attachment has a double extension",
     "A document-style name hides an executable extension.",
     "Do not open it."),
    ("ATT-HIDDEN-CHARACTERS", Severity.HIGH, "Attachment name contains hidden or reversing characters",
     "Characters such as right-to-left override can make a program look like a document.",
     "Do not open it."),
    ("ATT-DISGUISED-EXECUTABLE", Severity.HIGH, "Attachment content is a program but the name says otherwise",
     "The file starts with executable-program bytes but its extension is not an executable type.",
     "Do not open it."),
    ("ATT-DANGEROUS-TYPE", Severity.HIGH, "Attachment is an executable or script type",
     "Programs and scripts are the most direct way to run attacker code.",
     "Do not open it. Ask the sender through another channel if it is expected."),
    ("ATT-MACRO-DOCUMENT", Severity.MEDIUM, "Attachment is a macro-enabled Office document",
     "Macros can run code when the document is opened and enabled.",
     "Do not enable macros. Confirm with the sender first."),
    ("ATT-HTML", Severity.MEDIUM, "Attachment is an HTML or SVG file",
     "Local HTML files are used to show fake login pages that bypass link scanners.",
     "Do not open it in a browser."),
    ("ATT-ARCHIVE", Severity.LOW, "Attachment is an archive",
     "Archives, especially password-protected ones, are used to slip past scanners.",
     "Be cautious with anything inside, and verify the sender."),
)  # fmt: skip


def _extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].strip().lower() if "." in name else ""


def inspect_attachments(msg: EmailMessage) -> tuple[list[Finding], list[dict]]:
    buckets: dict[str, list[str]] = {rule[0]: [] for rule in _RULES}
    facts: list[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            raw_name = part.get_filename() or ""
        except Exception:  # malformed RFC 2231 parameters
            raw_name = ""
        if part.get_content_disposition() != "attachment" and not raw_name:
            continue
        payload = part.get_payload(decode=True)
        data = payload if isinstance(payload, bytes) else b""
        name = clean(raw_name or "(unnamed)", 120)
        ext = _extension(raw_name)
        pieces = [p.strip().lower() for p in raw_name.split(".")]

        if len(pieces) >= 3 and pieces[-2] in DOC_LIKE and pieces[-1] in DANGEROUS | MACRO_OFFICE:
            buckets["ATT-DOUBLE-EXTENSION"].append(name)
        if any(ch in raw_name for ch in HIDDEN_CHARS):
            buckets["ATT-HIDDEN-CHARACTERS"].append(name)
        if (len(data) >= 64 and data[:2] == b"MZ" or data[:4] == b"\x7fELF") and (
            ext not in NATIVE_EXECUTABLE
        ):
            buckets["ATT-DISGUISED-EXECUTABLE"].append(name)
        if ext in DANGEROUS:
            buckets["ATT-DANGEROUS-TYPE"].append(name)
        elif ext in MACRO_OFFICE:
            buckets["ATT-MACRO-DOCUMENT"].append(name)
        elif ext in HTMLISH:
            buckets["ATT-HTML"].append(name)
        elif ext in ARCHIVES:
            buckets["ATT-ARCHIVE"].append(name)

        facts.append(
            {
                "name": name,
                "content_type": clean(part.get_content_type(), 80),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest() if len(data) <= MAX_HASH_BYTES else None,
            }
        )

    findings = []
    for fid, severity, title, detail, fix in _RULES:
        names = list(dict.fromkeys(buckets[fid]))
        if names:
            more = f" and {len(names) - 3} more" if len(names) > 3 else ""
            findings.append(
                Finding(fid, severity, title, f"{detail} Files: {', '.join(names[:3])}{more}.", fix)
            )
    return findings, facts[:50]
