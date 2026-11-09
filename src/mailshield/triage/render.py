from __future__ import annotations

import json
import re

from mailshield.triage.verdict import DISCLAIMER, TriageReport


def _md(text: object) -> str:
    return re.sub(r"([\\`*_{}\[\]<>#|])", r"\\\1", str(text))


def to_json(report: TriageReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(report: TriageReport) -> str:
    auth = report.facts.get("authentication", {})
    auth_text = ", ".join(f"{k}={v}" for k, v in auth.items()) or "not present"
    lines = [
        f"# Phishing triage: {_md(report.subject or '(no subject)')}",
        "",
        f"**Risk:** {report.risk}/100 ({report.verdict})",
        "",
        f"- From: {_md(report.sender or 'unknown')}",
        f"- Reply-To: {_md(', '.join(report.facts.get('reply_to', [])) or 'none')}",
        f"- Return-Path: {_md(report.facts.get('return_path') or 'none')}",
        f"- Authentication results: {_md(auth_text)}",
        f"- Received hops: {report.facts.get('received_hops', 0)}",
        f"- Links found: {len(report.facts.get('urls', []))}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    for f in report.findings:
        lines += [f"### [{f.severity.label.upper()}] {_md(f.title)} (`{f.id}`)", "", _md(f.detail)]
        if f.fix:
            lines += ["", f"**Next step:** {_md(f.fix)}"]
        lines.append("")
    attachments = report.facts.get("attachments", [])
    if attachments:
        lines += ["## Attachments", ""]
        for item in attachments:
            lines.append(f"- {_md(item['name'])} ({item['size']} bytes), sha256 `{item['sha256']}`")
        lines.append("")
    lines += ["---", "", f"_{DISCLAIMER}_", ""]
    return "\n".join(lines)
