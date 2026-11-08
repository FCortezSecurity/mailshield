from __future__ import annotations

import json

from mailshield.audit import AuditReport


def to_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_markdown(report: AuditReport) -> str:
    lines = [
        f"# Email authentication audit: {report.domain}",
        "",
        f"**Score:** {report.score}/100 (grade {report.grade})",
        "",
        f"- SPF record: `{report.spf.record or 'none'}` ({report.spf.lookups} DNS lookups)",
        f"- DMARC record: `{report.dmarc.record or 'none'}`",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    for f in report.findings:
        lines.append(f"### [{f.severity.label.upper()}] {f.title} (`{f.id}`)")
        lines.append("")
        lines.append(f.detail)
        if f.fix:
            lines.append("")
            lines.append(f"**Fix:** {f.fix}")
        lines.append("")
    return "\n".join(lines)
