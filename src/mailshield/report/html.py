"""Self-contained HTML report.

Everything that came from DNS or from a remote policy file is untrusted, so every
dynamic value is HTML-escaped. The page has no scripts and loads no external
resources, and a Content-Security-Policy meta tag enforces that.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from mailshield import __version__
from mailshield.audit import AuditReport
from mailshield.models import Finding, Severity
from mailshield.report.render import dkim_summary, mta_sts_summary, tls_rpt_summary

_CSS = """
:root{--bg:#f4f6f8;--card:#fff;--text:#1b1f24;--muted:#5b6672;--border:#dde2e8;
--critical:#b42318;--high:#d92d20;--medium:#b54708;--low:#175cd3;--info:#667085;--ok:#067647}
@media (prefers-color-scheme: dark){:root{--bg:#0f1318;--card:#171c23;--text:#e6e9ee;
--muted:#9aa5b1;--border:#2a323c;--critical:#ff7b72;--high:#ff8a80;--medium:#f5a65b;
--low:#7aa7ff;--info:#98a2b3;--ok:#47c98a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 20px 48px}
h1{font-size:1.4rem;margin:0 0 4px;word-break:break-all}
h2{font-size:1.05rem;margin:32px 0 12px}
.muted{color:var(--muted);font-size:.9rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px 20px}
.top{display:flex;gap:20px;align-items:center;flex-wrap:wrap;margin-top:16px}
.score{font-size:3rem;font-weight:700;line-height:1}
.grade{display:inline-block;min-width:2.2rem;text-align:center;border-radius:8px;
padding:2px 10px;font-weight:700;font-size:1.4rem;color:#fff}
.g-A,.g-B{background:#067647}.g-C{background:#b54708}.g-D{background:#c4320a}.g-F{background:#b42318}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{border:1px solid var(--border);border-radius:999px;padding:2px 10px;font-size:.85rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.v{word-break:break-all;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
.badge{display:inline-block;border-radius:6px;padding:1px 8px;font-size:.75rem;font-weight:700;
text-transform:uppercase;letter-spacing:.03em;border:1px solid currentColor}
.s-critical{color:var(--critical)}.s-high{color:var(--high)}.s-medium{color:var(--medium)}
.s-low{color:var(--low)}.s-info{color:var(--info)}.s-ok{color:var(--ok)}
.finding{border-left:5px solid currentColor;margin-bottom:12px}
.finding h3{margin:6px 0 4px;font-size:1rem;color:var(--text)}
.finding p{margin:4px 0;color:var(--text)}
.finding .fix{color:var(--muted)}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;color:var(--muted)}
footer{margin-top:32px}
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _status(findings: list[Finding]) -> tuple[str, str]:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst < Severity.LOW:
        return "ok", "ok"
    return worst.label, worst.label


def _check_rows(report: AuditReport) -> str:
    spf = report.spf.record or "none"
    if report.spf.record:
        spf += f"  ({report.spf.lookups} DNS lookups)"
    rows = [
        ("SPF", spf, report.spf.findings),
        ("DMARC", report.dmarc.record or "none", report.dmarc.findings),
        ("DKIM", dkim_summary(report), report.dkim.findings),
        ("MTA-STS", mta_sts_summary(report), report.mta_sts.findings),
        ("TLS-RPT", tls_rpt_summary(report), report.tls_rpt.findings),
    ]
    out = []
    for name, value, findings in rows:
        css, label = _status(findings)
        out.append(
            f'<tr><td>{_esc(name)}</td><td class="v">{_esc(value)}</td>'
            f'<td><span class="badge s-{css}">{_esc(label)}</span></td></tr>'
        )
    return "\n".join(out)


def _finding_card(f: Finding) -> str:
    fix = f'<p class="fix"><strong>Fix:</strong> {_esc(f.fix)}</p>' if f.fix else ""
    return (
        f'<div class="card finding s-{f.severity.label}">'
        f'<span class="badge">{_esc(f.severity.label)}</span> <code>{_esc(f.id)}</code>'
        f"<h3>{_esc(f.title)}</h3><p>{_esc(f.detail)}</p>{fix}</div>"
    )


def to_html(report: AuditReport, generated_at: datetime | None = None) -> str:
    stamp = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    findings = report.findings
    chips = "".join(
        f'<span class="chip s-{sev.label}">{sum(f.severity == sev for f in findings)} '
        f"{_esc(sev.label)}</span>"
        for sev in sorted(Severity, reverse=True)
        if any(f.severity == sev for f in findings)
    )
    cards = "\n".join(_finding_card(f) for f in findings) or (
        '<div class="card">No findings.</div>'
    )
    note = (
        '<p class="muted">This domain publishes a deliberate no-mail policy, so '
        "reporting and DKIM checks were skipped.</p>"
        if report.null_sender
        else ""
    )
    domain = _esc(report.domain)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Email security report: {domain}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>{domain}</h1>
<div class="muted">Email authentication and transport security report</div>
<div class="card top">
<div><div class="score">{report.score}<span class="muted">/100</span></div></div>
<div><span class="grade g-{_esc(report.grade)}">{_esc(report.grade)}</span></div>
<div class="chips">{chips or '<span class="chip s-ok">no findings</span>'}</div>
</div>
{note}
<h2>Checks</h2>
<div class="card"><table>
<tr><th>Check</th><th>Result</th><th>Status</th></tr>
{_check_rows(report)}
</table></div>
<h2>Findings</h2>
{cards}
<footer class="muted">Generated by mailshield {_esc(__version__)} on {_esc(stamp)}.
Based on DNS records and the MTA-STS policy file only; it does not test mail delivery.</footer>
</main>
</body>
</html>
"""
