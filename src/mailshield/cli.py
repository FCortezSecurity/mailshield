from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mailshield import __version__
from mailshield.audit import AuditReport, audit_domain
from mailshield.dns_auth.resolver import DnsResolver
from mailshield.fetch import HttpsPolicyFetcher
from mailshield.models import Severity
from mailshield.report import to_html, to_json, to_markdown
from mailshield.report.render import dkim_summary, mta_sts_summary, tls_rpt_summary
from mailshield.textutil import clean
from mailshield.triage import render as triage_render
from mailshield.triage.parser import read_eml
from mailshield.triage.verdict import DISCLAIMER, TriageReport, triage_message

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
VERDICT_COLORS = {"likely phishing": "bold red", "suspicious": "yellow"}


def _t(value: object) -> str:
    """Make untrusted text safe for Rich: strip control characters, neutralize markup."""
    return escape(clean(value))


def _findings_table(findings, fix_header: str = "Fix") -> Table:
    table = Table(show_lines=True)
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column(fix_header)
    for f in findings:
        table.add_row(
            f"[{COLORS[f.severity]}]{f.severity.label}[/]",
            f"{_t(f.title)}\n[dim]{_t(f.detail)}[/dim]",
            _t(f.fix),
        )
    return table


def _print_text(report: AuditReport) -> None:
    console = Console()
    console.print(
        f"[bold]{_t(report.domain)}[/bold]  score {report.score}/100  grade {report.grade}"
    )
    console.print(f"SPF:   {_t(report.spf.record or 'none')} ({report.spf.lookups} lookups)")
    console.print(f"DMARC: {_t(report.dmarc.record or 'none')}")
    console.print(f"DKIM:  {_t(dkim_summary(report))}")
    console.print(f"MTA-STS: {_t(mta_sts_summary(report))}")
    console.print(f"TLS-RPT: {_t(tls_rpt_summary(report))}\n")
    if not report.findings:
        console.print("[green]No findings.[/green]")
        return
    console.print(_findings_table(report.findings))


def _print_triage_text(report: TriageReport) -> None:
    console = Console()
    color = VERDICT_COLORS.get(report.verdict, "green")
    console.print(f"[bold]{_t(report.subject or '(no subject)')}[/bold]")
    console.print(f"From:     {_t(report.sender or 'unknown')}")
    console.print(f"Reply-To: {_t(', '.join(report.facts['reply_to']) or 'none')}")
    auth = ", ".join(f"{k}={v}" for k, v in report.facts["authentication"].items())
    console.print(f"Auth:     {_t(auth or 'not present')}")
    console.print(f"Links:    {len(report.facts.get('urls', []))}")
    for item in report.facts.get("attachments", []):
        console.print(
            f"Attachment: {_t(item['name'])} ({item['size']} bytes) sha256={_t(item['sha256'])}"
        )
    console.print(f"Risk {report.risk}/100: [{color}]{_t(report.verdict)}[/]\n")
    if report.findings:
        console.print(_findings_table(report.findings, "Next step"))
    else:
        console.print("[green]No findings.[/green]")
    console.print(f"\n[dim]{_t(DISCLAIMER)}[/dim]")


def _output(args, report, renderers: dict[str, Callable], print_text: Callable) -> int:
    if args.format == "text":
        if args.output:
            print("error: --output needs --format json, markdown or html", file=sys.stderr)
            return 2
        print_text(report)
        return 0
    content = renderers[args.format](report)
    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(content)
    return 0


def _add_output_options(parser: argparse.ArgumentParser, formats: list[str]) -> None:
    parser.add_argument("--format", choices=formats, default="text")
    parser.add_argument(
        "-o",
        "--output",
        help="write the report to this file instead of printing it (not for --format text)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mailshield", description="Email security toolkit")
    parser.add_argument("--version", action="version", version=f"mailshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser(
        "audit", help="audit a domain's email authentication and transport security"
    )
    audit.add_argument("domain")
    _add_output_options(audit, ["text", "json", "markdown", "html"])
    audit.add_argument(
        "--selector",
        action="append",
        default=[],
        help="extra DKIM selector to probe (repeatable)",
    )
    audit.add_argument(
        "--no-fetch",
        action="store_true",
        help="do not download the MTA-STS policy file (DNS lookups only)",
    )
    audit.add_argument(
        "--timeout", type=float, default=5.0, help="DNS and HTTPS timeout in seconds"
    )
    audit.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit with code 1 if any finding is at or above this severity",
    )

    triage = sub.add_parser(
        "triage",
        help="analyze a suspicious .eml file offline (no network; attachments and links are never opened)",
    )
    triage.add_argument("file", help="path to an .eml file")
    _add_output_options(triage, ["text", "json", "markdown"])
    triage.add_argument(
        "--protected-name",
        action="append",
        default=[],
        help="name of a person who is likely to be impersonated, e.g. an executive (repeatable)",
    )
    triage.add_argument(
        "--trusted-domain",
        action="append",
        default=[],
        help="one of your own legitimate domains; used for impersonation and look-alike checks (repeatable)",
    )
    return parser


def _cmd_audit(args) -> int:
    try:
        fetcher = None if args.no_fetch else HttpsPolicyFetcher(timeout=args.timeout)
        report = audit_domain(
            args.domain, DnsResolver(timeout=args.timeout), args.selector, fetcher
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    renderers = {"json": to_json, "markdown": to_markdown, "html": to_html}
    code = _output(args, report, renderers, _print_text)
    if code:
        return code
    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in report.findings):
            return 1
    return 0


def _cmd_triage(args) -> int:
    try:
        message = read_eml(args.file)
        report = triage_message(message, args.protected_name, args.trusted_domain)
    except ValueError as exc:  # includes EmlError
        print(f"error: {exc}", file=sys.stderr)
        return 2
    renderers = {"json": triage_render.to_json, "markdown": triage_render.to_markdown}
    return _output(args, report, renderers, _print_triage_text)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        return _cmd_audit(args)
    return _cmd_triage(args)
