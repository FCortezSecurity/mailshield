from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from mailshield import __version__
from mailshield.audit import AuditReport, audit_domain
from mailshield.dns_auth.resolver import DnsResolver
from mailshield.fetch import HttpsPolicyFetcher
from mailshield.models import Severity
from mailshield.report import to_html, to_json, to_markdown
from mailshield.report.render import dkim_summary, mta_sts_summary, tls_rpt_summary

COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _print_text(report: AuditReport) -> None:
    console = Console()
    console.print(f"[bold]{report.domain}[/bold]  score {report.score}/100  grade {report.grade}")
    console.print(f"SPF:   {report.spf.record or 'none'} ({report.spf.lookups} lookups)")
    console.print(f"DMARC: {report.dmarc.record or 'none'}")
    console.print(f"DKIM:  {dkim_summary(report)}")
    console.print(f"MTA-STS: {mta_sts_summary(report)}")
    console.print(f"TLS-RPT: {tls_rpt_summary(report)}\n")
    if not report.findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(show_lines=True)
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Fix")
    for f in report.findings:
        table.add_row(
            f"[{COLORS[f.severity]}]{f.severity.label}[/]",
            f"{f.title}\n[dim]{f.detail}[/dim]",
            f.fix,
        )
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mailshield", description="Email security toolkit")
    parser.add_argument("--version", action="version", version=f"mailshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit a domain's SPF and DMARC records")
    audit.add_argument("domain")
    audit.add_argument("--format", choices=["text", "json", "markdown", "html"], default="text")
    audit.add_argument(
        "-o",
        "--output",
        help="write the report to this file instead of printing it (not for --format text)",
    )
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        fetcher = None if args.no_fetch else HttpsPolicyFetcher(timeout=args.timeout)
        report = audit_domain(
            args.domain, DnsResolver(timeout=args.timeout), args.selector, fetcher
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    renderers = {"json": to_json, "markdown": to_markdown, "html": to_html}
    if args.format == "text":
        if args.output:
            print("error: --output needs --format json, markdown or html", file=sys.stderr)
            return 2
        _print_text(report)
    else:
        content = renderers[args.format](report)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"wrote {args.output}", file=sys.stderr)
        else:
            print(content)
    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in report.findings):
            return 1
    return 0
