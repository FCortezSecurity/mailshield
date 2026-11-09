import re
from datetime import datetime, timezone

from mailshield.audit import audit_domain
from mailshield.cli import main
from mailshield.report import to_html

WHEN = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)


def test_report_contains_the_essentials(make_resolver):
    report = audit_domain("example.com", make_resolver())
    page = to_html(report, generated_at=WHEN)
    assert "<title>Email security report: example.com</title>" in page
    assert f">{report.score}<" in page and f"g-{report.grade}" in page
    assert "SPF-MISSING" in page and "DMARC-MISSING" in page
    assert "2026-01-02 03:04 UTC" in page


def test_findings_are_sorted_most_severe_first(make_resolver):
    page = to_html(audit_domain("example.com", make_resolver()), generated_at=WHEN)
    assert page.index("DMARC-MISSING") < page.index("DKIM-NOT-FOUND")


def test_untrusted_dns_data_is_escaped(make_resolver):
    evil = "<script>alert(1)</script>"
    resolver = make_resolver(
        {
            "example.com": [f"v=spf1 {evil} -all"],
            "_dmarc.example.com": ['v=DMARC1; p=reject; rua=mailto:"><img src=x onerror=alert(1)>'],
        }
    )
    page = to_html(audit_domain("example.com", resolver), generated_at=WHEN)
    assert evil not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img" not in page


def test_page_is_self_contained_and_script_free(make_resolver):
    page = to_html(audit_domain("example.com", make_resolver()), generated_at=WHEN)
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    for forbidden in ("<script", "<link", "<img", "<iframe", "src=", "@import", "url("):
        assert forbidden not in page
    assert not re.search(r"<a\s", page)


def test_cli_writes_html_file(tmp_path, monkeypatch, make_resolver):
    import mailshield.cli as cli

    monkeypatch.setattr(cli, "DnsResolver", lambda timeout: make_resolver())
    out = tmp_path / "report.html"
    code = main(["audit", "example.com", "--no-fetch", "--format", "html", "-o", str(out)])
    assert code == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_cli_rejects_output_for_text_format(tmp_path, monkeypatch, make_resolver):
    import mailshield.cli as cli

    monkeypatch.setattr(cli, "DnsResolver", lambda timeout: make_resolver())
    code = main(["audit", "example.com", "--no-fetch", "-o", str(tmp_path / "x.txt")])
    assert code == 2
