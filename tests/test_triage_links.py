from conftest import make_message

from mailshield.triage.body import extract_bodies
from mailshield.triage.urls import analyze_urls, defang, extract_links, is_ip_host


def run(html=None, text=""):
    return analyze_urls(extract_bodies(make_message(html=html, text=text)))


def ids(result):
    return {f.id for f in result.findings}


def test_defang():
    assert defang("https://evil.example.com/a?b=1") == "hxxps://evil[.]example[.]com/a?b=1"
    assert defang("http://x.example.org") == "hxxp://x[.]example[.]org"
    assert defang("example.com") == "example[.]com"
    assert "\x1b" not in defang("https://a.example.com/\x1b[2J")


def test_is_ip_host():
    for host in ("198.51.100.9", "::1", "2130706433", "0x7f000001", "0x7f.0.0.1"):
        assert is_ip_host(host)
    for host in ("example.com", "mail.example.org"):
        assert not is_ip_host(host)


def test_anchor_text_mismatch():
    html = '<a href="https://evil.example.net/login">https://www.example.com/account</a>'
    assert "URL-TEXT-MISMATCH" in ids(run(html))


def test_matching_anchor_text_and_plain_labels_are_fine():
    html = (
        '<a href="https://www.example.com/account">example.com/account</a>'
        '<a href="https://mail.example.com/">Click here</a>'
        '<a href="https://files.example.org/x">invoice.pdf</a>'
    )
    assert run(html).findings == []


def test_ip_shortener_punycode_userinfo_form():
    html = (
        '<a href="http://198.51.100.9/login">go</a>'
        '<a href="https://bit.ly/abc">go</a>'
        '<a href="https://xn--exmple-cua.com/">go</a>'
        '<a href="https://www.example.com@evil.example.org/">go</a>'
        '<form action="https://collect.example.net/post"></form>'
    )
    assert {
        "URL-IP-HOST",
        "URL-SHORTENER",
        "URL-PUNYCODE",
        "URL-USERINFO",
        "URL-FORM",
    } <= ids(run(html))


def test_plain_text_urls_are_checked_too():
    assert "URL-SHORTENER" in ids(run(text="see https://tinyurl.com/xyz."))


def test_non_http_schemes_are_ignored():
    html = '<a href="mailto:a@example.com">mail</a><a href="javascript:alert(1)">x</a>'
    assert run(html).findings == [] and run(html).urls == []


def test_urls_in_report_are_defanged_and_never_fetched():
    result = run('<a href="https://bit.ly/abc">go</a>')
    assert result.urls == ["hxxps://bit[.]ly/abc"]
    assert "https://bit.ly" not in result.findings[0].detail


def test_many_links_are_capped_and_findings_aggregated():
    html = "".join(f'<a href="https://bit.ly/{i}">x</a>' for i in range(500))
    assert len(extract_links(extract_bodies(make_message(html=html)))) == 200
    result = run(html)
    assert len(result.findings) == 1 and "and 197 more" in result.findings[0].detail


def test_broken_html_does_not_crash():
    assert run('<a href="https://[bad"><<<>>><a href=')


def test_no_live_urls_anywhere_in_link_findings():
    from pathlib import Path

    from mailshield.triage.parser import read_eml
    from mailshield.triage.verdict import triage_message

    fixture = Path(__file__).parent / "fixtures" / "link_mismatch.eml"
    report = triage_message(read_eml(fixture))
    for finding in report.findings:
        assert "http://" not in finding.detail and "https://" not in finding.detail
    assert not any(f.detail.endswith(".") for f in report.findings if f.id.startswith("URL-"))
