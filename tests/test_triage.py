import json
from pathlib import Path

import pytest

from mailshield.cli import main
from mailshield.triage import parser as parser_module
from mailshield.triage.domains import domain_of, org_domain, same_org
from mailshield.triage.headers import analyze_headers
from mailshield.triage.parser import EmlError, parse_eml, read_eml
from mailshield.triage.verdict import risk_score, triage_message, verdict_for

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_ids(name, **kwargs):
    report = triage_message(read_eml(FIXTURES / name), **kwargs)
    return report, {f.id for f in report.findings}


def build(headers: str) -> object:
    return parse_eml((headers.strip("\n") + "\n\nbody\n").encode())


# --- domains ------------------------------------------------------------------------
def test_org_domain_and_alignment():
    assert org_domain("mail.example.com") == "example.com"
    assert org_domain("a.b.example.co.uk") == "example.co.uk"
    assert org_domain("shop.example.com.mx") == "example.com.mx"
    assert same_org("mail.example.com", "example.com")
    assert not same_org("example.com", "example.org")
    assert not same_org("", "example.com")
    assert domain_of("<bounce@Mail.Example.com>") == "mail.example.com"


# --- parser -------------------------------------------------------------------------
def test_parser_rejects_bad_input(tmp_path, monkeypatch):
    for data in (b"", b"   \n", b"just some text without headers"):
        with pytest.raises(EmlError):
            parse_eml(data)
    with pytest.raises(EmlError, match="cannot read"):
        read_eml(tmp_path / "missing.eml")
    monkeypatch.setattr(parser_module, "MAX_EML_BYTES", 10)
    with pytest.raises(EmlError, match="larger"):
        parse_eml(b"Subject: hello world, this is long\n\nbody")


# --- fixtures -----------------------------------------------------------------------
def test_legit_newsletter_has_no_findings():
    report, found = fixture_ids("legit_newsletter.eml")
    assert found == set()
    assert report.verdict == "no strong indicators" and report.risk == 0
    assert report.facts["authentication"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_ceo_fraud_fixture():
    report, found = fixture_ids("ceo_fraud.eml")
    assert {"HDR-SPF-FAIL", "HDR-DKIM-NONE", "HDR-DMARC-FAIL", "HDR-REPLYTO-FREEMAIL"} <= found
    assert report.verdict == "likely phishing" and report.risk == 95


def test_impersonation_of_protected_name():
    _, found = fixture_ids(
        "ceo_fraud.eml", protected_names=["jane smith"], trusted_domains=["example.org"]
    )
    assert "HDR-IMPERSONATION" in found


def test_trusted_domain_is_not_impersonation():
    _, found = fixture_ids(
        "ceo_fraud.eml", protected_names=["Jane Smith"], trusted_domains=["example.net"]
    )
    assert "HDR-IMPERSONATION" not in found


def test_protected_name_requires_trusted_domain():
    with pytest.raises(ValueError, match="trusted-domain"):
        triage_message(read_eml(FIXTURES / "ceo_fraud.eml"), protected_names=["Jane Smith"])


def test_display_name_with_other_email():
    report, found = fixture_ids("display_name_email.eml")
    assert "HDR-DISPLAYNAME-EMAIL" in found and "HDR-NO-AUTH-RESULTS" in found
    assert report.verdict == "suspicious"


def test_multiple_from_headers():
    _, found = fixture_ids("multiple_from.eml")
    assert "HDR-MULTIPLE-FROM" in found


def test_received_and_date_anomalies():
    _, found = fixture_ids("received_anomaly.eml")
    assert {"HDR-RECEIVED-TIME-ANOMALY", "HDR-DATE-SKEW"} <= found


def test_minimal_message_does_not_crash():
    report, found = fixture_ids("minimal.eml")
    assert {"HDR-NO-FROM", "HDR-NO-RECEIVED", "HDR-NO-AUTH-RESULTS"} <= found
    assert report.sender == ""


# --- individual rules -----------------------------------------------------------------
def test_replyto_mismatch_not_freemail_is_medium():
    msg = build(
        "From: A <a@example.com>\nReply-To: b@example.org\nReceived: x; Tue, 03 Mar 2026 10:00:00 +0000"
    )
    findings, _ = analyze_headers(msg)
    finding = next(f for f in findings if f.id == "HDR-REPLYTO-MISMATCH")
    assert finding.severity.label == "medium"


def test_same_org_replyto_and_returnpath_are_fine():
    msg = build(
        "From: A <a@example.com>\nReply-To: help@mail.example.com\nReturn-Path: <x@bounce.example.com>"
    )
    found = {f.id for f in analyze_headers(msg)[0]}
    assert "HDR-REPLYTO-MISMATCH" not in found and "HDR-RETURNPATH-MISMATCH" not in found


def test_freemail_sender_with_freemail_replyto_is_not_flagged_as_freemail_redirect():
    msg = build("From: A <a@gmail.com>\nReply-To: b@outlook.com")
    found = {f.id for f in analyze_headers(msg)[0]}
    assert "HDR-REPLYTO-FREEMAIL" not in found and "HDR-REPLYTO-MISMATCH" in found


def test_returnpath_mismatch_is_low():
    msg = build("From: A <a@example.com>\nReturn-Path: <x@esp.example.net>")
    finding = next(f for f in analyze_headers(msg)[0] if f.id == "HDR-RETURNPATH-MISMATCH")
    assert finding.severity.label == "low"


def test_empty_return_path_is_ignored():
    msg = build("From: A <a@example.com>\nReturn-Path: <>")
    assert "HDR-RETURNPATH-MISMATCH" not in {f.id for f in analyze_headers(msg)[0]}


def test_display_name_domain_mention():
    msg = build('From: "example.com Support" <help@example.org>')
    assert "HDR-DISPLAYNAME-DOMAIN" in {f.id for f in analyze_headers(msg)[0]}
    msg = build('From: "Dr.Smith" <help@example.org>')
    assert "HDR-DISPLAYNAME-DOMAIN" not in {f.id for f in analyze_headers(msg)[0]}


def test_received_spf_header_is_used_when_no_authentication_results():
    msg = build("From: A <a@example.com>\nReceived-SPF: fail (example.org: not allowed)")
    found = {f.id for f in analyze_headers(msg)[0]}
    assert "HDR-SPF-FAIL" in found and "HDR-NO-AUTH-RESULTS" not in found


def test_only_topmost_authentication_results_is_trusted():
    msg = build(
        "Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\n"
        "Authentication-Results: forged.example.net; spf=fail; dkim=fail; dmarc=fail\n"
        "From: A <a@example.com>"
    )
    _, facts = analyze_headers(msg)
    assert facts["authentication"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_softfail_is_medium_and_pass_is_silent():
    msg = build("Authentication-Results: mx.example.org; spf=softfail; dkim=pass; dmarc=pass")
    findings, _ = analyze_headers(msg)
    spf = next(f for f in findings if f.id == "HDR-SPF-SOFTFAIL")
    assert spf.severity.label == "medium"
    assert not any(f.id.startswith(("HDR-DKIM", "HDR-DMARC")) for f in findings)


# --- scoring --------------------------------------------------------------------------
def test_verdict_thresholds():
    assert verdict_for(0) == verdict_for(24) == "no strong indicators"
    assert verdict_for(25) == verdict_for(59) == "suspicious"
    assert verdict_for(60) == verdict_for(100) == "likely phishing"


def test_risk_is_capped_at_100():
    report, _ = fixture_ids(
        "ceo_fraud.eml", protected_names=["Jane"], trusted_domains=["example.org"]
    )
    assert risk_score(report.findings) == 100


# --- hostile input --------------------------------------------------------------------
def test_control_characters_are_removed_from_report_text():
    msg = build(
        'Subject: hi\x1b[2J there\nFrom: "Boss\x1b]0;pwned\x07" <a@example.com>\n'
        "Reply-To: x@gmail.com"
    )
    report = triage_message(msg)
    blob = json.dumps(report.to_dict())
    assert "\\u001b" not in blob and "\\u0007" not in blob
    assert "\x1b" not in report.subject


# --- CLI ------------------------------------------------------------------------------
def test_cli_json_output(capsys):
    code = main(["triage", str(FIXTURES / "ceo_fraud.eml"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["verdict"] == "likely phishing"
    assert "heuristic" in data["note"].lower()


def test_cli_text_and_markdown_run(capsys):
    assert main(["triage", str(FIXTURES / "legit_newsletter.eml")]) == 0
    assert "no strong indicators" in capsys.readouterr().out
    assert main(["triage", str(FIXTURES / "ceo_fraud.eml"), "--format", "markdown"]) == 0
    assert "# Phishing triage" in capsys.readouterr().out


def test_cli_errors(capsys, tmp_path):
    assert main(["triage", str(tmp_path / "nope.eml")]) == 2
    assert main(["triage", str(FIXTURES / "ceo_fraud.eml"), "--protected-name", "Jane"]) == 2
    assert main(["triage", str(FIXTURES / "ceo_fraud.eml"), "-o", str(tmp_path / "x")]) == 2
    err = capsys.readouterr().err
    assert "cannot read" in err and "trusted-domain" in err


def test_cli_writes_file(tmp_path):
    out = tmp_path / "triage.md"
    code = main(["triage", str(FIXTURES / "ceo_fraud.eml"), "--format", "markdown", "-o", str(out)])
    assert code == 0 and out.read_text(encoding="utf-8").startswith("# Phishing triage")


# --- stage 2 integration -----------------------------------------------------------------
def test_link_fixture():
    report, found = fixture_ids("link_mismatch.eml")
    assert {
        "URL-TEXT-MISMATCH",
        "URL-IP-HOST",
        "URL-SHORTENER",
        "URL-USERINFO",
        "URL-PUNYCODE",
    } <= found
    assert all(u.startswith("hxxp") for u in report.facts["urls"])
    assert report.verdict == "likely phishing"


def test_attachment_fixture():
    report, found = fixture_ids("risky_attachment.eml")
    assert {
        "ATT-DOUBLE-EXTENSION",
        "ATT-DANGEROUS-TYPE",
        "ATT-DISGUISED-EXECUTABLE",
        "ATT-MACRO-DOCUMENT",
    } <= found
    assert {a["name"] for a in report.facts["attachments"]} == {
        "invoice.pdf.exe",
        "report.xlsm",
        "photo.jpg",
    }
    assert report.verdict == "likely phishing"


def test_lookalike_fixture_needs_trusted_domain():
    _, found = fixture_ids("lookalike_sender.eml")
    assert "LOOK-HOMOGLYPH" not in found
    _, found = fixture_ids("lookalike_sender.eml", trusted_domains=["example.com"])
    assert "LOOK-HOMOGLYPH" in found


def test_wire_change_fixture_combines_header_and_wording_signals():
    report, found = fixture_ids(
        "wire_change.eml", protected_names=["Jane Smith"], trusted_domains=["example.org"]
    )
    assert {
        "TXT-PAYMENT-CHANGE",
        "TXT-CLOSING-WIRE",
        "TXT-URGENCY-SECRECY",
        "HDR-REPLYTO-FREEMAIL",
        "HDR-IMPERSONATION",
    } <= found
    assert report.verdict == "likely phishing"


def test_wording_alone_is_only_suspicious():
    msg = parse_eml(
        b"From: Vendor <ap@example.com>\nSubject: Remittance update\n"
        b"Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\n"
        b"Received: x; Tue, 03 Mar 2026 10:00:00 +0000\n\n"
        b"Please note our updated bank details for future payments.\n"
    )
    report = triage_message(msg)
    assert {f.id for f in report.findings} == {"TXT-PAYMENT-CHANGE"}
    assert report.verdict == "suspicious"


def test_legit_fixture_is_still_clean_with_all_modules():
    report, found = fixture_ids("legit_newsletter.eml", trusted_domains=["example.com"])
    assert found == set() and report.facts["attachments"] == [] and report.facts["urls"] == []


def test_cli_markdown_lists_attachment_hashes(capsys):
    assert main(["triage", str(FIXTURES / "risky_attachment.eml"), "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert "## Attachments" in out and "sha256 `" in out
    assert main(["triage", str(FIXTURES / "link_mismatch.eml")]) == 0
    assert "Links:" in capsys.readouterr().out
