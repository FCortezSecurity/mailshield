import json

import pytest

from mailshield.audit import audit_domain, normalize_domain
from mailshield.report import to_json, to_markdown
from mailshield.scoring import grade


def test_normalize_domain():
    assert normalize_domain(" Example.COM. ") == "example.com"
    for bad in ("not a domain", "localhost", "a..com", ""):
        with pytest.raises(ValueError):
            normalize_domain(bad)


def test_grades():
    assert [grade(v) for v in (100, 85, 75, 65, 10)] == ["A", "B", "C", "D", "F"]


def test_good_domain_scores_100(make_resolver):
    r = make_resolver(
        {
            "example.com": ["v=spf1 ip4:192.0.2.1 -all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@example.com"],
        }
    )
    report = audit_domain("example.com", r)
    assert (report.score, report.grade) == (100, "A")


def test_bad_domain_scores_low_and_reports_render(make_resolver):
    report = audit_domain("example.com", make_resolver())
    assert report.score == 50 and report.grade == "F"
    data = json.loads(to_json(report))
    assert data["domain"] == "example.com" and len(data["findings"]) == 3
    assert "SPF-MISSING" in to_markdown(report)


def test_softfail_is_free_when_dmarc_enforces(make_resolver):
    r = make_resolver(
        {
            "example.com": ["v=spf1 ip4:192.0.2.1 ~all"],
            "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:a@example.com"],
        }
    )
    assert audit_domain("example.com", r).score == 100


def test_softfail_costs_points_without_enforcement(make_resolver):
    r = make_resolver(
        {
            "example.com": ["v=spf1 ip4:192.0.2.1 ~all"],
            "_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:a@example.com"],
        }
    )
    assert audit_domain("example.com", r).score == 80


NULL_DMARC = "v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"


def test_null_sender_domain_is_recognized(make_resolver):
    r = make_resolver(
        {"example.com": ["v=spf1 -all"], "_dmarc.example.com": [NULL_DMARC]},
    )
    report = audit_domain("example.com", r)
    assert report.null_sender is True
    assert report.score == 100
    assert {f.id for f in report.findings} == {"NULL-SENDER-DOMAIN"}


def test_null_sender_requires_enforcing_dmarc(make_resolver):
    r = make_resolver(
        {"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"]},
    )
    report = audit_domain("example.com", r)
    assert report.null_sender is False
    assert "DMARC-NO-RUA" in {f.id for f in report.findings}


def test_domain_with_senders_is_not_null_sender(make_resolver):
    r = make_resolver(
        {"example.com": ["v=spf1 ip4:192.0.2.1 -all"], "_dmarc.example.com": [NULL_DMARC]},
    )
    assert audit_domain("example.com", r).null_sender is False


def test_null_sender_with_wildcard_revoked_dkim_is_quiet(make_resolver):
    from mailshield.dns_auth.dkim import COMMON_SELECTORS

    records = {"example.com": ["v=spf1 -all"], "_dmarc.example.com": [NULL_DMARC]}
    records.update({f"{s}._domainkey.example.com": ["v=DKIM1; p="] for s in COMMON_SELECTORS})
    report = audit_domain("example.com", make_resolver(records))
    assert {f.id for f in report.findings} == {"NULL-SENDER-DOMAIN"}
    assert report.score == 100


def test_revoked_keys_are_summarized_separately(make_resolver):
    from mailshield.report.render import dkim_summary

    r = make_resolver({"k1._domainkey.example.com": ["v=DKIM1; p="]})
    summary = dkim_summary(audit_domain("example.com", r))
    assert summary == "none active among 20 common selectors (1 revoked)"
