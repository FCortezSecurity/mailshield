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
    assert data["domain"] == "example.com" and len(data["findings"]) == 2
    assert "SPF-MISSING" in to_markdown(report)
