from conftest import ids

from mailshield.dns_auth.dmarc import audit_dmarc, parse_tags


def _dmarc(make_resolver, record):
    return audit_dmarc("example.com", make_resolver({"_dmarc.example.com": [record]}))


def test_parse_tags():
    tags = parse_tags("v=DMARC1; p=reject; rua=mailto:a@example.com;")
    assert tags["p"] == "reject" and tags["rua"] == "mailto:a@example.com"


def test_missing(make_resolver):
    assert ids(audit_dmarc("example.com", make_resolver()).findings) == {"DMARC-MISSING"}


def test_p_none(make_resolver):
    result = _dmarc(make_resolver, "v=DMARC1; p=none; rua=mailto:a@example.com")
    assert ids(result.findings) == {"DMARC-P-NONE"}


def test_strong_policy_is_clean(make_resolver):
    result = _dmarc(make_resolver, "v=DMARC1; p=reject; rua=mailto:a@example.com")
    assert result.findings == []
    assert result.policy == "reject"


def test_quarantine_pct_sp_and_no_rua(make_resolver):
    result = _dmarc(make_resolver, "v=DMARC1; p=quarantine; pct=50; sp=none")
    assert {"DMARC-P-QUARANTINE", "DMARC-PCT", "DMARC-SP-WEAK", "DMARC-NO-RUA"} <= ids(
        result.findings
    )


def test_invalid_policy(make_resolver):
    assert "DMARC-INVALID" in ids(_dmarc(make_resolver, "v=DMARC1; p=banana").findings)
    assert "DMARC-INVALID" in ids(
        _dmarc(make_resolver, "v=DMARC1; rua=mailto:a@example.com").findings
    )


def test_multiple(make_resolver):
    r = make_resolver({"_dmarc.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]})
    assert "DMARC-MULTIPLE" in ids(audit_dmarc("example.com", r).findings)


def test_strict_alignment_info(make_resolver):
    result = _dmarc(make_resolver, "v=DMARC1; p=reject; rua=mailto:a@example.com; adkim=s; aspf=s")
    assert {"DMARC-STRICT-ADKIM", "DMARC-STRICT-ASPF"} == ids(result.findings)


def test_dns_error(make_resolver):
    r = make_resolver(errors=["_dmarc.example.com"])
    assert ids(audit_dmarc("example.com", r).findings) == {"DMARC-DNS-ERROR"}
