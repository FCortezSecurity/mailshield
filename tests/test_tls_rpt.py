from conftest import ids

from mailshield.dns_auth.tls_rpt import audit_tls_rpt

NAME = "_smtp._tls.example.com"


def run(make_resolver, records=None, present=False, active=False, errors=None):
    r = make_resolver({NAME: records} if records else {}, errors=errors)
    return audit_tls_rpt("example.com", r, mta_sts_present=present, mta_sts_active=active)


def test_valid_record(make_resolver):
    result = run(make_resolver, ["v=TLSRPTv1; rua=mailto:tls@example.com,https://r.example.com/x"])
    assert result.findings == [] and result.record


def test_missing_without_mta_sts_is_silent(make_resolver):
    assert run(make_resolver).findings == []


def test_missing_with_mta_sts_severity(make_resolver):
    low = run(make_resolver, present=True, active=True).findings[0]
    info = run(make_resolver, present=True, active=False).findings[0]
    assert (low.id, low.severity.label) == ("TLSRPT-MISSING", "low")
    assert info.severity.label == "info"


def test_invalid_records(make_resolver):
    for records in (
        ["v=TLSRPTv1"],
        ["v=TLSRPTv1; rua=ftp://x"],
        ["v=TLSRPTv1; rua=mailto:a@example.com", "v=TLSRPTv1; rua=mailto:b@example.com"],
    ):
        assert ids(run(make_resolver, records).findings) == {"TLSRPT-INVALID"}


def test_dns_error(make_resolver):
    assert ids(run(make_resolver, errors=[NAME]).findings) == {"TLSRPT-DNS-ERROR"}
