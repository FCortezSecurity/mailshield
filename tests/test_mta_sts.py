from conftest import ids

from mailshield.dns_auth.mta_sts import audit_mta_sts, mx_matches, parse_policy
from mailshield.fetch import FetchResult

GOOD = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 1209600\n"
TXT = {"_mta-sts.example.com": ["v=STSv1; id=20260101T000000"]}


def run(make_resolver, make_fetcher, body=GOOD, mx=None, **fetch):
    resolver = make_resolver(TXT, mx={"example.com": mx or ["mail.example.com"]})
    result = FetchResult(
        status=fetch.pop("status", 200), body=body, **{"content_type": "text/plain", **fetch}
    )
    fetcher = make_fetcher(result)
    return audit_mta_sts("example.com", resolver, fetcher), fetcher


def test_parse_policy_good():
    fields, problems = parse_policy(GOOD.replace("\n", "\r\n"))
    assert problems == []
    assert fields["mode"] == "enforce" and fields["max_age"] == 1209600
    assert fields["mx"] == ["mail.example.com"]


def test_parse_policy_problems():
    _, problems = parse_policy("version: STSv2\nmode: maybe\nmax_age: soon\nrubbish\n")
    text = " | ".join(problems)
    for expected in ("version", "mode", "max_age is not a number", "unparseable", "mx"):
        assert expected in text


def test_parse_policy_none_mode_needs_no_mx():
    _, problems = parse_policy("version: STSv1\nmode: none\nmax_age: 86400\n")
    assert problems == []


def test_mx_matching_rules():
    assert mx_matches("mail.example.com", "MAIL.example.com.")
    assert mx_matches("*.example.com", "mx1.example.com")
    assert not mx_matches("*.example.com", "a.b.example.com")
    assert not mx_matches("*.example.com", "example.com")
    assert not mx_matches("mail.example.com", "mail.example.org")


def test_missing_is_informational(make_resolver):
    result = audit_mta_sts("example.com", make_resolver())
    assert ids(result.findings) == {"MTA-STS-MISSING"}
    assert result.txt_id is None


def test_invalid_txt(make_resolver):
    for records in (["v=STSv1"], ["v=STSv1; id=a b"], ["v=STSv1; id=a", "v=STSv1; id=b"]):
        r = make_resolver({"_mta-sts.example.com": records})
        assert ids(audit_mta_sts("example.com", r).findings) == {"MTA-STS-TXT-INVALID"}


def test_no_fetch_mode(make_resolver):
    result = audit_mta_sts("example.com", make_resolver(TXT), fetcher=None)
    assert ids(result.findings) == {"MTA-STS-NOT-FETCHED"}
    assert result.txt_id == "20260101T000000"


def test_good_enforce_policy_is_clean_and_fetched_from_the_right_url(make_resolver, make_fetcher):
    result, fetcher = run(make_resolver, make_fetcher)
    assert result.findings == []
    assert (result.mode, result.max_age, result.fetched) == ("enforce", 1209600, True)
    assert fetcher.calls == [("mta-sts.example.com", "/.well-known/mta-sts.txt")]


def test_testing_mode_and_disabled(make_resolver, make_fetcher):
    result, _ = run(make_resolver, make_fetcher, GOOD.replace("enforce", "testing"))
    assert ids(result.findings) == {"MTA-STS-TESTING"}
    result, _ = run(make_resolver, make_fetcher, GOOD.replace("enforce", "none"))
    assert ids(result.findings) == {"MTA-STS-DISABLED"}


def test_short_max_age(make_resolver, make_fetcher):
    result, _ = run(make_resolver, make_fetcher, GOOD.replace("1209600", "3600"))
    assert ids(result.findings) == {"MTA-STS-MAXAGE-SHORT"}


def test_fetch_errors_redirects_and_status(make_resolver, make_fetcher):
    resolver = make_resolver(TXT)
    cases = [
        (FetchResult(error="TLS certificate not valid: expired"), "MTA-STS-POLICY-UNREACHABLE"),
        (FetchResult(status=301, content_type="text/html"), "MTA-STS-REDIRECT"),
        (FetchResult(status=404, body="nope"), "MTA-STS-POLICY-UNREACHABLE"),
    ]
    for response, expected in cases:
        result = audit_mta_sts("example.com", resolver, make_fetcher(response))
        assert ids(result.findings) == {expected}
        assert result.fetched is False


def test_wrong_content_type(make_resolver, make_fetcher):
    result, _ = run(make_resolver, make_fetcher, content_type="text/html")
    assert ids(result.findings) == {"MTA-STS-CONTENT-TYPE"}


def test_invalid_policy_body(make_resolver, make_fetcher):
    result, _ = run(make_resolver, make_fetcher, body="hello world")
    assert "MTA-STS-POLICY-INVALID" in ids(result.findings)
    assert result.fetched is False


def test_mx_mismatch_severity_depends_on_mode(make_resolver, make_fetcher):
    result, _ = run(make_resolver, make_fetcher, mx=["mail.example.com", "backup.other.net"])
    finding = next(f for f in result.findings if f.id == "MTA-STS-MX-MISMATCH")
    assert finding.severity.label == "high" and "backup.other.net" in finding.detail
    result, _ = run(
        make_resolver,
        make_fetcher,
        GOOD.replace("enforce", "testing"),
        mx=["mail.example.com", "backup.other.net"],
    )
    finding = next(f for f in result.findings if f.id == "MTA-STS-MX-MISMATCH")
    assert finding.severity.label == "medium"


def test_wildcard_mx_covers_hosts(make_resolver, make_fetcher):
    body = GOOD.replace("mail.example.com", "*.example.com")
    result, _ = run(make_resolver, make_fetcher, body, mx=["a.example.com", "b.example.com"])
    assert result.findings == []


def test_dns_error(make_resolver):
    r = make_resolver(errors=["_mta-sts.example.com"])
    assert ids(audit_mta_sts("example.com", r).findings) == {"MTA-STS-DNS-ERROR"}
