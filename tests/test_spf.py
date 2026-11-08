from conftest import ids

from mailshield.dns_auth.spf import audit_spf, parse_terms


def test_parse_terms():
    terms = parse_terms("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net ~all redirect=x.example")
    names = [(t.kind, t.qualifier, t.name) for t in terms]
    assert ("mechanism", "+", "ip4") in names
    assert ("mechanism", "~", "all") in names
    assert ("modifier", "", "redirect") in names


def test_missing(make_resolver):
    assert ids(audit_spf("example.com", make_resolver()).findings) == {"SPF-MISSING"}


def test_clean_hardfail(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 ip4:192.0.2.1 -all"]})
    result = audit_spf("example.com", r)
    assert result.findings == []
    assert result.lookups == 0


def test_plus_all_and_bare_all(make_resolver):
    for rec in ("v=spf1 +all", "v=spf1 all"):
        r = make_resolver({"example.com": [rec]})
        assert "SPF-ALL-PLUS" in ids(audit_spf("example.com", r).findings)


def test_neutral_and_softfail(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 ?all"]})
    assert "SPF-ALL-NEUTRAL" in ids(audit_spf("example.com", r).findings)
    r = make_resolver({"example.com": ["v=spf1 ~all"]})
    assert "SPF-SOFTFAIL" in ids(audit_spf("example.com", r).findings)


def test_no_all(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 ip4:192.0.2.1"]})
    assert "SPF-NO-ALL" in ids(audit_spf("example.com", r).findings)


def test_multiple_records(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
    assert "SPF-MULTIPLE" in ids(audit_spf("example.com", r).findings)


def test_ptr_and_unknown(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 ptr bogus:x -all"]})
    found = ids(audit_spf("example.com", r).findings)
    assert {"SPF-PTR", "SPF-SYNTAX"} <= found


def test_lookup_limit_exceeded(make_resolver):
    includes = " ".join(f"include:s{i}.example.net" for i in range(11))
    records = {"example.com": [f"v=spf1 {includes} -all"]}
    for i in range(11):
        records[f"s{i}.example.net"] = ["v=spf1 ip4:192.0.2.1 -all"]
    result = audit_spf("example.com", make_resolver(records))
    assert result.lookups == 11
    assert "SPF-LOOKUP-LIMIT" in ids(result.findings)


def test_nested_lookup_counting(make_resolver):
    r = make_resolver(
        {
            "example.com": ["v=spf1 include:a.example.net mx -all"],
            "a.example.net": ["v=spf1 a include:b.example.net -all"],
            "b.example.net": ["v=spf1 ip4:192.0.2.1 -all"],
        }
    )
    assert audit_spf("example.com", r).lookups == 4


def test_lookup_near_limit(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 " + "a " * 9 + "-all"]})
    assert "SPF-LOOKUP-NEAR" in ids(audit_spf("example.com", r).findings)


def test_include_loop(make_resolver):
    r = make_resolver(
        {
            "example.com": ["v=spf1 include:a.example.net -all"],
            "a.example.net": ["v=spf1 include:example.com -all"],
        }
    )
    assert "SPF-LOOP" in ids(audit_spf("example.com", r).findings)


def test_include_target_missing(make_resolver):
    r = make_resolver({"example.com": ["v=spf1 include:gone.example.net -all"]})
    assert "SPF-INCLUDE-INVALID" in ids(audit_spf("example.com", r).findings)


def test_dns_error(make_resolver):
    r = make_resolver(errors=["example.com"])
    assert ids(audit_spf("example.com", r).findings) == {"SPF-DNS-ERROR"}
