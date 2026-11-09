import pytest

from mailshield.triage.lookalike import check_lookalikes, edit_distance, skeleton

TRUSTED = ["example.com"]


def found(domain, trusted=TRUSTED, origin="sender address"):
    return {f.id: f for f in check_lookalikes([(origin, domain)], trusted)}


def test_edit_distance():
    assert edit_distance("example", "example") == 0
    assert edit_distance("example", "exampel") == 2
    assert edit_distance("example", "exxample") == 1
    assert edit_distance("", "abc") == 3


@pytest.mark.parametrize("lookalike", ["examp1e.com", "exarnple.com", "exampl\u0435.com"])
def test_homoglyphs(lookalike):
    assert "LOOK-HOMOGLYPH" in found(lookalike)


def test_punycode_homoglyph_is_decoded():
    cyrillic = "\u0435xample.com"  # Cyrillic e
    assert "LOOK-HOMOGLYPH" in found(cyrillic.encode("idna").decode())


def test_tld_swap():
    assert "LOOK-TLD-SWAP" in found("example.co")


def test_edit_distance_severity():
    assert found("exampple.com")["LOOK-EDIT-DISTANCE"].severity.label == "high"
    assert found("exaampple.com")["LOOK-EDIT-DISTANCE"].severity.label == "medium"


def test_embedded_domain_name():
    assert "LOOK-EMBEDDED" in found("example.com.evil.net")
    assert "LOOK-EMBEDDED" in found("login-example.org")


def test_real_domain_and_subdomains_are_never_flagged():
    for domain in ("example.com", "mail.example.com", "EXAMPLE.COM."):
        assert found(domain) == {}


def test_unrelated_and_short_names_are_not_flagged():
    assert found("google.com") == {}
    assert found("abcd.com", ["abce.com"]) == {}  # labels under five characters are too noisy


def test_no_trusted_domains_means_no_findings():
    assert check_lookalikes([("links", "examp1e.com")], []) == []


def test_skeleton_is_symmetric_for_trusted_names():
    assert skeleton("example.com") == skeleton("EXAMPLE.com")
