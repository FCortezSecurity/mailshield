import base64

import pytest
from conftest import ids

from mailshield.dns_auth.dkim import COMMON_SELECTORS, audit_dkim, rsa_key_bits


def _der(tag, content):
    n = len(content)
    if n < 128:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def pkcs1(bits):
    modulus = b"\x00\x80" + b"\x01" * (bits // 8 - 1)
    return _der(0x30, _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01"))


def spki(bits):
    algo = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    return _der(0x30, algo + _der(0x03, b"\x00" + pkcs1(bits)))


def rec(der, extra=""):
    return f"v=DKIM1; k=rsa; {extra}p=" + base64.b64encode(der).decode()


@pytest.mark.parametrize("bits", [512, 1024, 2048, 4096])
def test_key_bits_spki_and_pkcs1(bits):
    assert rsa_key_bits(spki(bits)) == bits
    assert rsa_key_bits(pkcs1(bits)) == bits


def test_garbage_key_raises():
    for bad in (b"", b"\x30", b"\x30\x03\x01\x01\x01", b"\x02\x01\x01"):
        with pytest.raises(ValueError):
            rsa_key_bits(bad)


def test_strong_key_clean(make_resolver):
    r = make_resolver({"google._domainkey.example.com": [rec(spki(2048))]})
    result = audit_dkim("example.com", r)
    assert [k.selector for k in result.keys] == ["google"]
    assert result.keys[0].bits == 2048
    assert result.findings == []


def test_short_and_weak_keys(make_resolver):
    r = make_resolver(
        {
            "s1._domainkey.example.com": [rec(spki(1024))],
            "s2._domainkey.example.com": [rec(spki(512))],
        }
    )
    found = ids(audit_dkim("example.com", r).findings)
    assert {"DKIM-KEY-SHORT", "DKIM-KEY-WEAK"} <= found


def test_revoked(make_resolver):
    r = make_resolver({"k1._domainkey.example.com": ["v=DKIM1; k=rsa; p="]})
    result = audit_dkim("example.com", r)
    assert "DKIM-REVOKED" in ids(result.findings)
    assert result.keys[0].revoked


def test_testing_mode(make_resolver):
    r = make_resolver({"default._domainkey.example.com": [rec(spki(2048), "t=y; ")]})
    assert "DKIM-TESTING" in ids(audit_dkim("example.com", r).findings)


def test_invalid_key(make_resolver):
    r = make_resolver(
        {
            "default._domainkey.example.com": ["v=DKIM1; k=rsa; p=!!!notbase64!!!"],
            "k1._domainkey.example.com": ["v=DKIM1; k=rsa; p=AAAA"],
        }
    )
    result = audit_dkim("example.com", r)
    assert [f.id for f in result.findings].count("DKIM-INVALID") == 2


def test_ed25519_not_flagged(make_resolver):
    key = base64.b64encode(b"\x01" * 32).decode()
    r = make_resolver({"default._domainkey.example.com": [f"v=DKIM1; k=ed25519; p={key}"]})
    assert audit_dkim("example.com", r).findings == []


def test_not_found_is_informational(make_resolver):
    result = audit_dkim("example.com", make_resolver())
    assert ids(result.findings) == {"DKIM-NOT-FOUND"}
    assert len(result.probed) == len(COMMON_SELECTORS)


def test_custom_selector_is_probed_once(make_resolver):
    r = make_resolver({"acme2026._domainkey.example.com": [rec(spki(2048))]})
    result = audit_dkim("example.com", r, extra_selectors=["ACME2026", "acme2026", "default"])
    assert [k.selector for k in result.keys] == ["acme2026"]
    assert result.probed.count("default") == 1


def test_dns_errors_are_reported(make_resolver):
    r = make_resolver(errors=["default._domainkey.example.com"])
    assert "DKIM-DNS-ERROR" in ids(audit_dkim("example.com", r).findings)
