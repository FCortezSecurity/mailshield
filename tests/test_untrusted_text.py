import pytest

from mailshield.audit import audit_domain
from mailshield.cli import main
from mailshield.dns_auth.resolver import DnsResolver
from mailshield.textutil import clean


def test_clean_removes_control_characters_and_truncates():
    assert clean("a\x1b[2Jb\x07c\r\nd") == "a [2Jb c  d"
    assert clean("x" * 10, limit=8) == "xxxxx..."
    assert clean("plain text") == "plain text"


class _Rdata:
    def __init__(self, data: bytes):
        self.strings = [data]


class _FakeDns:
    def resolve(self, name, rtype):
        return [_Rdata(b"v=spf1 -all\x1b[2J\x1b]0;pwned\x07")]


def test_dns_resolver_strips_control_characters():
    resolver = DnsResolver(timeout=1)
    resolver._resolver = _FakeDns()
    (record,) = resolver.txt("example.com")
    assert "\x1b" not in record and "\x07" not in record


@pytest.mark.parametrize(
    "record", ["v=spf1 [/oops] -all", "v=spf1 [red]x[/red] -all", "v=spf1 [bold -all"]
)
def test_text_output_survives_markup_in_dns_data(monkeypatch, capsys, make_resolver, record):
    import mailshield.cli as cli

    resolver = make_resolver({"example.com": [record]})
    monkeypatch.setattr(cli, "DnsResolver", lambda timeout: resolver)
    assert main(["audit", "example.com", "--no-fetch"]) == 0
    assert "spf1" in capsys.readouterr().out


def test_audit_report_object_still_builds(make_resolver):
    assert audit_domain("example.com", make_resolver()).score == 50
