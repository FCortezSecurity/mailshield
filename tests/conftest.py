import pytest

from mailshield.dns_auth.resolver import DnsError


class FakeResolver:
    def __init__(self, records=None, errors=None):
        self.records = {k.lower(): v for k, v in (records or {}).items()}
        self.errors = {e.lower() for e in (errors or [])}

    def txt(self, name):
        name = name.lower()
        if name in self.errors:
            raise DnsError(f"{name}: Timeout")
        return list(self.records.get(name, []))


@pytest.fixture
def make_resolver():
    return FakeResolver


def ids(findings):
    return {f.id for f in findings}
