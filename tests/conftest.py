import pytest

from mailshield.dns_auth.resolver import DnsError
from mailshield.fetch import FetchResult


class FakeResolver:
    def __init__(self, records=None, errors=None, mx=None):
        self.mx_records = {k.lower(): v for k, v in (mx or {}).items()}
        self.records = {k.lower(): v for k, v in (records or {}).items()}
        self.errors = {e.lower() for e in (errors or [])}

    def txt(self, name):
        name = name.lower()
        if name in self.errors:
            raise DnsError(f"{name}: Timeout")
        return list(self.records.get(name, []))

    def mx(self, name):
        name = name.lower()
        if name in self.errors:
            raise DnsError(f"{name}: Timeout")
        return list(self.mx_records.get(name, []))


class FakeFetcher:
    def __init__(self, result=None):
        self.result = result or FetchResult(error="no result configured")
        self.calls = []

    def fetch(self, host, path):
        self.calls.append((host, path))
        return self.result


@pytest.fixture
def make_fetcher():
    return FakeFetcher


@pytest.fixture
def make_resolver():
    return FakeResolver


def ids(findings):
    return {f.id for f in findings}
