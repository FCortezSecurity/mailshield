from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.resolver


class DnsError(Exception):
    """A DNS lookup failed in a way that is not 'record does not exist'."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]:
        """Return TXT records as strings. Empty list if none exist. Raise DnsError on failure."""

    def mx(self, name: str) -> list[str]:
        """Return MX target hostnames (lowercase, no trailing dot). Null MX is omitted."""


class DnsResolver:
    """Real resolver backed by dnspython, with a hard timeout."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def txt(self, name: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsError(f"{name}: {exc.__class__.__name__}") from exc
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answer]

    def mx(self, name: str) -> list[str]:
        try:
            answer = self._resolver.resolve(name, "MX")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DnsError(f"{name}: {exc.__class__.__name__}") from exc
        hosts = (str(rdata.exchange).rstrip(".").lower() for rdata in answer)
        return [h for h in hosts if h]
