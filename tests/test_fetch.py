import socket

import pytest

from mailshield.fetch import HttpsPolicyFetcher


def fake_getaddrinfo(*addresses):
    def _inner(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    return _inner


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "172.16.0.1", "0.0.0.0", "::1"],
)
def test_non_public_addresses_are_refused(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo(address))
    result = HttpsPolicyFetcher().fetch("mta-sts.example.com", "/.well-known/mta-sts.txt")
    assert result.error and "non-public address" in result.error
    assert result.status is None


def test_one_private_address_among_public_ones_is_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("93.184.216.34", "10.0.0.1"))
    result = HttpsPolicyFetcher().fetch("mta-sts.example.com", "/p")
    assert "non-public" in result.error


def test_public_addresses_pass_the_guard(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo("93.184.216.34", "93.184.216.34"))
    assert HttpsPolicyFetcher()._resolve("mta-sts.example.com") == ["93.184.216.34"]


def test_unresolvable_host(monkeypatch):
    def boom(*args, **kwargs):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    result = HttpsPolicyFetcher().fetch("mta-sts.example.com", "/p")
    assert result.error == "mta-sts.example.com does not resolve"
