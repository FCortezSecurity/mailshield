"""Minimal, defensive HTTPS fetcher used for MTA-STS policy files.

Design choices:
- The caller supplies only a hostname and a path, so the scheme is always https.
- Redirects are never followed (RFC 8461 forbids it).
- The TLS certificate and hostname are always verified.
- Hostnames that resolve to non-public addresses (loopback, private, link-local,
  cloud metadata, etc.) are refused, so a hostile domain cannot aim this tool at
  internal services.
- The response size and total time are capped.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Protocol

MAX_BYTES = 64 * 1024


@dataclass
class FetchResult:
    status: int | None = None
    body: str = ""
    content_type: str = ""
    error: str | None = None


class PolicyFetcher(Protocol):
    def fetch(self, host: str, path: str) -> FetchResult:
        """GET https://<host><path>. Never raises; failures are reported in `error`."""


class _Blocked(Exception):
    pass


class HttpsPolicyFetcher:
    def __init__(
        self,
        timeout: float = 5.0,
        max_bytes: int = MAX_BYTES,
        *,
        allow_private: bool = False,
        port: int = 443,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allow_private = allow_private
        self.port = port
        self._ctx = ssl_context or ssl.create_default_context()

    def _resolve(self, host: str) -> list[str]:
        infos = socket.getaddrinfo(host, self.port, type=socket.SOCK_STREAM)
        addresses: list[str] = []
        for info in infos:
            ip = str(info[4][0])
            if not self.allow_private and not ipaddress.ip_address(ip.split("%")[0]).is_global:
                raise _Blocked(
                    f"{host} resolves to a non-public address ({ip}); refusing to connect"
                )
            if ip not in addresses:
                addresses.append(ip)
        return addresses

    def _request(self, tls: ssl.SSLSocket, host: str, path: str, deadline: float) -> FetchResult:
        tls.settimeout(max(0.1, deadline - time.monotonic()))
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mailshield\r\n"
            "Accept: text/plain\r\nConnection: close\r\n\r\n"
        )
        tls.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(tls, method="GET")
        response.begin()
        status = response.status
        content_type = response.getheader("Content-Type", "") or ""
        if 300 <= status < 400:
            return FetchResult(status=status, content_type=content_type)
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError
            chunk = response.read(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                return FetchResult(
                    status=status, error=f"response is larger than {self.max_bytes} bytes"
                )
            chunks.append(chunk)
        body = b"".join(chunks).decode("utf-8", "replace")
        return FetchResult(status=status, body=body, content_type=content_type)

    def fetch(self, host: str, path: str) -> FetchResult:
        deadline = time.monotonic() + self.timeout
        try:
            addresses = self._resolve(host)
        except socket.gaierror:
            return FetchResult(error=f"{host} does not resolve")
        except _Blocked as exc:
            return FetchResult(error=str(exc))

        last_error = f"could not connect to {host}"
        for ip in addresses:
            try:
                raw = socket.create_connection((ip, self.port), timeout=self.timeout)
            except OSError as exc:
                last_error = f"could not connect to {host}: {exc.__class__.__name__}"
                continue
            try:
                with self._ctx.wrap_socket(raw, server_hostname=host) as tls:
                    return self._request(tls, host, path, deadline)
            except ssl.SSLCertVerificationError as exc:
                return FetchResult(error=f"TLS certificate not valid: {exc.verify_message}")
            except ssl.SSLError as exc:
                return FetchResult(error=f"TLS error: {exc.reason or exc.__class__.__name__}")
            except TimeoutError:
                return FetchResult(error="request timed out")
            except (OSError, http.client.HTTPException) as exc:
                return FetchResult(error=f"request failed: {exc.__class__.__name__}")
            finally:
                raw.close()
        return FetchResult(error=last_error)
