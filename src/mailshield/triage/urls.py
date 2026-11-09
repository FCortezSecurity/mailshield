"""Link analysis. Links are parsed and classified, never fetched or resolved."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from mailshield.models import Finding, Severity
from mailshield.textutil import clean
from mailshield.triage.body import Body
from mailshield.triage.domains import org_domain
from mailshield.triage.headers import KNOWN_TLDS

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
}
MAX_LINKS = 200
_PLAIN_URL = re.compile(r"https?://[^\s<>\"'()\[\]]+", re.IGNORECASE)
_URLISH_TEXT = re.compile(
    r"^(?:https?://)?((?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(KNOWN_TLDS)) + r"))(?:[/:?#]\S*)?$",
    re.IGNORECASE,
)
_NUMERIC_HOST = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE)


@dataclass(frozen=True)
class Link:
    href: str
    text: str
    kind: str  # "a", "form" or "text"


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def _finish(self) -> None:
        if self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._text).split()), "a"))
        self._href, self._text = None, []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attributes = dict(attrs)
        if tag == "a" and attributes.get("href"):
            self._finish()
            self._href = attributes["href"]
        elif tag == "form" and attributes.get("action"):
            self.links.append(Link(attributes["action"], "", "form"))

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._finish()

    def close(self) -> None:
        super().close()
        self._finish()


def defang(url: str, limit: int = 100) -> str:
    """Make a URL safe to display: it cannot be clicked or auto-linked by accident."""
    url = clean(url.strip(), limit)
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", url)
    if not match:
        return url.replace(".", "[.]")
    scheme, host, rest = match.groups()
    if scheme.lower().startswith("http"):
        scheme = "hxx" + scheme[3:]
    return f"{scheme}://{host.replace('.', '[.]')}{rest}"


def extract_links(body: Body) -> list[Link]:
    links: list[Link] = []
    if body.html:
        parser = _LinkParser()
        try:
            parser.feed(body.html)
            parser.close()
        except Exception:  # HTMLParser can raise on pathological markup
            pass
        links.extend(parser.links)
    for match in _PLAIN_URL.finditer(body.text):
        links.append(Link(match.group(0).rstrip(".,;:!?"), "", "text"))
    unique = list(dict.fromkeys(links))
    return unique[:MAX_LINKS]


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST.match(host))


@dataclass
class UrlAnalysis:
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)


_RULES = (
    (
        "userinfo",
        "URL-USERINFO",
        Severity.HIGH,
        "Link hides its real destination behind a username",
        "In a link like hxxps://shop[.]example[.]com@evil[.]example[.]net the real host is the "
        "part after the @.",
        "Do not click. Check where the link really goes.",
    ),
    (
        "mismatch",
        "URL-TEXT-MISMATCH",
        Severity.HIGH,
        "Link text shows one site but the link goes to another",
        "The visible text looks like a web address that differs from the real target.",
        "Do not click. Type the address yourself or use a bookmark.",
    ),
    (
        "ip",
        "URL-IP-HOST",
        Severity.HIGH,
        "Link points to a raw IP address",
        "Legitimate services almost never ask people to log in at a bare IP address.",
        "Do not click.",
    ),
    (
        "punycode",
        "URL-PUNYCODE",
        Severity.MEDIUM,
        "Link uses an internationalized (punycode) domain",
        "Domains like xn--... can display as look-alikes of real brands.",
        "Compare the real domain character by character before trusting it.",
    ),
    (
        "shortener",
        "URL-SHORTENER",
        Severity.MEDIUM,
        "Link uses a URL shortener",
        "Shorteners hide the real destination.",
        "Expand the link with a safe preview tool before opening it.",
    ),
    (
        "form",
        "URL-FORM",
        Severity.MEDIUM,
        "Message contains an HTML form",
        "Forms inside emails are rare for legitimate mail and are used to capture credentials.",
        "Do not enter anything into it.",
    ),
)


def analyze_urls(body: Body) -> UrlAnalysis:
    result = UrlAnalysis()
    buckets: dict[str, list[str]] = {rule[0]: [] for rule in _RULES}
    hosts: set[str] = set()
    for link in extract_links(body):
        try:
            parts = urlsplit(link.href.strip())
        except ValueError:
            continue
        if parts.scheme.lower() not in ("http", "https"):
            continue
        host = (parts.hostname or "").lower()
        if not host:
            continue
        shown = defang(link.href)
        result.urls.append(shown)
        hosts.add(host)
        if "@" in parts.netloc:
            buckets["userinfo"].append(shown)
        if is_ip_host(host):
            buckets["ip"].append(shown)
        if not host.isascii() or any(label.startswith("xn--") for label in host.split(".")):
            buckets["punycode"].append(shown)
        if org_domain(host) in SHORTENERS:
            buckets["shortener"].append(shown)
        if link.kind == "form":
            buckets["form"].append(shown)
        if link.kind == "a":
            match = _URLISH_TEXT.match(link.text.strip()[:200])
            if match and org_domain(match.group(1).lower()) != org_domain(host):
                buckets["mismatch"].append(f"shows {defang(link.text, 60)} but goes to {shown}")

    for key, fid, severity, title, intro, fix in _RULES:
        items = list(dict.fromkeys(buckets[key]))
        if not items:
            continue
        more = f"; and {len(items) - 3} more" if len(items) > 3 else ""
        result.findings.append(
            Finding(
                fid,
                severity,
                title,
                f"{intro} Found in {len(items)} link(s): {'; '.join(items[:3])}{more}",
                fix,
            )
        )
    result.hosts = sorted(hosts)[:50]
    result.urls = list(dict.fromkeys(result.urls))[:50]
    return result
