from __future__ import annotations

# A small built-in list. A full public-suffix list would be more accurate; this is a
# documented limitation.
MULTI_LABEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "co.jp",
    "co.in",
    "co.za",
    "com.br",
    "com.mx",
    "com.ar",
    "com.sg",
    "com.hk",
    "com.tr",
    "com.cn",
}


def domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rpartition("@")[2].strip().strip(">").lower().rstrip(".")


def org_domain(domain: str) -> str:
    """Approximate the registrable (organizational) domain."""
    domain = domain.lower().rstrip(".")
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_org(a: str, b: str) -> bool:
    return bool(a) and bool(b) and org_domain(a) == org_domain(b)
