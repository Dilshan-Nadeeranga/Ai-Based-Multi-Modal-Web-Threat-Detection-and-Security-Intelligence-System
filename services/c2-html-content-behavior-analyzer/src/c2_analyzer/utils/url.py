"""URL helpers: normalization, resolving, registrable domains, internal vs external.

Shared (used across Parts 1-9).

Why: the same page often appears in feeds with tiny differences
("HTTP://Site.com/login/" vs "http://site.com/login#top"). Normalizing URLs
lets the candidate list detect those as one URL, and comparing hosts lets the
fetcher notice when a scam URL redirected somewhere else.

Part 2 adds the "registrable domain" (the part a person can buy, e.g.
``bank.com.lk`` for ``login.secure.bank.com.lk``). Comparing registrable
domains tells whether a link, form or script points to another site. It uses
tldextract's bundled public-suffix list OFFLINE (no download at runtime). If
tldextract is not installed, a small built-in rule is used instead.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import urljoin, urlsplit, urlunsplit

# Fallback only (when tldextract is missing): two-level public suffixes we
# meet most often. tldextract knows all of them.
TWO_LEVEL_SUFFIXES = {
    "com.lk", "org.lk", "edu.lk", "gov.lk", "ac.lk", "net.lk", "sch.lk", "ltd.lk", "web.lk",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in",
    "org.in", "co.jp", "com.br", "com.cn", "com.sg", "com.my", "co.nz", "co.za", "com.tr",
}  # fmt: skip
# One DNS label (letters, digits, hyphens; punycode "xn--" included).
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_url(url: str) -> str:
    """Canonical form used to compare URLs (not to fetch them).

    - adds ``http://`` if no scheme was given
    - lowercases scheme and host (paths stay case-sensitive)
    - removes the ``#fragment`` (never sent to the server)
    - removes a trailing ``/``
    """
    url = url.strip()
    if "://" not in url:
        url = f"http://{url}"
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def extract_domain(url: str) -> str | None:
    """Return the host of ``url`` in lowercase without a leading ``www.``.

    Use ``registrable_domain`` to compare sites; this keeps every subdomain.
    """
    try:
        host = urlsplit(url.strip()).hostname
    except ValueError:  # e.g. a malformed IPv6 address
        return None
    if not host:
        return None
    return host.removeprefix("www.")


@lru_cache(maxsize=1)
def _tld_extractor():
    """tldextract configured offline, or None if the package is not installed.

    suffix_list_urls=() -> never download the list; use the snapshot shipped
    with the package. include_psl_private_domains=True -> hosting suffixes like
    pages.dev, vercel.app or github.io count as suffixes, so two different
    sites on the same free host are different domains (common for phishing).
    """
    try:
        import tldextract
    except ImportError:
        return None
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


def domain_method() -> str:
    """Which rule decides registrable domains (stored with every ParsedPage)."""
    return "tldextract-offline" if _tld_extractor() is not None else "builtin-rule"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@lru_cache(maxsize=65536)
def domain_of_host(host: str) -> str:
    """Registrable domain of a host name ("a.b.bank.com.lk" -> "bank.com.lk").

    IP addresses and single-label hosts ("localhost") are returned unchanged.
    A well-formed host whose suffix is not on the public-suffix list (reserved
    ".example", ".test", ".local", internal names) falls back to the built-in
    rule, so "cdn.site.example" and "www.site.example" are still one site.
    A host that IS a public suffix ("s3.ap-southeast-1.amazonaws.com") or is
    malformed ("bank.lk%20") is kept whole.
    """
    host = host.lower().rstrip(".")
    if _is_ip(host) or "." not in host:
        return host
    extractor = _tld_extractor()
    if extractor is not None:
        result = extractor(host)
        if hasattr(result, "top_domain_under_public_suffix"):  # tldextract >= 5.3
            domain = result.top_domain_under_public_suffix
        else:
            domain = result.registered_domain
        if domain:
            return domain
        if result.suffix or not HOST_LABEL.match(host.rsplit(".", 1)[-1]):
            return host  # the host is a suffix itself, or not a valid DNS name
    labels = host.split(".")
    keep = 3 if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[-keep:])


def registrable_domain(url: str | None) -> str | None:
    """Registrable domain of an http(s) URL, or None (relative, mailto:, javascript:, ...)."""
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    host = extract_domain(url)
    return domain_of_host(host) if host else None


def resolve_url(href: str | None, base_url: str | None) -> str | None:
    """Make ``href`` absolute against ``base_url`` (like a browser, without fetching).

    Returns None for an empty href. Without a base URL a relative href stays relative.
    """
    if href is None:
        return None
    href = href.strip()
    if not href:
        return None
    if not base_url:
        return href
    try:
        return urljoin(base_url, href)
    except ValueError:  # malformed URL (e.g. bad IPv6 brackets) - keep it as written
        return href


def is_external(link: str | None, page_url: str | None) -> bool:
    """True if an absolute http(s) ``link`` points to another registrable domain.

    Relative links and non-web links (mailto:, javascript:, #...) are internal.
    If the page's own address is unknown (an HTML string without URL), every
    absolute http(s) link counts as external, because it names a site.
    """
    link_domain = registrable_domain(link)
    if link_domain is None:
        return False
    return link_domain != registrable_domain(page_url)
