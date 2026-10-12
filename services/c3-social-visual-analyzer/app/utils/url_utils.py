"""URLs recorded as evidence: validation, extraction from post text, domains.

Nothing in this module fetches a URL.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlsplit

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_URL_LENGTH = 2048
URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\u200b]+", re.IGNORECASE)
_URL_TRAILING = ".,;:!?)]}'\""

# Click-tracking wrappers used by social platforms: host -> (path, query parameter holding the target).
_LINK_WRAPPERS: dict[str, tuple[str, str]] = {
    "l.facebook.com": ("/l.php", "u"),
    "lm.facebook.com": ("/l.php", "u"),
    "l.messenger.com": ("/l.php", "u"),
    "l.instagram.com": ("/", "u"),
}


def normalize_evidence_url(value: str) -> str:
    """Return a trimmed absolute http(s) URL or raise ``ValueError``.

    The URL text is otherwise kept exactly as observed (no lower-casing,
    redirect resolution or tracking-parameter removal) because the raw form is
    evidence for later URL analysis.
    """
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    url = value.strip()
    if not url:
        raise ValueError("URL is empty")
    if len(url) > _MAX_URL_LENGTH:
        raise ValueError(f"URL longer than {_MAX_URL_LENGTH} characters")
    if any(ch.isspace() for ch in url) or any(ord(ch) < 32 for ch in url):
        raise ValueError(f"URL contains whitespace or control characters: {url!r}")
    parts = urlsplit(url)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"URL must start with http:// or https://: {url!r}")
    if not parts.hostname:
        raise ValueError(f"URL has no host: {url!r}")
    return url


def extract_urls(text: str | None) -> list[str]:
    """Valid http(s) URLs written in ``text`` (``www.`` links get ``https://``), in order, without duplicates."""
    urls: list[str] = []
    for match in URL_IN_TEXT_RE.findall(text or ""):
        candidate = match.rstrip(_URL_TRAILING)
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        try:
            url = normalize_evidence_url(candidate)
        except ValueError:
            continue
        if url not in urls:
            urls.append(url)
    return urls


def unwrap_link(url: str) -> str:
    """Return the real target of a Facebook/Instagram click-tracking link, else ``url`` unchanged."""
    parts = urlsplit(url)
    wrapper = _LINK_WRAPPERS.get((parts.hostname or "").lower())
    if wrapper is None or parts.path != wrapper[0]:
        return url
    targets = parse_qs(parts.query).get(wrapper[1])
    if not targets:
        return url
    try:
        return normalize_evidence_url(targets[0])
    except ValueError:
        return url


def url_hostname(url: str | None) -> str | None:
    """Lower-case host of ``url`` without a trailing dot (``None`` if there is none)."""
    if not url:
        return None
    host = urlsplit(url).hostname
    return host.rstrip(".").lower() if host else None


@lru_cache(maxsize=1)
def _domain_extractor():
    import tldextract

    # Bundled Public Suffix List snapshot only: no network access, no cache files.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registered_domain(host: str | None) -> str | None:
    """Registrable domain of ``host`` (``login.example.co.uk`` -> ``example.co.uk``); IPs are returned as-is."""
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host.strip("[]")
    except ValueError:
        pass
    result = _domain_extractor()(host)
    domain = getattr(result, "top_domain_under_public_suffix", None) or getattr(result, "registered_domain", "")
    return domain or host
