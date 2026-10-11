"""Validation of URLs recorded as evidence (they are never fetched here)."""

from __future__ import annotations

from urllib.parse import urlsplit

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_URL_LENGTH = 2048


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
