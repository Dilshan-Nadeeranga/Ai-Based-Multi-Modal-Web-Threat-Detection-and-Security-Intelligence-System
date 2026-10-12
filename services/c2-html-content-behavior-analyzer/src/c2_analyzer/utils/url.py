"""URL helpers: normalization, host extraction, internal vs external classification.

Shared (used across Parts 1-9).

Why: the same page often appears in feeds with tiny differences
("HTTP://Site.com/login/" vs "http://site.com/login#top"). Normalizing URLs
lets the candidate list detect those as one URL, and comparing hosts lets the
fetcher notice when a scam URL redirected somewhere else.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


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

    Simplification: ``login.bank.example.com`` stays as-is (a real
    "registrable domain" needs the public-suffix list, added in Part 3 if needed).
    """
    host = urlsplit(url.strip()).hostname
    if not host:
        return None
    return host.removeprefix("www.")


def is_external(link: str, page_url: str | None) -> bool:
    """True if ``link`` points to a different domain than ``page_url``."""
    # TODO (Part 3): resolve relative links against page_url, then compare domains.
    raise NotImplementedError
