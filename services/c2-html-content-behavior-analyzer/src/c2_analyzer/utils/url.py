"""URL helpers: domain extraction, internal vs external classification.

Shared (used across Parts 1-9).
"""

from __future__ import annotations


def extract_domain(url: str) -> str | None:
    """Return the registrable domain of ``url``."""
    raise NotImplementedError


def is_external(link: str, page_url: str | None) -> bool:
    """True if ``link`` points to a different domain than ``page_url``."""
    raise NotImplementedError
