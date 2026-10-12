"""PII anonymization for collected pages (emails, phones, card numbers, names).

Shared (used across Parts 1-9).
"""

from __future__ import annotations


def anonymize_text(text: str) -> str:
    """Replace PII in ``text`` with placeholder tokens."""
    raise NotImplementedError


def anonymize_html(html: str) -> str:
    """Anonymize PII inside an HTML document, preserving structure."""
    raise NotImplementedError
