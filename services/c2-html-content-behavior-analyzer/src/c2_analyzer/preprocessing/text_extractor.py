"""Extract visible text, title, headings and paragraphs.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from typing import Any


def extract_title(soup: Any) -> str | None:
    """Page <title>."""
    raise NotImplementedError


def extract_headings(soup: Any) -> list[str]:
    """Text of h1-h6."""
    raise NotImplementedError


def extract_paragraphs(soup: Any) -> list[str]:
    """Text of <p> blocks."""
    raise NotImplementedError


def extract_visible_text(soup: Any) -> str:
    """All user-visible text (excluding script/style/hidden)."""
    raise NotImplementedError
