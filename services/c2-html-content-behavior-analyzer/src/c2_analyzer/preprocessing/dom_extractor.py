"""Extract links, iframes and meta tags.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from typing import Any


def extract_links(soup: Any) -> list[str]:
    """All href targets."""
    raise NotImplementedError


def extract_iframes(soup: Any) -> list[str]:
    """All iframe src values."""
    raise NotImplementedError


def extract_meta(soup: Any) -> dict[str, str]:
    """Meta tags (name/property -> content), incl. refresh redirects."""
    raise NotImplementedError
