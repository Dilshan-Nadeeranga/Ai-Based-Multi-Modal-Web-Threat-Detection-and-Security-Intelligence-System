"""Remove comments and separate CSS from the document.

Part 2: HTML preprocessing pipeline.
"""

from __future__ import annotations

from typing import Any


def remove_comments(soup: Any) -> Any:
    """Strip HTML comments."""
    raise NotImplementedError


def separate_css(soup: Any) -> tuple[Any, list[str]]:
    """Remove <style>/style attributes; return the soup and extracted CSS."""
    raise NotImplementedError
