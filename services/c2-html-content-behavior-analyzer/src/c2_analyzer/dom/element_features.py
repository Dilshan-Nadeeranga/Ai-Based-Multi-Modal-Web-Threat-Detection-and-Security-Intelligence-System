"""Element features: iframes, scripts, hidden elements.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from typing import Any

from c2_analyzer.schemas.parsed_page import ParsedPage


def element_features(soup: Any, page: ParsedPage) -> dict[str, int]:
    """Counts of iframes (incl. hidden), scripts (incl. external) and hidden elements."""
    raise NotImplementedError
