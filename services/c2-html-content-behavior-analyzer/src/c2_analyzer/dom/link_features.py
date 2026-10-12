"""Link features: internal vs external link ratio.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from c2_analyzer.schemas.parsed_page import ParsedPage


def link_features(page: ParsedPage) -> dict[str, float]:
    """Internal/external link counts and external ratio."""
    raise NotImplementedError
