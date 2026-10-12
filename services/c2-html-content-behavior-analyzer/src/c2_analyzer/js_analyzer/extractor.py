"""Prepare JS sources (inline bodies, event-handler attributes) for parsing.

Part 7: Static JavaScript intent analyzer.
"""

from __future__ import annotations

from c2_analyzer.schemas.parsed_page import ParsedPage


def collect_scripts(page: ParsedPage) -> list[str]:
    """Return analysable JS sources from a ParsedPage."""
    raise NotImplementedError
