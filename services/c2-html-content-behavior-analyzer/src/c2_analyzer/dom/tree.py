"""DOM tree statistics: node count, max depth.

Part 3: DOM structural analysis.
"""

from __future__ import annotations

from typing import Any


def node_count(soup: Any) -> int:
    """Number of element nodes."""
    raise NotImplementedError


def max_depth(soup: Any) -> int:
    """Maximum nesting depth of the DOM tree."""
    raise NotImplementedError
