"""Parse JS with esprima; fail gracefully on unparsable code.

Part 7: Static JavaScript intent analyzer.
"""

from __future__ import annotations

from typing import Any


def parse_js(source: str) -> Any | None:
    """Return an esprima AST, or ``None`` if the code cannot be parsed."""
    raise NotImplementedError
