"""Generic AST walker.

Part 7: Static JavaScript intent analyzer.
"""

from __future__ import annotations

from typing import Any


class AstVisitor:
    """Depth-first visitor dispatching ``visit_<NodeType>`` methods."""

    def visit(self, node: Any) -> None:
        """Visit ``node`` and its children."""
        raise NotImplementedError
