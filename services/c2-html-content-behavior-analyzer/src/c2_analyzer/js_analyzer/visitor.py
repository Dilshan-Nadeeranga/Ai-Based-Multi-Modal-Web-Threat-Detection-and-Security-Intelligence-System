"""Generic AST walker over a tree-sitter tree (task 4).

Part 7: Static JavaScript intent analyzer.

Why iterative: obfuscated code can nest thousands of levels deep
(``((((((...))))))``, long ``a.b.c.d...`` chains). A recursive walk would hit
Python's recursion limit and crash on exactly the pages we most need to
analyse. This walker uses tree-sitter's TreeCursor (first child / next
sibling / parent moves), so its memory is constant per level and it never
recurses. Below ``max_depth`` it stops descending and sets ``depth_capped``.

It yields only the node types a caller asks for, in source order, and says
whether a node lies inside an ERROR region (code the parser could not place:
detections there get confidence="low").
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


class AstWalker:
    """Pre-order walk; ``walk()`` yields (node, inside_error) for the wanted node types."""

    def __init__(self, wanted: frozenset[str], max_depth: int = 1500) -> None:
        self.wanted = wanted
        self.max_depth = max_depth
        self.depth_capped = False
        self.nodes_visited = 0

    def walk(self, root: Any) -> Iterator[tuple[Any, bool]]:
        cursor = root.walk()
        depth = 0
        error_depths: list[int] = []  # depths of the ERROR nodes we are inside
        wanted = self.wanted
        while True:
            node = cursor.node
            node_type = node.type
            self.nodes_visited += 1
            if node_type == "ERROR":
                error_depths.append(depth)
            if node_type in wanted:
                yield node, bool(error_depths)
            if depth < self.max_depth:
                if cursor.goto_first_child():
                    depth += 1
                    continue
            elif node.child_count:
                self.depth_capped = True
            # leave this node: next sibling, or climb until a parent has one
            while True:
                if error_depths and error_depths[-1] == depth:
                    error_depths.pop()
                if cursor.goto_next_sibling():
                    break
                if not cursor.goto_parent():
                    return
                depth -= 1
