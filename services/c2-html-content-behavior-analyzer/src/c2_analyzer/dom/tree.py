"""DOM tree parser and tree metrics (tasks 1-3).

Part 3: DOM structural analysis.

Why: Part 2 stores node/element counts, max depth and tag counts, but not the
whole tree (only a capped skeleton). Average depth and the leaf ratio need
every element, so the raw HTML is parsed again here - with Part 2's own
``parse_html`` (same lxml repair rules, so the counts agree with ParsedPage).

Definitions (identical to Part 2's dom_summary):
- depth: children of the document are depth 1 (``<html>`` = 1);
- node_count = elements + non-empty plain text nodes (comments are not nodes);
- leaf = an element without child elements.

The walk uses an explicit stack, so a page with 100,000 nested <div>s cannot
hit Python's recursion limit. If no raw HTML is available, the metrics are
taken from the ParsedPage (avg depth / leaves from the skeleton - exact unless
the skeleton was capped, which the caller reports as a warning).
"""

from __future__ import annotations

from dataclasses import dataclass

from bs4 import BeautifulSoup, NavigableString, Tag

from c2_analyzer.preprocessing.parser import parse_html
from c2_analyzer.schemas.parsed_page import ParsedPage


@dataclass(frozen=True)
class DomTree:
    """Tree metrics of one page."""

    node_count: int
    element_count: int
    max_depth: int
    avg_depth: float
    leaf_ratio: float
    distinct_tag_count: int


def parse(html: str) -> BeautifulSoup:
    """Task 1: HTML -> tree, with Part 2's never-crashing parser (lxml, then html.parser)."""
    return parse_html(html).soup


def measure(soup: BeautifulSoup) -> DomTree:
    """Tasks 2-3: walk the tree once (iteratively) and measure it."""
    elements = text_nodes = leaves = depth_sum = max_depth = 0
    tags: set[str] = set()
    stack: list[tuple] = [(child, 1) for child in reversed(soup.contents)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, NavigableString):
            if type(node) is NavigableString and node.strip():
                text_nodes += 1
            continue
        if not isinstance(node, Tag):
            continue
        elements += 1
        tags.add(node.name)
        depth_sum += depth
        max_depth = max(max_depth, depth)
        has_child_element = False
        for child in reversed(node.contents):
            if isinstance(child, Tag):
                has_child_element = True
            stack.append((child, depth + 1))
        leaves += not has_child_element
    return DomTree(
        node_count=elements + text_nodes,
        element_count=elements,
        max_depth=max_depth,
        avg_depth=round(depth_sum / elements, 4) if elements else 0.0,
        leaf_ratio=round(leaves / elements, 4) if elements else 0.0,
        distinct_tag_count=len(tags),
    )


def from_parsed_page(page: ParsedPage) -> DomTree:
    """Fallback without raw HTML: Part 2's counts + depth/leaves from the skeleton."""
    dom = page.dom
    depth_sum = leaves = count = 0
    if dom.skeleton is not None:
        # The skeleton root may be a synthetic "#document" holding several roots.
        start = dom.skeleton.children if dom.skeleton.tag == "#document" else [dom.skeleton]
        stack = [(node, 1) for node in start]
        while stack:
            node, depth = stack.pop()
            count += 1
            depth_sum += depth
            leaves += not node.children
            stack.extend((child, depth + 1) for child in node.children)
    return DomTree(
        node_count=dom.node_count,
        element_count=dom.element_count,
        max_depth=dom.max_depth,
        avg_depth=round(depth_sum / count, 4) if count else 0.0,
        leaf_ratio=round(leaves / count, 4) if count else 0.0,
        distinct_tag_count=len(dom.tag_counts),
    )
