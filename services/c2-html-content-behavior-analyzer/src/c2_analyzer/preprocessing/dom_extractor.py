"""Extract the DOM structure, links and embedded frames/objects (Task 9).

Part 2: HTML preprocessing pipeline.

Why: phishing kits are copied from site to site, so their STRUCTURE (which
tags, how deep, how many) is a strong signal even when the text changes.
Part 3 builds its features from this summary:

- ``node_count`` (elements + non-empty text nodes), ``element_count``,
  ``max_depth`` and ``tag_counts`` - over the whole document;
- ``skeleton``: the element tree with only id, first 2 classes, type, name and
  the domain of href - capped at 3000 nodes / depth 40, so one giant page
  cannot produce a giant JSON file (meta.truncated is set when capped);
- ``links``: every <a href>, resolved, with its registrable domain;
- ``embedded``: iframes, frames, objects and embeds, with their size and
  whether they are hidden.

The tree is walked with an explicit stack (no recursion limit problems).
"""

from __future__ import annotations

from collections import Counter

from bs4 import BeautifulSoup, NavigableString, Tag

from c2_analyzer.preprocessing.settings import PreprocessSettings
from c2_analyzer.preprocessing.text_utils import normalize_inline, truncate
from c2_analyzer.preprocessing.visibility import is_hidden_in_tree, zero_size
from c2_analyzer.schemas.parsed_page import DomSummary, Embedded, Link, SkeletonNode
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import is_external, registrable_domain, resolve_url

EMBED_SOURCES = {"iframe": "src", "frame": "src", "object": "data", "embed": "src"}
MAX_ATTRIBUTE_CHARS = 100


def _attr(tag: Tag, name: str) -> str | None:
    value = tag.get(name)
    if isinstance(value, list):
        value = " ".join(value)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _skeleton_node(tag: Tag, base_url: str | None) -> dict:
    """The few attributes kept in the skeleton (no text, no full URLs)."""
    node: dict = {"tag": tag.name, "children": []}
    if value := _attr(tag, "id"):
        node["id"] = value[:MAX_ATTRIBUTE_CHARS]
    classes = tag.get("class")
    if isinstance(classes, list) and classes:
        node["class"] = [name[:MAX_ATTRIBUTE_CHARS] for name in classes[:2]]
    for name in ("type", "name"):
        if value := _attr(tag, name):
            node[name] = value[:MAX_ATTRIBUTE_CHARS]
    if href := _attr(tag, "href"):
        if domain := registrable_domain(resolve_url(href, base_url)):
            node["href_domain"] = domain
    return node


def dom_summary(
    soup: BeautifulSoup, base_url: str | None, settings: PreprocessSettings
) -> tuple[DomSummary, list[str]]:
    """Counts over the whole tree + the capped skeleton -> (summary, truncation reasons)."""
    tag_counts: Counter = Counter()
    text_nodes = 0
    max_depth = 0
    skeleton_nodes = 0
    reasons: set[str] = set()
    roots: list[dict] = []

    # (node, depth, parent skeleton dict or None, may this node enter the skeleton?)
    stack: list[tuple] = [(child, 1, None, True) for child in reversed(soup.contents)]
    while stack:
        node, depth, parent, in_skeleton = stack.pop()
        if isinstance(node, NavigableString):
            if type(node) is NavigableString and node.strip():
                text_nodes += 1
            continue
        if not isinstance(node, Tag):
            continue
        tag_counts[node.name] += 1
        max_depth = max(max_depth, depth)

        entry = None
        if in_skeleton:
            if depth > settings.skeleton_max_depth:
                reasons.add(f"skeleton depth > {settings.skeleton_max_depth}")
            elif skeleton_nodes >= settings.skeleton_max_nodes:
                reasons.add(f"skeleton nodes > {settings.skeleton_max_nodes}")
            else:
                entry = _skeleton_node(node, base_url)
                skeleton_nodes += 1
                (parent["children"] if parent is not None else roots).append(entry)
        for child in reversed(node.contents):
            stack.append((child, depth + 1, entry, entry is not None))

    element_count = sum(tag_counts.values())
    root = (
        roots[0]
        if len(roots) == 1
        else ({"tag": "#document", "children": roots} if roots else None)
    )
    summary = DomSummary(
        node_count=element_count + text_nodes,
        element_count=element_count,
        max_depth=max_depth,
        tag_counts=dict(tag_counts.most_common()),
        skeleton=SkeletonNode.model_validate(root) if root else None,
    )
    return summary, sorted(reasons)


def extract_links(
    soup: BeautifulSoup, base_url: str | None, page_url: str | None, settings: PreprocessSettings
) -> list[Link]:
    """Every <a href> with its absolute URL, text and domain."""
    links = []
    for anchor in soup.find_all("a", href=True):
        raw = anchor["href"] if isinstance(anchor["href"], str) else ""
        lowered = raw.strip().lower()
        absolute = None if lowered.startswith("javascript:") else resolve_url(raw, base_url)
        rel = anchor.get("rel")
        links.append(
            Link(
                href_raw=truncate(mask_url(raw.strip()), settings.max_url_chars) or "",
                href_abs=truncate(mask_url(absolute), settings.max_url_chars),
                text=truncate(normalize_inline(anchor.get_text(" ")), settings.max_link_text_chars)
                or "",
                domain=registrable_domain(absolute),
                is_external=is_external(absolute, page_url),
                rel=" ".join(rel) if isinstance(rel, list) else _attr(anchor, "rel"),
                target=_attr(anchor, "target"),
            )
        )
    return links


def extract_embedded(
    soup: BeautifulSoup, base_url: str | None, page_url: str | None, settings: PreprocessSettings
) -> list[Embedded]:
    """iframes, frames, objects and embeds (their content is never loaded)."""
    items = []
    hidden_cache: dict[int, bool] = {}  # see visibility.is_hidden_in_tree
    for tag in soup.find_all(list(EMBED_SOURCES)):
        source = _attr(tag, EMBED_SOURCES[tag.name])
        absolute = resolve_url(source, base_url)
        items.append(
            Embedded(
                tag=tag.name,
                src_abs=truncate(mask_url(absolute), settings.max_url_chars),
                domain=registrable_domain(absolute),
                is_external=is_external(absolute, page_url),
                width=_attr(tag, "width"),
                height=_attr(tag, "height"),
                hidden=zero_size(tag) or is_hidden_in_tree(tag, cache=hidden_cache),
            )
        )
    return items
