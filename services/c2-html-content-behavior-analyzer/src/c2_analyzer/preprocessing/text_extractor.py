"""Extract the title, meta tags, headings, paragraphs and page text (Tasks 5-7).

Part 2: HTML preprocessing pipeline.

Why: the words on a page are the main input of the content models (Parts
5-6). This module separates
- ``visible_text``: what a visitor actually sees, block by block;
- ``hidden_text``: text inside hidden elements (hidden attribute,
  aria-hidden, display:none, visibility:hidden, opacity:0, font-size:0,
  <noscript>, svg <title>). Scammers hide keywords there, so it is kept,
  but separately, so it never pollutes the visible text.
Script, style, template and <head> content is in neither (the title has its
own field).

The tree is walked with an explicit stack instead of recursion, so a page
with thousands of nested <div>s cannot crash Python's recursion limit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup, NavigableString, Tag

from c2_analyzer.preprocessing.settings import PreprocessSettings
from c2_analyzer.preprocessing.text_utils import normalize_block, normalize_inline, truncate
from c2_analyzer.preprocessing.visibility import is_hidden_element
from c2_analyzer.schemas.parsed_page import Heading, MetaTag
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import resolve_url

# Never text: code, CSS, templates, and the <head> (its <title> is a separate field).
SKIP_TAGS = {"script", "style", "template", "head"}
# Text that exists but is not shown on the page -> hidden_text.
HIDDEN_TAGS = {"noscript"}
# A new line before and after these elements (how a browser lays them out).
BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "br", "caption", "dd", "details", "dialog",
    "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3",
    "h4", "h5", "h6", "header", "hr", "legend", "li", "main", "nav", "ol", "option", "p", "pre",
    "section", "summary", "table", "tbody", "thead", "tfoot", "tr", "ul",
}  # fmt: skip
CELL_TAGS = {"td", "th"}  # separated by a space within a row
HEADING_TAGS = ["h1", "h2", "h3", "h4", "h5", "h6"]
REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\"]+)", re.IGNORECASE)
SOURCE_WHITESPACE = re.compile(r"\s+")
CHARSET = re.compile(r"charset\s*=\s*['\"]?([A-Za-z0-9_.:-]+)", re.IGNORECASE)


@dataclass
class PageText:
    visible: str
    hidden: str


def split_text(soup: BeautifulSoup) -> PageText:
    """Walk the tree once and sort every text node into visible or hidden text."""
    visible: list[str] = []
    hidden: list[str] = []
    # (node, inside a hidden element?, inside <svg>?, is this the "leaving the tag" marker?)
    stack: list[tuple] = [(soup, False, False, False)]
    while stack:
        node, in_hidden, in_svg, leaving = stack.pop()
        target = hidden if in_hidden else visible
        if leaving:
            target.append("\n" if node.name in BLOCK_TAGS else " ")
            continue
        if isinstance(node, NavigableString):
            # Only plain text: skips Comment, Doctype, CData, ProcessingInstruction and the
            # Script/Stylesheet/TemplateString subclasses.
            if type(node) is NavigableString:
                # Line breaks in the HTML source are just spaces on screen; only
                # block elements (added below) start a new line.
                target.append(SOURCE_WHITESPACE.sub(" ", str(node)))
            continue
        if not isinstance(node, Tag):
            continue
        name = node.name
        if name in SKIP_TAGS:
            continue
        svg = in_svg or name == "svg"
        hide = (
            in_hidden
            or name in HIDDEN_TAGS
            or (svg and name == "title")
            or (name != "[document]" and is_hidden_element(node))
        )
        if name in BLOCK_TAGS or name in CELL_TAGS:
            (hidden if hide else visible).append("\n" if name in BLOCK_TAGS else " ")
            stack.append((node, hide, svg, True))
        for child in reversed(node.contents):
            stack.append((child, hide, svg, False))
    return PageText(normalize_block("".join(visible)), normalize_block("".join(hidden)))


def extract_title(soup: BeautifulSoup) -> str | None:
    """The page <title> (not an <svg><title> tooltip)."""
    for title in soup.find_all("title"):
        if title.find_parent("svg") is None:
            return normalize_inline(title.get_text()) or None
    return None


def extract_headings(soup: BeautifulSoup) -> list[Heading]:
    """h1-h6 in document order with their level (empty headings are skipped)."""
    headings = []
    for tag in soup.find_all(HEADING_TAGS):
        text = normalize_inline(tag.get_text(" "))
        if text:
            headings.append(Heading(level=int(tag.name[1]), text=text))
    return headings


def extract_paragraphs(soup: BeautifulSoup) -> list[str]:
    """Non-empty <p> texts in document order."""
    texts = (normalize_inline(p.get_text(" ")) for p in soup.find_all("p"))
    return [text for text in texts if text]


def _attr(tag: Tag, name: str) -> str | None:
    value = tag.get(name)
    if isinstance(value, list):
        value = " ".join(value)
    return value.strip() if isinstance(value, str) and value.strip() else None


def extract_meta_tags(
    soup: BeautifulSoup, base_url: str | None, settings: PreprocessSettings
) -> list[MetaTag]:
    """Every <meta> with name/property/http-equiv; a refresh gets its resolved redirect_url."""
    tags = []
    for meta in soup.find_all("meta"):
        name, prop = _attr(meta, "name"), _attr(meta, "property")
        http_equiv = _attr(meta, "http-equiv")
        http_equiv = http_equiv.lower() if http_equiv else None
        content = _attr(meta, "content")
        if not (name or prop or http_equiv):
            continue  # e.g. <meta charset> - stored as charset_declared
        redirect = None
        if http_equiv == "refresh" and content:
            match = REFRESH_URL.search(content)
            if match:
                redirect = mask_url(resolve_url(match.group(1).strip(), base_url))
            content = mask_url(content)
        tags.append(
            MetaTag(
                name=name,
                property=prop,
                http_equiv=http_equiv,
                content=truncate(content, settings.max_meta_content_chars),
                redirect_url=truncate(redirect, settings.max_url_chars),
            )
        )
    return tags


def meta_content(tags: list[MetaTag], name: str) -> str | None:
    """Content of <meta name="..."> (case-insensitive), normalized."""
    for tag in tags:
        if tag.name and tag.name.lower() == name:
            return normalize_inline(tag.content) or None
    return None


def extract_charset(soup: BeautifulSoup) -> str | None:
    """<meta charset="..."> or the charset in <meta http-equiv="Content-Type" content="...">."""
    for meta in soup.find_all("meta"):
        charset = _attr(meta, "charset")
        if charset:
            return charset.lower()
        match = CHARSET.search(_attr(meta, "content") or "")
        if match and (_attr(meta, "http-equiv") or "").lower() == "content-type":
            return match.group(1).lower()
    return None


def extract_lang(soup: BeautifulSoup) -> str | None:
    html = soup.find("html")
    return _attr(html, "lang") if html else None
