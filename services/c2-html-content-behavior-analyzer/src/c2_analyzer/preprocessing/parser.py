"""Parse HTML into a BeautifulSoup tree that never crashes (Task 2).

Part 2: HTML preprocessing pipeline.

Why: scam pages are often broken on purpose (unclosed tags, garbage bytes,
odd nesting). "lxml" is fast and repairs broken markup like a browser does;
if it ever raises, Python's built-in "html.parser" is used instead, and if
even that fails we continue with an empty document. The parser that was
used and any error are recorded in ParsedPage.meta.

Parsing only builds a tree in memory: no script runs and no URL is fetched.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

# XHTML pages start with <?xml ...>; reading them as HTML is what a browser does.
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

PARSERS = ("lxml", "html.parser")


@dataclass
class ParseResult:
    soup: BeautifulSoup
    parser_used: str
    errors: list[str] = field(default_factory=list)


def parse_html(html: str, parsers: tuple[str, ...] = PARSERS) -> ParseResult:
    """Parse with the first parser that works; record the failures of the others."""
    # A NUL character makes some parsers stop early; browsers show U+FFFD instead.
    html = html.replace("\x00", "�")
    errors = []
    for name in parsers:
        try:
            return ParseResult(BeautifulSoup(html, name), name, errors)
        except Exception as error:  # noqa: BLE001 - any parser bug must not stop the pipeline
            errors.append(f"parser {name} failed: {type(error).__name__}: {error}")
    return ParseResult(BeautifulSoup("", "html.parser"), "none", errors)
