"""PageView: a light, text-only summary of one saved HTML page.

Part 1: Multilingual dataset preparation (Batch C).

Why: the quality checker, the near-duplicate finder, the review tool and the
peer-review export all need the same few facts about a page - its title,
visible text, tag sequence, forms and outside domains. Parsing the page once
here keeps those tools consistent with each other.

Safety: the HTML is only parsed as text (BeautifulSoup). Nothing is rendered
and no script runs. Part 2 (preprocessing) builds the full parser used for
training; this summary is just enough to clean and review the dataset.
"""

from __future__ import annotations

import re
import unicodedata
import warnings
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

from c2_analyzer.dataset.fetcher import decode_html
from c2_analyzer.utils.url import extract_domain

# Some pages are XHTML (start with <?xml ...>). Reading them as HTML - like a
# browser does - is exactly what we want, so bs4's warning about it is noise.
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Tags whose text is never shown to the visitor.
INVISIBLE_TAGS = ("script", "style", "noscript", "template", "head")
# (tag, attribute) pairs that point at another URL.
LINK_ATTRIBUTES = (
    ("a", "href"),
    ("link", "href"),
    ("form", "action"),
    ("script", "src"),
    ("img", "src"),
    ("iframe", "src"),
)
# Bidirectional-override characters can make text display differently from
# what it really is, so they are removed before printing.
BIDI_CONTROLS = set("‪‫‬‭‮⁦⁧⁨⁩")


@dataclass
class FormInfo:
    """One <form>: where it sends data, how, and which kinds of inputs it has."""

    action: str
    method: str
    input_types: list[str]

    def summary(self) -> str:
        """E.g. 'POST https://evil.example/post.php (email, password, hidden x2)'."""
        counts = Counter(self.input_types)
        inputs = ", ".join(
            name if count == 1 else f"{name} x{count}" for name, count in counts.items()
        )
        return f"{self.method} {self.action or '(same page)'} ({inputs or 'no inputs'})"


@dataclass
class PageView:
    """The facts about a page that Part 1 needs (see module docstring)."""

    title: str
    text: str  # visible text, whitespace collapsed to single spaces
    tags: list[str]  # tag names in document order
    forms: list[FormInfo] = field(default_factory=list)
    script_count: int = 0
    iframe_count: int = 0
    external_domains: Counter = field(default_factory=Counter)
    loose_input_types: list[str] = field(default_factory=list)  # inputs outside any <form>

    @property
    def element_count(self) -> int:
        return len(self.tags)

    @property
    def input_count(self) -> int:
        return len(self.loose_input_types) + sum(len(form.input_types) for form in self.forms)

    @property
    def has_password_field(self) -> bool:
        return "password" in self.loose_input_types or any(
            "password" in form.input_types for form in self.forms
        )


def collapse_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_page(html: str, page_url: str | None = None) -> PageView:
    """Build a PageView from HTML text. ``page_url`` resolves relative links."""
    soup = BeautifulSoup(html, "lxml")
    tags = [tag.name for tag in soup.find_all(True)]
    title = collapse_spaces(soup.title.get_text(" ")) if soup.title else ""

    forms = []
    for form in soup.find_all("form"):
        forms.append(
            FormInfo(
                action=_absolute(form.get("action", ""), page_url),
                method=str(form.get("method", "GET")).upper(),
                input_types=[_input_type(item) for item in form.find_all(["input", "textarea"])],
            )
        )
    loose = [_input_type(item) for item in soup.find_all("input") if not item.find_parent("form")]

    own_domain = extract_domain(page_url or "")
    domains: Counter = Counter()
    for tag_name, attribute in LINK_ATTRIBUTES:
        for tag in soup.find_all(tag_name):
            target = _absolute(tag.get(attribute, ""), page_url)
            domain = extract_domain(target) if target.startswith(("http://", "https://")) else ""
            if domain and domain != own_domain:
                domains[domain] += 1

    script_count = len(soup.find_all("script"))
    iframe_count = len(soup.find_all(["iframe", "frame"]))
    for tag in soup(INVISIBLE_TAGS):
        tag.decompose()
    text = collapse_spaces(f"{title} {soup.get_text(' ')}")

    return PageView(
        title=title,
        text=text,
        tags=tags,
        forms=forms,
        script_count=script_count,
        iframe_count=iframe_count,
        external_domains=domains,
        loose_input_types=loose,
    )


def read_html(path: Path) -> str:
    """Read a saved page as text (BOM / <meta charset> aware, never crashes on bad bytes)."""
    html, _ = decode_html(Path(path).read_bytes())
    return html


def load_page(path: Path, page_url: str | None = None) -> PageView:
    return parse_page(read_html(path), page_url)


def terminal_safe(text: str) -> str:
    """Remove control characters a malicious page could use to mess with the terminal.

    ANSI escape sequences (ESC [ ...) can move the cursor, hide text or change
    the window title. Newlines and tabs are kept; zero-width joiners used by
    Sinhala/Tamil are kept (they are format characters, not controls).
    """
    return "".join(
        char
        for char in text
        if char in "\n\t" or (unicodedata.category(char) != "Cc" and char not in BIDI_CONTROLS)
    )


def _absolute(url: object, page_url: str | None) -> str:
    url = str(url or "").strip()
    if not url or not page_url:
        return url
    try:
        return urljoin(page_url, url)
    except ValueError:  # malformed URL in a scam page must not crash anything
        return url


def _input_type(tag) -> str:
    if tag.name == "textarea":
        return "textarea"
    return str(tag.get("type", "text")).strip().lower() or "text"
