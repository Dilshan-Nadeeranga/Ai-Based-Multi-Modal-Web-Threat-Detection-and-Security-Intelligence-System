"""Sanitized preview of a sample, for looking at its LAYOUT when text is not enough.

Part 1: Multilingual dataset preparation (Batch C, Task 12 helper).

Why: sometimes the label only becomes clear from how a page looks (a fake
bank login vs. a news article). Opening the ORIGINAL file in a browser is
dangerous: it runs the scam's JavaScript, loads resources from the attacker's
server (telling them who looked) and its forms really submit. This module
writes a copy with everything active removed, so it can be opened safely.

What is removed / neutralised:
  * <script>, <iframe>, <frame>, <base>, <link>, <meta> (incl. meta refresh)
    and HTML comments - with their content
  * <object>, <embed>, <applet>, <frameset>, <portal>, <noscript> - the tag
    only; the HTML inside is kept and cleaned like the rest
  * every on* event attribute (onclick, onload, ...)
  * every attribute that loads or goes to a URL (src, srcset, href, action,
    formaction, poster, data, background, ...) - links and form actions are
    set to "#" so they go nowhere
  * url(...) and @import inside CSS
On top of that a strict Content-Security-Policy meta tag tells the browser to
load nothing at all (default-src 'none') and to submit no form, as a second
line of defence if something slipped through.

The ORIGINAL file in data/raw/ must still never be opened in a browser.
"""

from __future__ import annotations

import html as html_lib
import re
from pathlib import Path

from bs4 import BeautifulSoup, Comment

from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import read_html

# Removed together with everything inside them (their content is code or a URL).
DROP_TAGS = ("script", "iframe", "frame", "base", "link", "meta")
# The tag itself is removed but its inner HTML is kept and cleaned like the
# rest (e.g. an <object>'s fallback text). The parser also treats <embed> as a
# container, so dropping it whole would silently delete the page after it.
UNWRAP_TAGS = ("object", "embed", "applet", "frameset", "portal", "noscript")
# Attributes that load something or navigate somewhere.
URL_ATTRIBUTES = {
    "src", "srcset", "href", "xlink:href", "action", "formaction", "poster", "data",
    "background", "lowsrc", "dynsrc", "ping", "codebase", "cite", "longdesc",
    "manifest", "icon", "imagesrcset", "srcdoc",
}  # fmt: skip
CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"
CSS_URL = re.compile(r"url\s*\([^)]*\)", re.IGNORECASE)
CSS_IMPORT = re.compile(r"@import[^;]*;?", re.IGNORECASE)
CSS_EXPRESSION = re.compile(r"expression\s*\(", re.IGNORECASE)  # old IE: JavaScript in CSS

BANNER_STYLE = (
    "position:sticky;top:0;z-index:2147483647;background:#c00;color:#fff;"
    "font:bold 22px sans-serif;padding:14px;text-align:center;border-bottom:4px solid #600"
)


def clean_css(css: str) -> str:
    css = CSS_IMPORT.sub("", css)
    css = CSS_URL.sub("none", css)
    return CSS_EXPRESSION.sub("none(", css)


def sanitize_html(page_html: str, sample_id: str) -> str:
    """Return a copy of the page that cannot run code, load anything or submit anything."""
    soup = BeautifulSoup(page_html, "lxml")

    for comment in soup.find_all(string=lambda node: isinstance(node, Comment)):
        comment.extract()  # comments can hide old-IE conditional <script> blocks
    for tag in soup(DROP_TAGS):
        tag.decompose()
    for tag in soup(UNWRAP_TAGS):
        tag.unwrap()

    for tag in soup.find_all(True):
        for name in list(tag.attrs):
            lowered = name.lower()
            if lowered.startswith("on") or lowered in URL_ATTRIBUTES:
                del tag.attrs[name]
            elif lowered == "style":
                tag.attrs[name] = clean_css(str(tag.attrs[name]))
            elif "javascript:" in str(tag.attrs[name]).lower().replace(" ", ""):
                del tag.attrs[name]
        if tag.name in ("a", "area"):
            tag.attrs["href"] = "#"
        if tag.name == "form":
            tag.attrs["action"] = "#"
        if tag.name == "style":
            tag.string = clean_css(tag.get_text())  # also flattens any odd children

    # Rebuild a minimal document around the cleaned body.
    head_title = soup.title.get_text(" ") if soup.title else ""
    body = soup.body or soup
    body_html = "".join(str(child) for child in body.children)
    styles = "".join(
        str(style) for style in soup.find_all("style") if not style.find_parent("body")
    )
    safe_id = html_lib.escape(sample_id)
    return (
        "<!doctype html>\n<html>\n<head>\n"
        '<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">\n'
        f"<title>SANITIZED {safe_id} - {html_lib.escape(head_title)}</title>\n"
        f"{styles}\n</head>\n<body>\n"
        f'<div style="{BANNER_STYLE}">SANITIZED PREVIEW &ndash; SAMPLE {safe_id}<br>'
        '<span style="font-size:14px">Scripts, links, forms and outside resources removed. '
        "Never open the original file from data/raw.</span></div>\n"
        f"{body_html}\n</body>\n</html>\n"
    )


def write_safe_preview(store: MetadataStore, sample_id: str, out_dir: Path | None = None) -> Path:
    """Write data/metadata/review/<sample_id>_safe.html and return its path."""
    record = store.get(sample_id)  # validated id -> safe to use in a file name
    source = store.raw_dir / record.file_path
    if not source.is_file():
        raise FileNotFoundError(f"File not found: {source} (quarantined by antivirus?)")
    out_dir = out_dir or store.csv_path.parent / "review"
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{sample_id}_safe.html"
    target.write_text(sanitize_html(read_html(source), sample_id), encoding="utf-8")
    return target
