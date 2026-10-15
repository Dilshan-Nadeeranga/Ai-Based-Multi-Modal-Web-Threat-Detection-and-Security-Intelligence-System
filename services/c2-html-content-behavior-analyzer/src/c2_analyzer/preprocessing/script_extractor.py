"""Extract JavaScript as TEXT: inline scripts, external references, handlers (Tasks 10-11).

Part 2: HTML preprocessing pipeline.

Why: Parts 7-8 analyse what a page's JavaScript would do - statically, from
its source code. This module collects every place JavaScript can hide in
HTML, without running any of it and without downloading external files:

- inline <script> bodies (capped at 500 KB each; ``chars`` keeps the real size);
- external <script src> references (URL, async/defer, integrity, crossorigin);
- event-handler attributes (onclick, onsubmit, onload, ...);
- ``javascript:`` URLs in href/src/action/formaction.

<script> tags that hold DATA are kept apart: JSON-LD / JSON go to
``structured_data``, HTML templates (text/template, handlebars, ...) to
``templates``. Treating them as code would confuse the JS parser in Part 7.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag

from c2_analyzer.preprocessing.settings import PreprocessSettings
from c2_analyzer.preprocessing.text_utils import truncate
from c2_analyzer.schemas.parsed_page import (
    DataBlock,
    EventHandler,
    ExternalScript,
    InlineScript,
    JavascriptUrl,
)
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import is_external, registrable_domain, resolve_url

# type="" values a browser runs as JavaScript (besides anything containing
# "javascript"/"ecmascript", e.g. Cloudflare Rocket Loader's "<hash>-text/javascript").
JS_TYPES = {"", "module", "text/jscript", "text/livescript", "rocketlazyloadscript"}
URL_ATTRIBUTES = ("href", "src", "action", "formaction", "data", "xlink:href")
# Browsers ignore tabs/newlines inside a URL scheme: "java\tscript:" still runs.
URL_NOISE = re.compile(r"[\x00-\x20]+")


def script_kind(type_attr: str) -> str:
    """'js', 'data' (JSON-LD / JSON / importmap) or 'template' (anything else)."""
    value = type_attr.split(";")[0].strip().lower()
    if value in JS_TYPES or "javascript" in value or "ecmascript" in value:
        return "js"
    if "json" in value or value == "importmap" or value == "speculationrules":
        return "data"
    return "template"


def _type(tag: Tag) -> str:
    value = tag.get("type")
    return value.strip() if isinstance(value, str) else ""


def extract_scripts(
    soup: BeautifulSoup, base_url: str | None, page_url: str | None, settings: PreprocessSettings
) -> dict:
    """Inline scripts, data/template blocks and external scripts, in document order."""
    inline, data, templates, external = [], [], [], []
    for tag in soup.find_all("script"):
        type_attr = _type(tag)
        src = tag.get("src")
        if isinstance(src, str) and src.strip():
            # With src, the browser ignores the inline body.
            absolute = resolve_url(src, base_url)
            crossorigin = tag.get("crossorigin")
            external.append(
                ExternalScript(
                    src_raw=truncate(mask_url(src.strip()), settings.max_url_chars),
                    src_abs=truncate(mask_url(absolute), settings.max_url_chars),
                    domain=registrable_domain(absolute),
                    is_external=is_external(absolute, page_url),
                    is_async=tag.has_attr("async"),
                    defer=tag.has_attr("defer"),
                    type=type_attr or None,
                    has_integrity=tag.has_attr("integrity"),
                    crossorigin=crossorigin if isinstance(crossorigin, str) else None,
                )
            )
            continue
        content = tag.string if tag.string is not None else tag.get_text()
        content = str(content)
        kind = script_kind(type_attr)
        if kind == "js":
            if not content.strip():
                continue
            inline.append(
                InlineScript(
                    index=len(inline),
                    type=type_attr or None,
                    chars=len(content),
                    content=truncate(content, settings.max_script_chars),
                    content_truncated=len(content) > settings.max_script_chars,
                    position="head" if tag.find_parent("head") is not None else "body",
                )
            )
        else:
            block = DataBlock(
                type=type_attr,
                chars=len(content),
                content=truncate(content, settings.max_structured_chars),
            )
            (data if kind == "data" else templates).append(block)
    return {
        "scripts_inline": inline,
        "structured_data": data,
        "templates": templates,
        "scripts_external": external,
    }


def extract_handlers(
    soup: BeautifulSoup, settings: PreprocessSettings
) -> tuple[list[EventHandler], list[JavascriptUrl]]:
    """on*= attributes and javascript: URLs on any element."""
    handlers, js_urls = [], []
    for tag in soup.find_all(True):
        for attribute, value in tag.attrs.items():
            if not isinstance(value, str):
                continue
            name = attribute.lower()
            if name.startswith("on") and len(name) > 2 and name[2:].isalpha():
                handlers.append(
                    EventHandler(
                        tag=tag.name,
                        attribute=name,
                        code=truncate(value, settings.max_handler_chars),
                    )
                )
            elif name in URL_ATTRIBUTES:
                compact = URL_NOISE.sub("", value)
                if compact[:11].lower() == "javascript:":
                    code = value.split(":", 1)[1] if ":" in value else ""
                    js_urls.append(
                        JavascriptUrl(
                            tag=tag.name,
                            attribute=name,
                            code=truncate(code.strip(), settings.max_handler_chars),
                        )
                    )
    return handlers, js_urls
