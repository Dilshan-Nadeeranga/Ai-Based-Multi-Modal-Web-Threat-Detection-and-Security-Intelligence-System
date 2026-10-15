"""Part 2 pipeline: raw HTML -> ParsedPage (one page). Batch runs are in batch.py.

Part 2: HTML preprocessing pipeline.

Core principle: Part 2 EXTRACTS and ORGANIZES; it never JUDGES. There are no
"suspicious" flags here - deciding what is suspicious is the job of Part 3
(DOM), Part 5 (content) and Parts 7/8 (JavaScript). Part 2 never executes
JavaScript, never makes a network request and never fetches external
scripts or CSS: it only reads the HTML text it is given.

The same ``preprocess`` works for
  (a) a sample from a frozen dataset manifest  -> loader.from_sample
  (b) a raw HTML string + optional page URL    -> preprocess_html (Part 9 API)

Steps (each one timed in meta.step_ms):
  parse     -> BeautifulSoup tree (lxml, fallback html.parser)      Task 2
  base_url  -> <base href> > page URL
  comments  -> removed from the tree, counted                       Task 3
  css       -> <style>/stylesheets summarised, style="" kept         Task 4
  text      -> title, meta tags, headings, paragraphs,
               visible_text, hidden_text                             Tasks 5-7
  forms     -> forms, inputs, labels, buttons                       Task 8
  dom       -> counts, depth, skeleton, links, embedded frames      Task 9
  scripts   -> inline JS, external JS, handlers, javascript: URLs   Tasks 10-11

One failing step never stops the others: its error is written to
meta.errors and its fields keep their empty defaults (a partial result is
more useful than none). Saving (Task 12) is ``to_json`` / batch.py.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from c2_analyzer.preprocessing import (
    cleaner,
    dom_extractor,
    form_extractor,
    script_extractor,
    text_extractor,
)
from c2_analyzer.preprocessing.loader import RawHtml, from_string
from c2_analyzer.preprocessing.parser import parse_html
from c2_analyzer.preprocessing.settings import PreprocessSettings, default_settings
from c2_analyzer.schemas.parsed_page import PageMeta, ParsedPage
from c2_analyzer.utils.pii import mask_url
from c2_analyzer.utils.url import domain_method, resolve_url


def _base_url(soup, page_url: str | None) -> str | None:
    """<base href> (itself resolved against the page URL) wins over the page URL."""
    base = soup.find("base", href=True)
    href = base["href"] if base is not None and isinstance(base["href"], str) else ""
    if href.strip() and not href.strip().lower().startswith(("javascript:", "data:")):
        return resolve_url(href, page_url)
    return page_url


def preprocess(raw: RawHtml, settings: PreprocessSettings | None = None) -> ParsedPage:
    """Run every step on one page and return the ParsedPage (never raises for page content)."""
    settings = settings or default_settings()
    started = time.perf_counter()
    meta = PageMeta(
        sample_id=raw.sample_id,
        page_url=mask_url(raw.page_url),
        dataset_version=raw.dataset_version,
        html_size_bytes=raw.size_bytes,
        source_sha256=raw.sha256,
        encoding=raw.encoding,
        domain_method=domain_method(),
    )
    if raw.truncated:
        meta.truncated = True
        meta.truncation_reasons.append(f"input > {settings.max_html_bytes} bytes")
    fields: dict[str, Any] = {}

    def step(name: str, function: Callable[[], Any]) -> Any:
        """Run one step; on error record it and return None."""
        begin = time.perf_counter()
        try:
            return function()
        except Exception as error:  # noqa: BLE001 - see "one failing step" in the docstring
            meta.errors.append(f"{name}: {type(error).__name__}: {error}")
            return None
        finally:
            meta.step_ms[name] = round((time.perf_counter() - begin) * 1000, 2)

    parsed = step("parse", lambda: parse_html(raw.html))
    if parsed is None:  # cannot happen with the html.parser fallback, but stay safe
        meta.processing_ms = round((time.perf_counter() - started) * 1000, 2)
        return ParsedPage(meta=meta)
    soup = parsed.soup
    meta.parser_used = parsed.parser_used
    meta.errors.extend(parsed.errors)
    page_url = raw.page_url

    base_url = step("base_url", lambda: _base_url(soup, page_url))
    base_url = base_url if base_url is not None else page_url
    meta.base_url = mask_url(base_url)

    comments = step("comments", lambda: cleaner.remove_comments(soup, settings))
    if comments is not None:
        fields["comments"] = comments
    css = step("css", lambda: cleaner.summarize_css(soup, base_url, page_url, settings))
    if css is not None:
        fields["css"] = css

    def text_step() -> dict:
        tags = text_extractor.extract_meta_tags(soup, base_url, settings)
        text = text_extractor.split_text(soup)
        return {
            "title": text_extractor.extract_title(soup),
            "meta_tags": tags,
            "meta_description": text_extractor.meta_content(tags, "description"),
            "meta_keywords": text_extractor.meta_content(tags, "keywords"),
            "lang_attr": text_extractor.extract_lang(soup),
            "charset_declared": text_extractor.extract_charset(soup),
            "headings": text_extractor.extract_headings(soup),
            "paragraphs": text_extractor.extract_paragraphs(soup),
            "visible_text": text.visible,
            "hidden_text": text.hidden,
        }

    def forms_step() -> dict:
        forms, outside = form_extractor.extract_forms(soup, base_url, page_url, settings)
        return {"forms": forms, "inputs_outside_forms": outside}

    def dom_step() -> dict:
        summary, reasons = dom_extractor.dom_summary(soup, base_url, settings)
        if reasons:
            meta.truncated = True
            meta.truncation_reasons.extend(reasons)
        return {
            "dom": summary,
            "links": dom_extractor.extract_links(soup, base_url, page_url, settings),
            "embedded": dom_extractor.extract_embedded(soup, base_url, page_url, settings),
        }

    def scripts_step() -> dict:
        result = script_extractor.extract_scripts(soup, base_url, page_url, settings)
        handlers, js_urls = script_extractor.extract_handlers(soup, settings)
        return {**result, "event_handlers": handlers, "javascript_urls": js_urls}

    for name, function in (
        ("text", text_step),
        ("forms", forms_step),
        ("dom", dom_step),
        ("scripts", scripts_step),
    ):
        result = step(name, function)
        if result is not None:
            fields.update(result)

    meta.processing_ms = round((time.perf_counter() - started) * 1000, 2)
    return ParsedPage(meta=meta, **fields)


def preprocess_html(
    html: str, page_url: str | None = None, settings: PreprocessSettings | None = None
) -> ParsedPage:
    """Convenience for the API (Part 9): an HTML string and an optional URL."""
    return preprocess(from_string(html, page_url, settings), settings)


def to_json(page: ParsedPage) -> str:
    """The JSON stored on disk (UTF-8 text, Sinhala/Tamil kept readable, aliases used)."""
    return page.model_dump_json(by_alias=True, indent=1)
