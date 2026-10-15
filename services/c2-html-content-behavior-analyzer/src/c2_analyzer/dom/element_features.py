"""Element features: iframes, script elements and hidden elements (tasks 9-11).

Part 3: DOM structural analysis.

Why:
- iframes can load another site invisibly (click-jacking, tracking, drive-by
  downloads) - counted from Part 2's ``embedded`` list;
- scripts are COUNTED here (how many, from how many domains, how much inline
  code, how many on*= handlers); what the code DOES is Part 7's job;
- hidden elements are counted from the raw HTML tree, because Part 2 keeps
  hidden TEXT but not a per-element count.

Hidden element = an element that hides ITSELF (descendants of a hidden element
are not counted again - the count measures hiding tricks, not block sizes):
  Part 2 rules (``visibility.is_hidden_element``): hidden attribute,
  aria-hidden="true", inline display:none / visibility:hidden|collapse /
  opacity:0 / font-size:0; plus Part 2's ``zero_size`` (width/height 0) and,
  new here, off-screen positioning (position absolute/fixed with
  left/top/right/bottom <= -offscreen_px, or text-indent <= -offscreen_px).
<input type=hidden> has its own feature, and tags that are never visible
(script, style, meta, head, ...) are ignored. CSS rules in <style> blocks are
not evaluated (same documented limit as Part 2).
"""

from __future__ import annotations

import re
from collections import Counter

from bs4 import BeautifulSoup, Tag

from c2_analyzer.dom.dictionary import load_dictionary
from c2_analyzer.preprocessing.visibility import inline_style, is_hidden_element, zero_size
from c2_analyzer.schemas.parsed_page import ParsedPage

FRAME_TAGS = ("iframe", "frame")
PIXELS = re.compile(r"^(-?\d+(?:\.\d+)?)(px)?$")
OFFSET_PROPERTIES = ("left", "top", "right", "bottom")


def _pixels(value: str | None) -> float | None:
    match = PIXELS.match((value or "").replace(" ", ""))
    return float(match.group(1)) if match else None


def offscreen(style: dict[str, str], limit: float) -> bool:
    """Positioned far outside the viewport, or text pushed out with text-indent."""
    indent = _pixels(style.get("text-indent"))
    if indent is not None and indent <= -limit:
        return True
    if style.get("position") not in ("absolute", "fixed"):
        return False
    return any(
        (value := _pixels(style.get(name))) is not None and value <= -limit
        for name in OFFSET_PROPERTIES
    )


def hiding_method(tag: Tag, limit: float) -> str | None:
    """How this element hides itself (None = it does not)."""
    if tag.has_attr("hidden"):
        return "hidden attribute"
    if str(tag.get("aria-hidden", "")).strip().lower() == "true":
        return "aria-hidden"
    style = inline_style(tag)
    if is_hidden_element(tag):  # Part 2: display / visibility / opacity / font-size
        return "inline style"
    if zero_size(tag):
        return "zero size"
    if offscreen(style, limit):
        return "off-screen"
    return None


def hidden_elements(soup: BeautifulSoup) -> tuple[int, Counter]:
    """(count, methods) of elements hidden by their own markup (iterative walk)."""
    dictionary = load_dictionary()
    methods: Counter = Counter()
    stack = [child for child in reversed(soup.contents) if isinstance(child, Tag)]
    while stack:
        tag = stack.pop()
        if tag.name in dictionary.never_visible_tags:
            if tag.name == "html":  # never counted itself, but its body is
                stack.extend(c for c in reversed(tag.contents) if isinstance(c, Tag))
            continue
        is_hidden_input = tag.name == "input" and str(tag.get("type", "")).lower() == "hidden"
        method = None if is_hidden_input else hiding_method(tag, dictionary.offscreen_px)
        if method is not None:
            methods[method] += 1
            continue  # its descendants are hidden too - not counted again
        stack.extend(child for child in reversed(tag.contents) if isinstance(child, Tag))
    return sum(methods.values()), methods


def element_features(
    page: ParsedPage, page_url_known: bool, soup: BeautifulSoup | None
) -> tuple[dict, dict, list[str]]:
    """Groups iframes, scripts, hidden_elements -> (features, details, warnings)."""
    warnings = []
    frames = [item for item in page.embedded if item.tag in FRAME_TAGS]
    external_frames = [item for item in frames if item.is_external] if page_url_known else []
    hidden_frames = [item for item in frames if item.hidden]
    script_domains = (
        {s.domain for s in page.scripts_external if s.is_external and s.domain}
        if page_url_known
        else set()
    )
    if soup is not None:
        hidden_count, methods = hidden_elements(soup)
    else:
        hidden_count, methods = 0, Counter()
        warnings.append("hidden_element_count = 0: raw HTML not available")
    visible_chars, hidden_chars = len(page.visible_text), len(page.hidden_text)

    features = {
        "iframe_count": len(frames),
        "external_iframe_count": len(external_frames),
        "hidden_iframe_count": len(hidden_frames),
        "inline_script_count": len(page.scripts_inline),
        "external_script_count": len(page.scripts_external),
        "external_script_domain_count": len(script_domains),
        "inline_script_chars_total": sum(script.chars for script in page.scripts_inline),
        "event_handler_count": len(page.event_handlers),
        "javascript_url_count": len(page.javascript_urls),
        "hidden_element_count": hidden_count,
        "hidden_text_chars": hidden_chars,
        "hidden_text_ratio": (
            round(hidden_chars / (hidden_chars + visible_chars), 4)
            if hidden_chars + visible_chars
            else 0.0
        ),
    }
    details = {
        "hidden_iframe_count": {"sources": [f.src_abs for f in hidden_frames][:5]},
        "external_script_domain_count": {"domains": sorted(script_domains)[:10]},
        "javascript_url_count": {"examples": [j.code[:80] for j in page.javascript_urls][:3]},
        "event_handler_count": {
            "attributes": dict(Counter(h.attribute for h in page.event_handlers).most_common(5))
        },
        "hidden_element_count": {
            "methods": ", ".join(f"{name} {n}" for name, n in methods.most_common()),
            "by_method": dict(methods),
        },
        "hidden_text_ratio": {
            "percent": round(100 * features["hidden_text_ratio"]),
            "hidden_chars": hidden_chars,
        },
    }
    return features, details, warnings
