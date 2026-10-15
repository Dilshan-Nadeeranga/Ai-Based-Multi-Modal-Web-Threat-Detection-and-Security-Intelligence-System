"""Link and meta/resource features: internal vs external links, null links, refresh (task 12).

Part 3: DOM structural analysis.

Why: a phishing kit copies the look of a brand's site, but its menu items
either point to the REAL brand (many external links) or nowhere ("#",
javascript:). Genuine sites mostly link to themselves. Part 2 already
resolved every link and decided internal/external against the page URL;
this module counts.

Definitions:
- null link: href empty, "#", "#..." or javascript: (goes nowhere);
- web link: a non-null link with an http(s) domain; internal + external = web links;
- external_link_ratio = external / web links (0.0 when there are none).
If the page URL is unknown, internal/external cannot be decided: those
features are 0 (the caller sets base_url_known = 0).
"""

from __future__ import annotations

from collections import Counter

from c2_analyzer.schemas.parsed_page import Link, ParsedPage
from c2_analyzer.utils.url import is_external


def _ratio(part: float, whole: float) -> float:
    return round(part / whole, 4) if whole else 0.0


def is_null_link(link: Link) -> bool:
    raw = (link.href_raw or "").strip().lower()
    return raw == "" or raw.startswith("#") or raw.startswith("javascript:")


def link_features(page: ParsedPage, page_url_known: bool) -> tuple[dict, dict]:
    """Groups links and meta_resources -> (features, details)."""
    links = page.links
    null = [link for link in links if is_null_link(link)]
    web = [link for link in links if not is_null_link(link) and link.domain]
    external = [link for link in web if link.is_external] if page_url_known else []
    internal = [link for link in web if not link.is_external] if page_url_known else []
    domains = Counter(link.domain for link in external)

    refresh = page.meta_refresh
    refresh_external = bool(
        page_url_known
        and refresh is not None
        and refresh.redirect_url
        and is_external(refresh.redirect_url, page.meta.page_url)
    )
    sheets = page.css.external_stylesheets
    external_sheets = sum(sheet.is_external for sheet in sheets) if page_url_known else 0

    features = {
        "link_count": len(links),
        "internal_link_count": len(internal),
        "external_link_count": len(external),
        "external_link_ratio": _ratio(len(external), len(internal) + len(external)),
        "null_link_count": len(null),
        "null_link_ratio": _ratio(len(null), len(links)),
        "distinct_external_domains": len(domains),
        "has_meta_refresh": int(refresh is not None),
        "meta_refresh_external": int(refresh_external),
        "external_stylesheet_ratio": _ratio(external_sheets, len(sheets)),
        "has_title": int(bool(page.title)),
        "title_length": len(page.title or ""),
    }
    details = {
        "external_link_ratio": {
            "percent": round(100 * features["external_link_ratio"]),
            "domains": ", ".join(name for name, _ in domains.most_common(3)),
        },
        "distinct_external_domains": {"top": dict(domains.most_common(5))},
        "null_link_ratio": {"percent": round(100 * features["null_link_ratio"])},
        "has_meta_refresh": {"content": refresh.content if refresh else None},
        "meta_refresh_external": {"url": refresh.redirect_url if refresh else None},
    }
    return features, details
