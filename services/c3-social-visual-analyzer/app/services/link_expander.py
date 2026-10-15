"""Expand a shortened link with plain HTTP redirects, before the browser capture.

Many shorteners answer a non-browser request with a 301/302 to the target even
when browsers get an interstitial or a bot-verification page. Redirects are
followed one hop at a time and every hop is checked with the capture
``UrlSafetyPolicy`` (no private addresses, no social-media hosts). Only the
first 64 KB of an HTML response is read, to find a ``<meta refresh>`` target.
"""

from __future__ import annotations

import html
import logging
import re
from urllib.parse import urljoin

from app.services.url_safety import UrlSafetyPolicy

logger = logging.getLogger(__name__)

MAX_HOPS = 8
MAX_PEEK_BYTES = 64 * 1024
USER_AGENT = "ScamTrace-C3/1.0 (link expander; research)"
_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*['"]?([^"'>\s]+)""",
    re.IGNORECASE,
)


def expand_short_link(url: str, policy: UrlSafetyPolicy, timeout: float = 10.0, transport=None) -> dict:
    import httpx

    hops: list[dict] = []
    current = url
    reason = None
    with httpx.Client(follow_redirects=False, timeout=timeout, transport=transport,
                      headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"}) as client:
        for _ in range(MAX_HOPS):
            verdict = policy.check(current)
            if not verdict.allowed:
                reason = f"{getattr(verdict.code, 'value', verdict.code)}: {verdict.message}"
                break
            try:
                with client.stream("GET", current) as response:
                    status = response.status_code
                    location = response.headers.get("location")
                    target = None
                    if status in (301, 302, 303, 307, 308) and location:
                        target = urljoin(current, location)
                    elif status == 200 and "html" in (response.headers.get("content-type") or ""):
                        peek = b""
                        for chunk in response.iter_bytes():
                            peek += chunk
                            if len(peek) >= MAX_PEEK_BYTES:
                                break
                        match = _META_REFRESH.search(peek.decode("utf-8", "ignore"))
                        if match:
                            target = urljoin(current, html.unescape(match.group(1)))
            except httpx.HTTPError as exc:
                reason = f"request failed: {exc.__class__.__name__}"
                break
            hops.append({"url": current, "status": status})
            if target is None:
                if status >= 400:
                    reason = f"HTTP {status} (dead link, or the site requires a browser / bot verification)"
                break
            current = target
        else:
            reason = "too many redirects"

    expanded = current if len(hops) > 1 or (hops and current != url) else None
    if expanded == url:
        expanded = None
    logger.info("Short link %s expanded to %s (%d hop(s)%s)", url, expanded, len(hops), f", stopped: {reason}" if reason else "")
    return {"original_url": url, "expanded_url": expanded, "resolved": expanded is not None,
            "hops": hops, "stopped_reason": reason, "method": "http_redirect"}
