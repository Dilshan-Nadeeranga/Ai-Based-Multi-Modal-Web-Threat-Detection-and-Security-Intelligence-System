"""Extract the text, embedded URL and image of one public Reddit post.

Reddit's JSON API and old.reddit.com now sit behind a login wall for
anonymous clients, so the post page is rendered in headless Chromium and the
``<shreddit-post>`` element is read. Only Reddit hosts are opened; embedded
links are returned, never visited here (the analysis capture does that in its
sandbox). Images are downloaded only from Reddit / Imgur image hosts.
"""

from __future__ import annotations

import base64
import io
import logging
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse

from PIL import Image

from app.config import Settings
from app.exceptions import ServiceError

logger = logging.getLogger(__name__)

REDDIT_HOSTS = {"reddit.com", "www.reddit.com", "old.reddit.com", "new.reddit.com", "m.reddit.com", "np.reddit.com", "redd.it"}
IMAGE_HOSTS = {"i.redd.it", "preview.redd.it", "external-preview.redd.it", "i.imgur.com"}
INTERNAL_HOST_SUFFIXES = ("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "imgur.com")
IMAGE_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}
CONVERTIBLE_TYPES = {"image/avif"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
_POST_PATH = re.compile(r"^/(r/[^/]+/(comments|s)/[^/]+|comments/[^/]+|[a-z0-9]{5,10}/?$)", re.IGNORECASE)

_READ_POST_JS = """(post) => {
  const body = post.querySelector('[slot="text-body"]');
  const imageHosts = /^(i|preview|external-preview)\\.redd\\.it$|^i\\.imgur\\.com$/;
  const images = [...post.querySelectorAll('img')]
    .map((img) => ({ src: img.currentSrc || img.src, width: img.naturalWidth || img.width || 0 }))
    .filter((img) => { try { return imageHosts.test(new URL(img.src).hostname); } catch { return false; } });
  return {
    id: post.getAttribute('id') || '',
    title: post.getAttribute('post-title') || '',
    type: post.getAttribute('post-type') || '',
    domain: post.getAttribute('domain') || '',
    content_href: post.getAttribute('content-href') || '',
    permalink: post.getAttribute('permalink') || '',
    subreddit: post.getAttribute('subreddit-prefixed-name') || '',
    created: post.getAttribute('created-timestamp') || '',
    body: body ? body.innerText : '',
    links: body ? [...body.querySelectorAll('a[href]')].map((a) => a.href) : [],
    images,
  };
}"""


class RedditFetchError(ServiceError):
    code = "REDDIT_FETCH_FAILED"
    status_code = 502


class InvalidRedditUrlError(ServiceError):
    code = "INVALID_REDDIT_URL"
    status_code = 400
    default_message = ("Enter a Reddit or Facebook post URL, e.g. https://www.reddit.com/r/Scams/comments/abc123/... "
                       "or https://www.facebook.com/<page>/posts/<id>")


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_internal(url: str) -> bool:
    host = _host(url)
    return any(host == suffix or host.endswith("." + suffix) for suffix in INTERNAL_HOST_SUFFIXES)


def normalize_reddit_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or _host(url) not in REDDIT_HOSTS or not _POST_PATH.match(parsed.path or ""):
        raise InvalidRedditUrlError()
    host = "redd.it" if _host(url) == "redd.it" else "www.reddit.com"
    return f"https://{host}{parsed.path}"


def fetch_reddit_post(url: str, settings: Settings) -> dict:
    post_url = normalize_reddit_url(url)
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    timeout_ms = int(settings.web_capture_timeout_seconds * 1000)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
            try:
                context = browser.new_context(locale="en-US", user_agent=USER_AGENT, viewport={"width": 1366, "height": 900})
                page = context.new_page()
                page.goto(post_url, wait_until="domcontentloaded", timeout=timeout_ms)
                try:
                    page.wait_for_selector("shreddit-post", timeout=20000)
                except PlaywrightError as exc:
                    logger.warning("No shreddit-post on %s (title %r)", page.url[:200], page.title())
                    raise RedditFetchError("Reddit did not return the post (removed, private, or blocked by Reddit).") from exc
                if _host(page.url) not in REDDIT_HOSTS:
                    raise RedditFetchError("The link did not resolve to a Reddit post.")
                page.wait_for_timeout(800)
                raw = page.eval_on_selector("shreddit-post", _READ_POST_JS)
                final_url = page.url.split("?")[0]
            finally:
                browser.close()
    except ServiceError:
        raise
    except PlaywrightError as exc:
        logger.warning("Reddit fetch failed for %s: %s", post_url, exc)
        raise RedditFetchError("Could not load the Reddit post (browser error or timeout).") from exc

    image = _download_image(_pick_image(raw))
    title, body = (raw.get("title") or "").strip(), (raw.get("body") or "").strip()
    content_href = raw.get("content_href") or ""
    candidates = ([content_href] if content_href and not _is_internal(content_href) else []) + raw.get("links", [])
    embedded = list(dict.fromkeys(u for u in candidates if u.startswith(("http://", "https://")) and not _is_internal(u)))
    permalink = raw.get("permalink") or ""
    return {
        "success": True,
        "platform": "reddit",
        "source_url": url,
        "permalink": f"https://www.reddit.com{permalink}" if permalink.startswith("/") else final_url,
        "post_id": (raw.get("id") or "").removeprefix("t3_"),
        "subreddit": raw.get("subreddit"),
        "source_name": raw.get("subreddit"),
        "post_type": raw.get("type"),
        "created": raw.get("created"),
        "title": title,
        "body": body,
        "post_text": "\n\n".join(part for part in (title, body) if part),
        "embedded_urls": embedded,
        "embedded_url": embedded[0] if embedded else None,
        "image": image,
        "image_candidates": len(raw.get("images") or []),
    }


def _pick_image(raw: dict) -> str | None:
    href = raw.get("content_href") or ""
    if _host(href) in IMAGE_HOSTS:
        return href
    images = sorted(raw.get("images") or [], key=lambda img: -(img.get("width") or 0))
    return images[0]["src"] if images else None


def _download_image(url: str | None, allowed_hosts: set[str] = IMAGE_HOSTS, allowed_suffixes: tuple[str, ...] = ()) -> dict | None:
    host = _host(url or "")
    if not url or not (host in allowed_hosts or any(host.endswith(suffix) for suffix in allowed_suffixes)):
        return None
    import httpx

    try:
        import truststore

        truststore.inject_into_ssl()
    except ImportError:
        pass
    try:
        with httpx.stream("GET", url, headers={"User-Agent": USER_AGENT, "Accept": "image/jpeg,image/png,image/webp;q=0.9"},
                          timeout=20, follow_redirects=False) as response:
            content_type = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
            if response.status_code != 200 or content_type not in (*IMAGE_TYPES, *CONVERTIBLE_TYPES):
                return None
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_IMAGE_BYTES:
                    return None
    except httpx.HTTPError as exc:
        logger.warning("Post image download failed: %s", exc)
        return None
    if not body:
        return None
    if content_type in CONVERTIBLE_TYPES:
        try:
            converted = io.BytesIO()
            Image.open(io.BytesIO(body)).convert("RGB").save(converted, format="JPEG", quality=92)
        except (OSError, ValueError) as exc:
            logger.warning("Could not convert %s image: %s", content_type, exc)
            return None
        body, content_type = converted.getvalue(), "image/jpeg"
    name = (PurePosixPath(urlparse(url).path).stem or "post_image")[:80]
    return {
        "source_url": url,
        "filename": f"{name}{IMAGE_TYPES[content_type]}",
        "content_type": content_type,
        "size_bytes": len(body),
        "data_url": f"data:{content_type};base64,{base64.b64encode(body).decode('ascii')}",
    }
