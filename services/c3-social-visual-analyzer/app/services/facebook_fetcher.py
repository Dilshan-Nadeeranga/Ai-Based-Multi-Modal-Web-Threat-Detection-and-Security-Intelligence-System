"""Best-effort extraction of one public Facebook post (no login).

Facebook shows some public Page posts to logged-out visitors; group, private
and many personal posts are behind the login wall and cannot be read. The post
page is rendered in headless Chromium and read from the story message element,
with the page's Open Graph tags as fallback. Embedded links are returned, never
visited here. Images are downloaded only from Facebook's CDN (*.fbcdn.net).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

from app.config import Settings
from app.exceptions import ServiceError
from app.services.reddit_fetcher import USER_AGENT, _download_image, _host

logger = logging.getLogger(__name__)

FACEBOOK_HOSTS = {"facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com", "mbasic.facebook.com",
                  "touch.facebook.com", "fb.com", "www.fb.com", "fb.watch"}
INTERNAL_SUFFIXES = ("facebook.com", "fb.com", "fbcdn.net", "fb.watch", "instagram.com", "messenger.com")
CDN_SUFFIXES = (".fbcdn.net",)
# Reaction GIFs / stickers (e.g. in comments) are wrapped like outbound links but are not the post's destination.
MEDIA_SUFFIXES = ("tenor.com", "tenor.co", "giphy.com", "gph.is")
_MEDIA_FILE = re.compile(r"\.(gif|gifv|jpe?g|png|webp|avif|mp4|webm)$", re.IGNORECASE)
_POST_PATH = re.compile(r"/(posts|permalink\.php|story\.php|photo|photos|share|watch|reel|videos|groups/[^/]+/(posts|permalink))\b",
                        re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

_READ_POST_JS = """() => {
  const meta = (name) => document.querySelector(`meta[property="${name}"]`)?.content || '';
  const article = document.querySelector('[role=article]');
  const message = document.querySelector('[data-ad-rendering-role="story_message"], [data-ad-preview="message"], [data-ad-comet-preview="message"]');
  const scope = (message && message.closest('[role=article]')) || article || document;
  const imageScope = message ? scope : document;
  const minWidth = message ? 200 : 400;
  const images = [...imageScope.querySelectorAll('img')]
    .filter((img) => /fbcdn\\.net$/.test(new URL(img.src, location.href).hostname) && (img.naturalWidth || 0) >= minWidth)
    .map((img) => ({ src: img.currentSrc || img.src, width: img.naturalWidth }));
  return {
    title: document.title,
    page_name: meta('og:title'),
    og_description: meta('og:description'),
    og_image: meta('og:image'),
    og_url: meta('og:url'),
    message: message ? message.innerText : '',
    message_links: message ? [...message.querySelectorAll('a[href]')].map((a) => a.href) : [],
    attachment_link: scope.querySelector('a[href*="l.facebook.com/l.php"]')?.href || '',
    images,
    login_wall: !!document.querySelector('form[action*="login"]') && !message && !meta('og:description'),
  };
}"""


class FacebookFetchError(ServiceError):
    code = "FACEBOOK_FETCH_FAILED"
    status_code = 502


class InvalidFacebookUrlError(ServiceError):
    code = "INVALID_FACEBOOK_URL"
    status_code = 400
    default_message = "Enter a Facebook post URL, e.g. https://www.facebook.com/<page>/posts/<id> or a facebook.com/share/p/... link."


def _is_internal(url: str) -> bool:
    host = _host(url)
    return any(host == suffix or host.endswith("." + suffix) for suffix in INTERNAL_SUFFIXES)


def _is_media(url: str) -> bool:
    host = _host(url)
    return (any(host == suffix or host.endswith("." + suffix) for suffix in MEDIA_SUFFIXES)
            or bool(_MEDIA_FILE.search(urlparse(url).path or "")))


def _unwrap(url: str) -> str:
    """Facebook wraps outbound links as l.facebook.com/l.php?u=<target>."""
    if _host(url) in ("l.facebook.com", "lm.facebook.com"):
        target = parse_qs(urlparse(url).query).get("u", [""])[0]
        return target or url
    return url


def is_facebook_url(url: str) -> bool:
    candidate = url.strip() if re.match(r"^https?://", url.strip(), re.IGNORECASE) else "https://" + url.strip()
    return _host(candidate) in FACEBOOK_HOSTS


def normalize_facebook_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    parsed = urlparse(url)
    if _host(url) not in FACEBOOK_HOSTS or not _POST_PATH.search(parsed.path or ""):
        raise InvalidFacebookUrlError()
    host = "fb.watch" if _host(url) == "fb.watch" else "www.facebook.com"
    query = f"?{parsed.query}" if parsed.query and re.search(r"(story_fbid|fbid|id|v)=", parsed.query) else ""
    return f"https://{host}{parsed.path}{query}"


def fetch_facebook_post(url: str, settings: Settings) -> dict:
    post_url = normalize_facebook_url(url)
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
                    page.wait_for_selector('[data-ad-rendering-role="story_message"], [role=article], meta[property="og:description"]',
                                           state="attached", timeout=12000)
                except PlaywrightError:
                    pass
                page.wait_for_timeout(1500)
                if _host(page.url) not in FACEBOOK_HOSTS:
                    raise FacebookFetchError("The link did not resolve to a Facebook post.")
                raw = page.evaluate(_READ_POST_JS)
                final_url = page.url
            finally:
                browser.close()
    except ServiceError:
        raise
    except PlaywrightError as exc:
        logger.warning("Facebook fetch failed for %s: %s", post_url, exc)
        raise FacebookFetchError("Could not load the Facebook post (browser error or timeout).") from exc

    text = (raw.get("message") or raw.get("og_description") or "").strip()
    if not text and not raw.get("og_image") and not raw.get("images"):
        raise FacebookFetchError("Facebook did not show this post without logging in (private, group, or removed post). "
                               "Fill the fields manually instead.")

    image_url = raw.get("og_image") or (max(raw["images"], key=lambda img: img["width"])["src"] if raw.get("images") else None)
    image = _download_image(image_url, set(), CDN_SUFFIXES)
    links = [_unwrap(link) for link in [*(raw.get("message_links") or []), raw.get("attachment_link") or ""]] + _URL.findall(text)
    embedded = list(dict.fromkeys(link for link in links if link.startswith(("http://", "https://"))
                                  and not _is_internal(link) and not _is_media(link)))
    return {
        "success": True,
        "platform": "facebook",
        "source_url": url,
        "permalink": raw.get("og_url") or final_url.split("&__cft__")[0],
        "post_id": None,
        "source_name": raw.get("page_name") or "Facebook",
        "post_type": "photo" if image else "text",
        "created": None,
        "title": "",
        "body": text,
        "post_text": text,
        "embedded_urls": embedded,
        "embedded_url": embedded[0] if embedded else None,
        "image": image,
        "image_candidates": len(raw.get("images") or []) + (1 if raw.get("og_image") else 0),
        "text_source": "post message" if raw.get("message") else "page preview (og:description)" if text else None,
    }
