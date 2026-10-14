"""Read public old.reddit.com listings with Playwright.

Keywords decide which posts are candidates. Nothing here is labelled a scam.
URLs are stored as real http(s) links. Usernames are removed from the text.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote_plus, urljoin, urlparse

_USERNAME = re.compile(r"\bu/[A-Za-z0-9_-]{3,}\b")
_IMAGE_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp")
_OLD = "https://old.reddit.com"


def _delay() -> float:
    return max(8.0, float(os.getenv("REDDIT_REQUEST_DELAY_SECONDS", "8")))


def _max_posts() -> int:
    return max(1, int(os.getenv("REDDIT_MAX_POSTS_PER_SEARCH", "10")))


def strip_usernames(text: str) -> str:
    return _USERNAME.sub("[user]", text or "").strip()


def _abs(url: str) -> str:
    if not url:
        return ""
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        return urljoin(_OLD, url)
    return url


def _is_image(url: str) -> bool:
    path = urlparse(url).path.lower()
    host = (urlparse(url).hostname or "").lower()
    if "thumbs.redditmedia.com" in host or "redditstatic.com" in host:
        return False
    return path.endswith(_IMAGE_EXT) or host in {"i.redd.it", "preview.redd.it", "i.imgur.com"}


def _listing(page, url: str) -> list[dict]:
    page.goto(url, wait_until="domcontentloaded", timeout=30000)
    page.wait_for_selector("#siteTable .thing", timeout=15000)
    rows = page.eval_on_selector_all(
        "#siteTable .thing.link",
        """(nodes) => nodes.map((post) => {
            const title = post.querySelector("a.title");
            const body = post.querySelector(".expando .md");
            return {
                id: (post.getAttribute("data-fullname") || "").replace(/^t3_/, ""),
                title: title ? title.innerText : "",
                outbound: post.getAttribute("data-url") || "",
                permalink: post.getAttribute("data-permalink") || (title ? title.getAttribute("href") : ""),
                timestamp: post.getAttribute("data-timestamp") || "",
                body: body ? body.innerText : "",
                subreddit: post.getAttribute("data-subreddit") || "",
            };
        })""",
    )
    return [row for row in rows if row.get("id") and row.get("title")][: _max_posts()]


def _fill_body(page, row: dict) -> str:
    body = (row.get("body") or "").strip()
    if body:
        return body
    permalink = _abs(row.get("permalink") or "")
    if "/comments/" not in permalink:
        return ""
    time.sleep(_delay())
    page.goto(permalink, wait_until="domcontentloaded", timeout=30000)
    try:
        page.wait_for_selector("div.usertext-body .md", timeout=8000)
    except Exception:
        return ""
    text = page.eval_on_selector(
        "div.usertext-body .md",
        "(el) => el.innerText || ''",
    )
    return (text or "").strip()


def _to_record(row: dict, body: str, matched: list[str]) -> dict:
    permalink = _abs(row.get("permalink") or "")
    outbound = _abs(row.get("outbound") or "")
    images = [outbound] if outbound and _is_image(outbound) else []
    extra = ""
    if outbound and outbound != permalink and not _is_image(outbound):
        extra = "\n" + outbound
    try:
        created = int(row.get("timestamp") or "0") / 1000
    except ValueError:
        created = datetime.now(timezone.utc).timestamp()
    if created <= 0:
        created = datetime.now(timezone.utc).timestamp()
    return {
        "id": row["id"],
        "title": strip_usernames(row.get("title") or ""),
        "selftext": strip_usernames(body + extra),
        "created_utc": created,
        "url": permalink,
        "html_hrefs": images,
        "subreddit": (row.get("subreddit") or "search").lower(),
        "matched": matched,
    }


def _browse(urls: list[tuple[str, list[str]]]) -> list[dict]:
    from playwright.sync_api import sync_playwright

    posts: list[dict] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(locale="en-US")
        context.add_cookies([{
            "name": "over18", "value": "1", "domain": ".reddit.com", "path": "/",
        }])
        page = context.new_page()
        try:
            for url, matched in urls:
                print(f"[browser] {url}")
                time.sleep(_delay())
                try:
                    rows = _listing(page, url)
                except Exception as exc:
                    print(f"[browser] listing failed: {exc}")
                    continue
                for row in rows:
                    body = _fill_body(page, row)
                    posts.append(_to_record(row, body, matched))
        finally:
            context.close()
            browser.close()
    return posts


def search_keyword(keyword: str) -> list[dict]:
    url = f"{_OLD}/search?q={quote_plus(keyword)}&sort=new&restrict_sr=off"
    return _browse([(url, [keyword])])


def subreddit_new(name: str, keywords: list[str]) -> list[dict]:
    url = f"{_OLD}/r/{name}/new/"
    found = _browse([(url, [])])
    if not keywords:
        return found
    kept = []
    for post in found:
        text = f"{post['title']}\n{post['selftext']}".lower()
        matched = [kw for kw in keywords if kw and kw in text]
        if matched:
            post["matched"] = matched
            kept.append(post)
    return kept
