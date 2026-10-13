"""
ThreatRadar — Reddit Scam URL Scraper
======================================
Uses Reddit public RSS feeds — no API app, OAuth, or email login required.

Modes (pass as first CLI arg):
  continuous  (default) — batch-scrape subreddits, then poll for new posts
  batch                 — scrape recent posts once and exit
  watch                 — poll for new posts only
"""

import csv
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from typing import Optional
from urllib.parse import quote_plus, urlparse

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import requests

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ==================== CONFIGURATION ====================
USER_AGENT = os.getenv("REDDIT_USER_AGENT", "ThreatRadar/1.0 (scam URL monitor)")

SUBREDDITS_ENV = [
    s.strip().replace("r/", "").replace("/", "")
    for s in os.getenv("REDDIT_SCRAPE_SUBREDDITS", "").split(",")
    if s.strip()
]

SUBREDDITS_FILE = os.getenv(
    "SUBREDDITS_FILE",
    str(Path(__file__).parent.parent / "data" / "reddit_subreddits.json"),
)

KEYWORDS_FILE = os.getenv(
    "KEYWORDS_FILE",
    str(Path(__file__).parent.parent / "data" / "keywords.json"),
)

def _keywords_from_env() -> list[str]:
    raw = (
        os.getenv("SCAM_KEYWORDS")
        or os.getenv("REDDIT_SCRAPE_KEYWORDS")
        or os.getenv("REDDIT_KEYWORDS")
        or ""
    )
    return [k.strip().lower() for k in raw.split(",") if k.strip()]


ENV_KEYWORDS = _keywords_from_env()

LOOKBACK_DAYS            = int(os.getenv("REDDIT_LOOKBACK_DAYS", "7"))
POLL_INTERVAL_SECONDS    = int(os.getenv("REDDIT_POLL_INTERVAL_SECONDS", "120"))
REQUEST_DELAY_SECONDS    = float(os.getenv("REDDIT_REQUEST_DELAY_SECONDS", "3"))
AUTO_FIND_SUBREDDITS     = os.getenv("REDDIT_AUTO_FIND_SUBREDDITS", "false").lower() == "true"

SCRAPED_OUTPUT_DIR = os.getenv(
    "REDDIT_SCRAPED_OUTPUT_DIR",
    str(Path(__file__).parent.parent / "data" / "scraped"),
)
SETTINGS_FILE = os.getenv(
    "REDDIT_SETTINGS_FILE",
    str(Path(__file__).parent.parent / "data" / "reddit_settings.json"),
)
REDDIT_URLS_ONLY = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_urls_only.csv")
REDDIT_FULL_CSV  = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_scraped_urls.csv")
REDDIT_POSTS_CSV = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_posts.csv")
REDDIT_IMAGES_DIR = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_images")
POST_COLUMNS = [
    "post_id", "subreddit", "date", "matched_keywords", "title", "text",
    "post_url", "urls", "image_urls", "image_files",
]
MAX_POST_TEXT = 8000
MAX_IMAGES_PER_POST = 6
MAX_IMAGE_BYTES = 8 * 1024 * 1024
_IMAGE_HOSTS = {"i.redd.it", "preview.redd.it", "external-preview.redd.it", "i.imgur.com"}
_IMAGE_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif", "image/webp": ".webp"}
URLS_ONLY_MODE   = os.getenv("REDDIT_URLS_ONLY_MODE", "true").lower() == "true"
# Fetch full comment trees via Reddit's public .json API (no Playwright, no login)
FETCH_COMMENT_JSON = os.getenv("REDDIT_FETCH_COMMENT_JSON", "true").lower() == "true"

DEFAULT_KNOWN_HOST_SUFFIXES = [
    "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
    "t.me", "telegram.org", "telegra.ph",
    "x.com", "twitter.com", "facebook.com", "fb.com",
    "instagram.com", "threads.net", "forms.gle",
    "google.com", "googleapis.com", "gstatic.com",
    "youtube.com", "youtu.be", "linkedin.com",
    "tiktok.com", "discord.com", "discord.gg",
    "github.com", "gitlab.com", "medium.com", "whatsapp.com",
    "apple.com", "microsoft.com", "amazon.com", "wikipedia.org",
    "cloudflare.com", "paypal.com", "imgur.com", "i.redd.it", "v.redd.it",
    "binance.com", "bybit.com", "bybit.net", "coinbase.com",
    "okx.com", "kucoin.com", "gate.io", "huobi.com", "kraken.com",
    "tradingview.com", "trustwallet.com", "metamask.io", "substack.com",
]

EXTRA_WHITELIST = [
    h.strip().lower().replace("www.", "")
    for h in os.getenv("REDDIT_KNOWN_HOST_WHITELIST", "").split(",")
    if h.strip()
]

KNOWN_HOST_SUFFIXES = list(dict.fromkeys(DEFAULT_KNOWN_HOST_SUFFIXES + EXTRA_WHITELIST))

_seen_post_ids: set[str] = set()
_rate_limited_until: float = 0.0
_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})
_ATOM_NS = {"atom": "http://www.w3.org/2005/Atom"}
MAX_JSON_FETCHES_PER_CYCLE = int(os.getenv("REDDIT_MAX_JSON_FETCHES", "8"))
# =======================================================


@dataclass
class RedditPost:
    id: str
    title: str
    selftext: str
    created_utc: float
    score: Optional[int]
    url: str
    subreddit: str
    html_hrefs: Optional[list] = None


def load_keywords() -> list[str]:
    try:
        with open(KEYWORDS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                data = data.get("keywords", [])
            if isinstance(data, list):
                kws = [str(k).strip().lower() for k in data if str(k).strip()]
                if kws:
                    return kws
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return ENV_KEYWORDS


def is_auto_scrape_enabled() -> bool:
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return bool(data.get("autoScrape", False))
    except (FileNotFoundError, json.JSONDecodeError):
        return os.getenv("REDDIT_SCRAPER_ENABLED", "false").lower() == "true"


def get_search_scope() -> str:
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            scope = json.load(f).get("searchScope", "global")
            return scope if scope in ("global", "subreddits", "both") else "global"
    except (FileNotFoundError, json.JSONDecodeError):
        return "global"


def load_subreddits() -> list[str]:
    try:
        with open(SUBREDDITS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            subs = [
                str(s).strip().replace("r/", "").replace("/", "")
                for s in data
                if str(s).strip()
            ]
            if subs:
                return subs
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return SUBREDDITS_ENV


def host_matches_suffix(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith(f".{suffix}")


def is_plausible_host(hostname: str) -> bool:
    """Reject prices (99.99), bare IPs, and numeric pseudo-domains."""
    if not hostname or "." not in hostname:
        return False
    h = hostname.lower().replace("www.", "")
    parts = h.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if not re.fullmatch(r"[a-z]{2,63}", tld):
        return False
    label = ".".join(parts[:-1])
    if not re.search(r"[a-z]", label, re.I):
        return False
    if re.fullmatch(r"\d+\.\d+", h):
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
        return False
    return True


def is_known_or_internal(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
        if not host or not is_plausible_host(host):
            return True
        if "reddit" in host:
            return True
        return any(host_matches_suffix(host, s) for s in KNOWN_HOST_SUFFIXES)
    except Exception:
        return True


def strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html or "")
    return unescape(re.sub(r"\s+", " ", text)).strip()


def extract_urls_from_text(text: str) -> list[str]:
    urls: set[str] = set()
    urls.update(re.findall(r'https?://[^\s<>"\']+', text or ""))
    urls.update(
        re.findall(
            r'(?:www\.)?(?:[a-z0-9][-a-z0-9]*\.)+[a-z]{2,}(?:/[^\s<>"\']*)?',
            text or "",
            flags=re.I,
        )
    )
    out = []
    for u in urls:
        u = u.rstrip(".,);]>")
        if not u.startswith("http"):
            u = f"https://{u}"
        try:
            parsed = urlparse(u)
            if parsed.scheme in ("http", "https") and not is_known_or_internal(u):
                out.append(u)
        except Exception:
            pass
    return out


def _walk_reddit_listing(listing, urls: set[str]) -> None:
    if not isinstance(listing, dict):
        return
    data = listing.get("data") or {}
    for child in data.get("children") or []:
        if not isinstance(child, dict):
            continue
        d = child.get("data") or {}
        body = " ".join(
            str(d.get(k) or "")
            for k in ("title", "selftext", "body")
        )
        for u in extract_urls_from_text(body):
            urls.add(u)
        link = d.get("url")
        if link and isinstance(link, str) and link.startswith("http") and not d.get("is_self"):
            if not is_known_or_internal(link):
                urls.add(link)
        replies = d.get("replies")
        if isinstance(replies, dict):
            _walk_reddit_listing(replies, urls)


def fetch_urls_from_post_json(permalink: str) -> list[str]:
    """Reddit public JSON — post body + comments, no browser needed."""
    global _rate_limited_until
    if time.time() < _rate_limited_until:
        return []
    if not permalink or "/comments/" not in permalink:
        return []
    base = permalink.split("?")[0].rstrip("/")
    json_url = f"{base}.json?limit=50&depth=4&raw_json=1"
    urls: set[str] = set()

    for attempt in range(2):
        time.sleep(REQUEST_DELAY_SECONDS)
        try:
            resp = _session.get(json_url, timeout=30)
            if resp.status_code == 429:
                wait = 30 * (attempt + 1)
                _rate_limited_until = time.time() + wait
                print(f"   [!] JSON rate limited — pausing {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code != 200:
                return []
            payload = resp.json()
            if isinstance(payload, list):
                for block in payload:
                    _walk_reddit_listing(block, urls)
            return list(urls)
        except Exception:
            if attempt == 1:
                return list(urls)
    return list(urls)


def parse_post_id(entry_id: str) -> str:
    if entry_id.startswith("t3_"):
        return entry_id[3:]
    return entry_id


def parse_published(value: str) -> float:
    try:
        return parsedate_to_datetime(value).timestamp()
    except Exception:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except Exception:
            return datetime.now(timezone.utc).timestamp()


def _engine() -> str:
    return os.getenv("REDDIT_ENGINE", "rss").strip().lower()


def _posts_from_browser(rows: list[dict]) -> list[RedditPost]:
    return [
        RedditPost(
            id=row["id"],
            title=row.get("title") or "",
            selftext=row.get("selftext") or "",
            created_utc=float(row.get("created_utc") or 0),
            score=None,
            url=row.get("url") or "",
            subreddit=row.get("subreddit") or "search",
            html_hrefs=row.get("html_hrefs") or [],
        )
        for row in rows
    ]


def fetch_rss_posts(subreddit: str, keywords: list[str] | None = None) -> list[RedditPost]:
    if _engine() == "playwright":
        try:
            from reddit_browser import subreddit_new

            rows = subreddit_new(subreddit, keywords or [])
            if rows:
                return _posts_from_browser(rows)
            print(f"   [!] Browser found no posts in r/{subreddit}; trying RSS")
        except Exception as exc:
            print(f"   [!] Browser unavailable for r/{subreddit} ({exc}). Using RSS.")
    url = f"https://www.reddit.com/r/{subreddit}/new/.rss"
    return _fetch_rss_feed(url, subreddit)


def fetch_global_search_posts(keyword: str) -> list[RedditPost]:
    if _engine() == "playwright":
        try:
            from reddit_browser import search_keyword

            rows = search_keyword(keyword)
            if rows:
                return _posts_from_browser(rows)
            print(f"   [!] Browser search returned nothing for {keyword!r}; trying RSS")
        except Exception as exc:
            print(f"   [!] Browser search unavailable ({exc}). Using RSS.")
    url = f"https://www.reddit.com/search.rss?q={quote_plus(keyword)}&sort=new"
    return _fetch_rss_feed(url, "search")


def _fetch_rss_feed(feed_url: str, label: str) -> list[RedditPost]:
    resp = None

    for attempt in range(3):
        time.sleep(REQUEST_DELAY_SECONDS * (attempt + 1))
        resp = _session.get(feed_url, timeout=30)
        if resp.status_code == 429:
            wait = 15 * (attempt + 1)
            print(f"   [!] Rate limited ({label}), waiting {wait}s...")
            time.sleep(wait)
            continue
        break

    if resp is None or resp.status_code == 403:
        raise RuntimeError(
            f"Reddit blocked RSS for {label}. "
            "Set REDDIT_USER_AGENT=ThreatRadar/1.0 (by u/your_reddit_username)"
        )
    resp.raise_for_status()

    root = ET.fromstring(resp.content)
    posts: list[RedditPost] = []

    for entry in root.findall("atom:entry", _ATOM_NS):
        title_el = entry.find("atom:title", _ATOM_NS)
        content_el = entry.find("atom:content", _ATOM_NS)
        published_el = entry.find("atom:published", _ATOM_NS)
        id_el = entry.find("atom:id", _ATOM_NS)
        link_el = entry.find("atom:link", _ATOM_NS)

        title = (title_el.text or "").strip() if title_el is not None else ""
        raw_content = (content_el.text or "") if content_el is not None else ""
        selftext = strip_html(raw_content)
        html_hrefs = re.findall(r"""(?:href|src)=["']([^"']+)""", raw_content or "", re.I)
        post_id = parse_post_id((id_el.text or "").strip() if id_el is not None else "")
        published = (published_el.text or "").strip() if published_el is not None else ""
        post_url = link_el.get("href", "") if link_el is not None else ""

        posts.append(RedditPost(
            id=post_id,
            title=title,
            selftext=selftext,
            created_utc=parse_published(published),
            score=None,
            url=post_url,
            subreddit=label,
            html_hrefs=html_hrefs,
        ))

    return posts


def append_records(records: list[dict]) -> None:
    if not records:
        return
    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)
    url_cols = ["domain", "url", "subreddit", "date", "post_id", "score", "title"]
    header_urls = not os.path.exists(REDDIT_URLS_ONLY)

    with open(REDDIT_URLS_ONLY, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=url_cols, extrasaction="ignore")
        if header_urls:
            writer.writeheader()
        for rec in records:
            row = {k: rec.get(k, "") for k in url_cols}
            if row.get("score") is None:
                row["score"] = ""
            writer.writerow(row)

    print(f"   [+] Saved {len(records)} URLs → {REDDIT_URLS_ONLY}")


def deduplicate_csv() -> int:
    if not os.path.exists(REDDIT_URLS_ONLY):
        return 0
    try:
        with open(REDDIT_URLS_ONLY, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        before = len(rows)

        seen_domains: set[str] = set()
        unique = []
        for row in rows:
            url = str(row.get("url") or "")
            domain = str(row.get("domain") or extract_domain(url))
            if not domain or is_reddit_host(url) or not is_plausible_host(domain):
                continue
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            row["domain"] = domain
            unique.append(row)

        url_cols = ["domain", "url", "subreddit", "date", "post_id", "score", "title"]
        with open(REDDIT_URLS_ONLY, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=url_cols, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(unique)

        removed = before - len(unique)
        if removed:
            print(f"[dedup] Removed {removed} duplicate URLs. {len(unique)} unique remain.")
        return len(unique)
    except Exception as e:
        print(f"[dedup] Failed: {e}")
        return 0


def extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return ""


def is_reddit_host(url: str) -> bool:
    host = extract_domain(url)
    if not host:
        return True
    if "reddit" in host:
        return True
    return host == "redd.it" or host.endswith(".redd.it")


def build_record(post: RedditPost, subreddit: str, url: str) -> dict:
    title = (post.title or "")[:200]
    body = (post.selftext or "")[:400]
    return {
        "domain": extract_domain(url),
        "subreddit": subreddit,
        "post_id": post.id,
        "date": datetime.fromtimestamp(post.created_utc, tz=timezone.utc).isoformat(),
        "url": url,
        "score": post.score,
        "title": title,
        "text_snippet": f"{title} {body}".strip()[:400],
    }


def text_matches_keywords(text: str, keywords: list[str]) -> bool:
    if not keywords:
        return True
    lower = (text or "").lower()
    return any(kw in lower for kw in keywords)


def keywords_in_text(text: str, keywords: list[str]) -> list[str]:
    lower = (text or "").lower()
    return [kw for kw in keywords if kw and kw in lower]


def _is_image_url(url: str) -> bool:
    try:
        parts = urlparse(url)
    except Exception:
        return False
    host = (parts.hostname or "").lower()
    if host in ("www.redditstatic.com", "emoji.redditmedia.com", "styles.redditmedia.com"):
        return False
    path = parts.path.lower().split("?")[0]
    if path.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")):
        return True
    return host in _IMAGE_HOSTS


def image_urls_for(post: RedditPost) -> list[str]:
    found: list[str] = []
    for raw in [*(post.html_hrefs or []), post.url or ""]:
        url = unescape(raw or "").replace("&amp;", "&")
        if url.startswith("//"):
            url = "https:" + url
        if url.startswith("http") and _is_image_url(url) and url not in found:
            found.append(url)
    return found[:MAX_IMAGES_PER_POST]


def external_urls_in_text(*parts: str) -> list[str]:
    """http(s) links that are not Reddit and not an image file."""
    found: list[str] = []
    for part in parts:
        for url in re.findall(r"https?://[^\s<>\"']+", part or ""):
            url = unescape(url).replace("&amp;", "&").rstrip(".,);]>")
            if not url.startswith("http") or url in found:
                continue
            if is_reddit_host(url) or _is_image_url(url):
                continue
            found.append(url)
    return found


def destination_urls_for(post: RedditPost) -> list[str]:
    """Links outside Reddit. The post permalink and image files are not destination URLs."""
    hrefs = " ".join(href for href in (post.html_hrefs or []) if href.startswith("http"))
    return external_urls_in_text(post.title or "", post.selftext or "", hrefs, post.url or "")


def download_post_images(post_id: str, urls: list[str]) -> list[str]:
    """Save post images next to the CSV. Only known image hosts are downloaded."""
    saved: list[str] = []
    safe_id = re.sub(r"[^A-Za-z0-9]", "", post_id)[:20] or "post"
    os.makedirs(REDDIT_IMAGES_DIR, exist_ok=True)
    index = 1
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if host not in _IMAGE_HOSTS:
            continue
        if index > MAX_IMAGES_PER_POST:
            break
        try:
            resp = _session.get(url, timeout=20, stream=True)
            if resp.status_code != 200:
                continue
            ext = _IMAGE_TYPES.get(resp.headers.get("content-type", "").split(";", 1)[0].strip().lower())
            if not ext:
                continue
            name = f"{safe_id}_{index:02d}{ext}"
            path = os.path.join(REDDIT_IMAGES_DIR, name)
            size = 0
            with open(path, "wb") as handle:
                for chunk in resp.iter_content(64 * 1024):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_IMAGE_BYTES:
                        size = -1
                        break
                    handle.write(chunk)
            if size <= 0:
                os.remove(path)
                continue
            saved.append(f"reddit_images/{name}")
            index += 1
        except Exception:
            continue
    return saved


def build_post_record(post: RedditPost, subreddit: str, matched: list[str]) -> Optional[dict]:
    """Keep a keyword post only when it has a link outside Reddit. An image is optional."""
    from reddit_browser import strip_usernames

    destinations = destination_urls_for(post)
    if not destinations:
        return None
    body = strip_usernames(post.selftext or "")
    title = strip_usernames(post.title or "")
    blob = f"{title}\n{body}\n{' '.join(destinations)}".lower()
    confirmed = [kw for kw in matched if kw and kw.lower() in blob]
    if not confirmed:
        return None
    text = body[:MAX_POST_TEXT] if body else title[:MAX_POST_TEXT]
    images = image_urls_for(post)
    files = download_post_images(post.id, images) if images else []
    return {
        "post_id": post.id,
        "subreddit": subreddit,
        "date": datetime.fromtimestamp(post.created_utc, tz=timezone.utc).isoformat(),
        "matched_keywords": " | ".join(confirmed),
        "title": title[:300],
        "text": text,
        "post_url": destinations[0],
        "urls": " ".join(destinations),
        "image_urls": " ".join(images),
        "image_files": " ".join(files),
    }


def append_posts(records: list[dict]) -> int:
    records = [row for row in records if row and (row.get("urls") or "").strip()]
    if not records:
        return 0
    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)
    seen: set[str] = set()
    if os.path.exists(REDDIT_POSTS_CSV):
        with open(REDDIT_POSTS_CSV, encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row.get("post_id"):
                    seen.add(row["post_id"])
    fresh = [row for row in records if row.get("post_id") and row["post_id"] not in seen]
    if not fresh:
        return 0
    new_file = not os.path.exists(REDDIT_POSTS_CSV)
    with open(REDDIT_POSTS_CSV, "a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=POST_COLUMNS, extrasaction="ignore")
        if new_file:
            writer.writeheader()
        writer.writerows(fresh)
    jsonl_path = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_posts.jsonl")
    with open(jsonl_path, "a", encoding="utf-8") as handle:
        for row in fresh:
            handle.write(json.dumps({
                "platform": "reddit",
                "post_id": row.get("post_id"),
                "subreddit": row.get("subreddit"),
                "post_permalink": row.get("post_url"),
                "post_text": row.get("text"),
                "extracted_urls": (row.get("urls") or "").split(),
                "image_urls": (row.get("image_urls") or "").split(),
                "image_files": (row.get("image_files") or "").split(),
                "matched_keywords": (row.get("matched_keywords") or "").split(" | "),
                "label_status": "not_annotated",
                "collected_at": row.get("date"),
            }, ensure_ascii=False) + "\n")
    print(f"   [+] Saved {len(fresh)} posts (text, images, urls) → {REDDIT_POSTS_CSV}")
    _publish_rows(fresh)
    return len(fresh)


def _read_post_rows() -> list[dict]:
    if not os.path.exists(REDDIT_POSTS_CSV):
        return []
    with open(REDDIT_POSTS_CSV, encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_post_rows(rows: list[dict]) -> None:
    with open(REDDIT_POSTS_CSV, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=POST_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _publish_rows(rows: list[dict]) -> None:
    if not rows:
        return
    try:
        from cloud_store import publish_posts
        posts, images = publish_posts(rows, REDDIT_IMAGES_DIR)
        if posts:
            print(f"   [+] Database {posts} post(s), Backblaze {images} image(s)")
    except Exception as exc:
        print(f"   [!] Database/Backblaze save failed: {exc}")


def retain_external_posts() -> list[dict]:
    """Drop saved posts that have no link outside Reddit. Keep an image only when one exists."""
    kept: list[dict] = []
    for row in _read_post_rows():
        urls = external_urls_in_text(row.get("title") or "", row.get("text") or "", row.get("urls") or "", row.get("post_url") or "")
        keywords = [part.strip() for part in (row.get("matched_keywords") or "").split("|") if part.strip()]
        blob = f"{row.get('title') or ''}\n{row.get('text') or ''}\n{' '.join(urls)}".lower()
        confirmed = [kw for kw in keywords if kw.lower() in blob]
        if not urls or not confirmed:
            continue
        row["urls"] = " ".join(urls)
        row["post_url"] = urls[0]
        row["matched_keywords"] = " | ".join(confirmed)
        kept.append(row)
    _write_post_rows(kept)
    jsonl_path = os.path.join(SCRAPED_OUTPUT_DIR, "reddit_posts.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as handle:
        for row in kept:
            handle.write(json.dumps({
                "platform": "reddit",
                "post_id": row.get("post_id"),
                "subreddit": row.get("subreddit"),
                "post_permalink": row.get("post_url"),
                "post_text": row.get("text"),
                "extracted_urls": (row.get("urls") or "").split(),
                "image_urls": (row.get("image_urls") or "").split(),
                "image_files": (row.get("image_files") or "").split(),
                "matched_keywords": (row.get("matched_keywords") or "").split(" | "),
                "label_status": "not_annotated",
                "collected_at": row.get("date"),
            }, ensure_ascii=False) + "\n")
    try:
        from cloud_store import keep_only
        removed = keep_only([row["post_id"] for row in kept if row.get("post_id")])
        print(f"[store] Kept {len(kept)} posts with an external link, removed {removed} from the database")
    except Exception as exc:
        print(f"[store] Database cleanup failed: {exc}")
    return kept


def backfill_cloud() -> None:
    """Send posts already on disk to Neon, and upload any saved images to Backblaze."""
    retain_external_posts()
    rows = _read_post_rows()
    if not rows:
        print("[store] No local posts to send")
        return
    changed = False
    for row in rows:
        if (row.get("image_files") or "").strip() or not (row.get("image_urls") or "").strip():
            continue
        files = download_post_images(row.get("post_id") or "", (row.get("image_urls") or "").split())
        if files:
            row["image_files"] = " ".join(files)
            changed = True
    if changed:
        current = {row.get("post_id"): row for row in _read_post_rows()}
        for row in rows:
            post_id = row.get("post_id")
            if post_id in current and (row.get("image_files") or "").strip():
                current[post_id]["image_files"] = row["image_files"]
            elif post_id and post_id not in current:
                current[post_id] = row
        _write_post_rows(list(current.values()))
        rows = _read_post_rows()
    _publish_rows(rows)


def collect_urls_from_post(
    post: RedditPost,
    subreddit: str,
    keywords: list[str],
    *,
    require_keyword_match: bool = True,
    json_budget: Optional[list] = None,
) -> list[dict]:
    combined = f"{post.title}\n{post.selftext}"
    if require_keyword_match and keywords and not text_matches_keywords(combined, keywords):
        return []

    records = []
    seen_urls: set[str] = set()

    candidate_urls = extract_urls_from_text(combined)
    for href in post.html_hrefs or []:
        if href.startswith("http"):
            candidate_urls.append(href)
    if post.url and post.url.startswith("http") and not is_reddit_host(post.url):
        candidate_urls.append(post.url)

    if FETCH_COMMENT_JSON and json_budget is not None:
        if json_budget[0] > 0:
            json_budget[0] -= 1
            permalink = post.url if "/comments/" in (post.url or "") else f"https://www.reddit.com/comments/{post.id}/"
            json_urls = fetch_urls_from_post_json(permalink)
            if json_urls:
                print(f"   [json] post {post.id}: +{len(json_urls)} URL(s) from comments")
            candidate_urls.extend(json_urls)
    elif FETCH_COMMENT_JSON and json_budget is None:
        permalink = post.url if "/comments/" in (post.url or "") else f"https://www.reddit.com/comments/{post.id}/"
        json_urls = fetch_urls_from_post_json(permalink)
        if json_urls:
            print(f"   [json] post {post.id}: +{len(json_urls)} URL(s) from comments")
        candidate_urls.extend(json_urls)

    for url in candidate_urls:
        if url not in seen_urls and not is_reddit_host(url):
            seen_urls.add(url)
            records.append(build_record(post, subreddit, url))

    return records


def scrape_subreddit(subreddit_name: str, from_date: datetime, keywords: list[str]) -> tuple[list[dict], list[dict]]:
    records = []
    posts_out: list[dict] = []
    print(f"\n[batch] r/{subreddit_name}  since {from_date.date()}")
    json_budget = [MAX_JSON_FETCHES_PER_CYCLE]

    try:
        posts = fetch_rss_posts(subreddit_name, keywords)
        checked = 0
        for post in posts:
            posted = datetime.fromtimestamp(post.created_utc, tz=timezone.utc)
            if posted < from_date:
                continue
            checked += 1
            matched = keywords_in_text(f"{post.title}\n{post.selftext}", keywords)
            if keywords and not matched:
                continue
            record = build_post_record(post, subreddit_name, matched)
            if not record:
                continue
            posts_out.append(record)
            records.extend(
                collect_urls_from_post(
                    post, subreddit_name, keywords, require_keyword_match=True, json_budget=json_budget
                )
            )
    except Exception as e:
        print(f"   [!] Cannot access r/{subreddit_name}: {e}")
        return records, posts_out

    print(f"   [+] {len(posts_out)} keyword posts, {len(records)} external URLs ({checked} posts checked)")
    return records, posts_out


def scrape_global_keyword(keyword: str, from_date: datetime) -> tuple[list[dict], list[dict]]:
    records = []
    posts_out: list[dict] = []
    json_budget = [MAX_JSON_FETCHES_PER_CYCLE]
    print(f"\n[batch] Global search: \"{keyword}\"")

    try:
        posts = fetch_global_search_posts(keyword)
        checked = 0
        for post in posts:
            posted = datetime.fromtimestamp(post.created_utc, tz=timezone.utc)
            if posted < from_date:
                continue
            checked += 1
            record = build_post_record(post, "search", [keyword])
            if not record:
                continue
            posts_out.append(record)
            records.extend(
                collect_urls_from_post(
                    post, "search", [keyword], require_keyword_match=False, json_budget=json_budget
                )
            )
        print(f"   [+] {len(posts_out)} posts, {len(records)} external URLs ({checked} posts checked)")
    except Exception as e:
        print(f"   [!] Global search failed for \"{keyword}\": {e}")

    return records, posts_out


def run_batch(subreddits: list[str], keywords: list[str]) -> list[str]:
    from_date = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    scope = get_search_scope()
    print(f"\n[batch] Window: last {LOOKBACK_DAYS} days · scope: {scope}")
    print(f"[batch] Keywords: {keywords or '(all posts)'}")

    all_records = []
    all_posts = []

    if scope in ("global", "both") and keywords:
        print(f"[batch] Global keyword search ({len(keywords)} keyword(s))...\n")
        for kw in keywords:
            urls, posts = scrape_global_keyword(kw, from_date)
            all_records.extend(urls)
            all_posts.extend(posts)

    if scope in ("subreddits", "both") and subreddits:
        print(f"[batch] Subreddit RSS ({len(subreddits)} sub(s))...\n")
        for sub in subreddits:
            try:
                urls, posts = scrape_subreddit(sub, from_date, keywords)
                all_records.extend(urls)
                all_posts.extend(posts)
            except Exception as e:
                print(f"[!] Error r/{sub}: {repr(e)}")
    elif scope in ("subreddits", "both") and not subreddits:
        print("[batch] No subreddits configured — add some in the UI or use global scope")

    if scope == "global" and not keywords:
        print("[batch] Global scope needs at least one keyword")

    saved_posts = append_posts(all_posts)
    append_records(all_records)
    total = deduplicate_csv()
    print(f"\n[batch] Done — {saved_posts} new posts, {len(all_records)} new URLs. {total} unique domains in CSV.\n")
    return subreddits


def run_watch(subreddits: list[str]) -> None:
    print(f"\n[watch] Polling every {POLL_INTERVAL_SECONDS}s (scope: {get_search_scope()})...\n")

    while True:
        if not is_auto_scrape_enabled():
            print("[watch] Auto-scrape OFF — exiting")
            sys.exit(0)

        scope = get_search_scope()
        keywords = load_keywords()
        all_records = []
        all_posts = []

        if scope in ("global", "both") and keywords:
            for kw in keywords:
                try:
                    print(f"[watch] Global search: {kw}")
                    json_budget = [MAX_JSON_FETCHES_PER_CYCLE]
                    for post in fetch_global_search_posts(kw):
                        key = f"search:{post.id}"
                        if key in _seen_post_ids:
                            continue
                        _seen_post_ids.add(key)
                        record = build_post_record(post, "search", [kw])
                        if not record:
                            continue
                        all_posts.append(record)
                        recs = collect_urls_from_post(
                            post, "search", [kw], require_keyword_match=False, json_budget=json_budget
                        )
                        if recs:
                            print(f"[watch] search:{kw}: post {post.id} ({len(recs)} URL(s))")
                            all_records.extend(recs)
                except Exception as e:
                    print(f"[watch] search:{kw}: {e}")

        if scope in ("subreddits", "both") and subreddits:
            for sub in subreddits:
                try:
                    for post in fetch_rss_posts(sub, keywords):
                        if post.id in _seen_post_ids:
                            continue
                        matched = keywords_in_text(f"{post.title}\n{post.selftext}", keywords)
                        if keywords and not matched:
                            _seen_post_ids.add(post.id)
                            continue
                        _seen_post_ids.add(post.id)
                        record = build_post_record(post, sub, matched)
                        if not record:
                            continue
                        all_posts.append(record)
                        recs = collect_urls_from_post(
                            post, sub, keywords, require_keyword_match=True, json_budget=[MAX_JSON_FETCHES_PER_CYCLE]
                        )
                        if recs:
                            print(f"[watch] r/{sub}: post {post.id} ({len(recs)} URL(s))")
                            all_records.extend(recs)
                except Exception as e:
                    print(f"[watch] Error r/{sub}: {e}")

        if all_posts:
            append_posts(all_posts)
        if all_records:
            append_records(all_records)
            deduplicate_csv()

        time.sleep(POLL_INTERVAL_SECONDS)


def run_continuous() -> None:
    keywords = load_keywords()
    subreddits = load_subreddits()
    subreddits = run_batch(subreddits, keywords)
    run_watch(subreddits)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "continuous"

    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)

    print("[reddit-py] Process started", flush=True)

    print("=" * 50)
    print("  ThreatRadar — Reddit Scam Scraper")
    print("  Source: RSS + public JSON (no Playwright required)")
    print("=" * 50)
    print(f"Mode:             {mode}")
    print(f"User-Agent:       {USER_AGENT}")
    print(f"Keywords file:    {KEYWORDS_FILE}")
    print(f"Keywords:         {load_keywords() or '(all — no filter)'}")
    print(f"Subreddits file:  {SUBREDDITS_FILE}")
    print(f"Subreddits:       {load_subreddits() or '(add via UI)'}")
    print(f"Request delay:    {REQUEST_DELAY_SECONDS}s")
    print(f"Output dir:       {SCRAPED_OUTPUT_DIR}")
    print(f"Posts file:       {REDDIT_POSTS_CSV}")
    print("=" * 50 + "\n")
    backfill_cloud()

    if mode == "batch":
        run_batch(load_subreddits(), load_keywords())
    elif mode == "watch":
        run_watch(load_subreddits())
    else:
        run_continuous()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[reddit] Stopped by user.")
    except Exception as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
