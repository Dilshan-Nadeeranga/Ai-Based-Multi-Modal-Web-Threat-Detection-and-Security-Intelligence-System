"""
ThreatRadar — Telegram Scam URL Scraper
========================================
Modes (pass as first CLI arg):
  continuous  (default) — batch-scrape discovered channels, then watch for new
                           messages, then re-discover every REDISCOVER_HOURS hours
  batch                 — scrape history once and exit
  watch                 — real-time watch only (no historical scrape)

Keywords are loaded from KEYWORDS_FILE (managed by the frontend UI).
Fallback: TELEGRAM_SCRAPE_KEYWORDS env var.
"""

import asyncio
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd
from dotenv import load_dotenv
from telethon import TelegramClient, events
from telethon.errors import FloodWaitError
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError
from telethon.tl.functions.contacts import SearchRequest
from telethon.tl.types import MessageEntityTextUrl, MessageEntityUrl

load_dotenv()

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

# ==================== CONFIGURATION ====================
API_ID   = int(os.getenv("API_ID", "0"))
API_HASH = os.getenv("API_HASH", "")
PHONE    = os.getenv("PHONE", "")

CHANNELS = [
    c.strip().replace("@", "")
    for c in os.getenv("TELEGRAM_SCRAPE_CHANNELS", "").split(",")
    if c.strip()
]

# Keywords file managed by the Node.js backend / frontend UI
KEYWORDS_FILE = os.getenv(
    "KEYWORDS_FILE",
    str(Path(__file__).parent.parent / "data" / "keywords.json"),
)

ENV_KEYWORDS = [
    k.strip().lower()
    for k in os.getenv("TELEGRAM_SCRAPE_KEYWORDS", "").split(",")
    if k.strip()
]

LOOKBACK_DAYS             = int(os.getenv("TELEGRAM_LOOKBACK_DAYS", "7"))
FROM_DATE                 = os.getenv("TELEGRAM_FROM_DATE", "")
TO_DATE                   = os.getenv("TELEGRAM_TO_DATE", "")
TODAY_ONLY                = os.getenv("TELEGRAM_TODAY_ONLY", "true").lower() == "true"
FORCE_LOOKBACK            = os.getenv("TELEGRAM_FORCE_LOOKBACK", "false").lower() == "true"
MAX_MESSAGES_PER_CHANNEL  = int(os.getenv("TELEGRAM_MAX_MESSAGES_PER_CHANNEL", "2000"))
SESSION_NAME              = os.getenv("TELEGRAM_SESSION_NAME", "scraper_session")
AUTO_FIND_CHANNELS        = os.getenv("TELEGRAM_AUTO_FIND_CHANNELS", "true").lower() == "true"
AUTO_FIND_MAX_CHANNELS    = int(os.getenv("TELEGRAM_AUTO_FIND_MAX_CHANNELS", "20"))
AUTO_FIND_LIMIT_PER_QUERY = int(os.getenv("TELEGRAM_AUTO_FIND_LIMIT_PER_QUERY", "40"))
URLS_ONLY_MODE            = os.getenv("TELEGRAM_URLS_ONLY_MODE", "true").lower() == "true"

# How often (hours) to re-discover channels and batch-scrape in continuous mode
REDISCOVER_HOURS = float(os.getenv("TELEGRAM_REDISCOVER_HOURS", "6"))

AUTO_FIND_QUERIES = [
    q.strip().lower()
    for q in os.getenv("TELEGRAM_AUTO_FIND_QUERIES",
        "crypto signal,forex signal,airdrop,giveaway,investment,vip trade,double money,usdt bonus"
    ).split(",")
    if q.strip()
]

SCRAPED_OUTPUT_DIR = os.getenv(
    "SCRAPED_OUTPUT_DIR",
    str(Path(__file__).parent.parent / "data" / "scraped"),
)
SCRAPED_URLS_ONLY  = os.path.join(SCRAPED_OUTPUT_DIR, "urls_only.csv")
SCRAPED_FULL_CSV   = os.path.join(SCRAPED_OUTPUT_DIR, "scraped_urls.csv")
SEEN_DOMAINS_FILE  = os.path.join(SCRAPED_OUTPUT_DIR, "seen_domains.json")
URLS_ONLY_DATE_FILE = os.path.join(SCRAPED_OUTPUT_DIR, "urls_only_date.txt")

DEFAULT_KNOWN_HOST_SUFFIXES = [
    "t.me", "telegram.org", "telegra.ph",
    "x.com", "twitter.com", "facebook.com", "fb.com",
    "instagram.com", "threads.net", "forms.gle",
    "google.com", "googleapis.com", "gstatic.com",
    "youtube.com", "youtu.be", "linkedin.com",
    "tiktok.com", "discord.com", "discord.gg",
    "reddit.com", "redd.it", "github.com", "gitlab.com",
    "medium.com", "whatsapp.com", "apple.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "cloudflare.com", "paypal.com",
    "binance.com", "bybit.com", "bybit.net", "coinbase.com",
    "okx.com", "kucoin.com", "gate.io", "huobi.com", "kraken.com",
    "tradingview.com", "trustwallet.com", "metamask.io", "substack.com",
]

EXTRA_WHITELIST = [
    h.strip().lower().replace("www.", "")
    for h in os.getenv("TELEGRAM_KNOWN_HOST_WHITELIST", "").split(",")
    if h.strip()
]

KNOWN_HOST_SUFFIXES = list(dict.fromkeys(DEFAULT_KNOWN_HOST_SUFFIXES + EXTRA_WHITELIST))
# =======================================================


def session_file_path() -> Path:
    return Path(__file__).parent / f"{SESSION_NAME}.session"


def is_session_conflict_error(err: BaseException) -> bool:
    msg = str(err).lower()
    return (
        isinstance(err, AuthKeyDuplicatedError)
        or "two different ip addresses" in msg
        or ("authorization key" in msg and "simultaneously" in msg)
    )


def handle_dead_session():
    session_path = session_file_path()
    lock_path = Path(__file__).parent / ".scraper.lock"
    print("\n" + "=" * 60)
    print("FATAL: Telegram session was used from two places at once.")
    print("=" * 60)
    print("Telegram killed this session. Fix:")
    print("  1. Stop the OTHER backend (local OR Render — only one may run scraper)")
    print("  2. Log in again from the frontend: Telegram Login section")
    print("  3. On Render: update TELEGRAM_SESSION_B64 after re-login")
    print("=" * 60 + "\n")
    if session_path.exists():
        session_path.unlink(missing_ok=True)
        print(f"[scraper] Deleted dead session: {session_path}")
    lock_path.unlink(missing_ok=True)
    sys.exit(2)


def acquire_scraper_lock() -> bool:
    """Only one scraper process per machine."""
    lock_path = Path(__file__).parent / ".scraper.lock"
    if lock_path.exists():
        try:
            pid = int(lock_path.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
            print(f"[scraper] Another scraper is already running (pid {pid}). Exiting.")
            return False
        except (OSError, ValueError):
            lock_path.unlink(missing_ok=True)
    lock_path.write_text(str(os.getpid()), encoding="utf-8")
    return True


def release_scraper_lock():
    lock_path = Path(__file__).parent / ".scraper.lock"
    try:
        if lock_path.exists() and lock_path.read_text(encoding="utf-8").strip() == str(os.getpid()):
            lock_path.unlink(missing_ok=True)
    except Exception:
        pass


def load_keywords() -> list[str]:
    """Load keywords from the shared JSON file (frontend-managed); fall back to env."""
    try:
        with open(KEYWORDS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            kws = [str(k).strip().lower() for k in data if str(k).strip()]
            if kws:
                return kws
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return ENV_KEYWORDS


def parse_dt(date_text: str | None, fallback_now: bool = False) -> datetime | None:
    if not date_text:
        return datetime.now(timezone.utc) if fallback_now else None
    dt = datetime.fromisoformat(date_text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def resolve_date_range() -> tuple[datetime, datetime]:
    to_date = parse_dt(TO_DATE, fallback_now=True)
    if TODAY_ONLY:
        from_date = to_date.replace(hour=0, minute=0, second=0, microsecond=0)
        return from_date, to_date
    if FORCE_LOOKBACK or not FROM_DATE.strip():
        from_date = to_date - timedelta(days=LOOKBACK_DAYS)
    else:
        from_date = parse_dt(FROM_DATE) or (to_date - timedelta(days=LOOKBACK_DAYS))
    return from_date, to_date


def extract_domain(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
        return host.split(":")[0] if host else ""
    except Exception:
        return ""


def load_seen_domains() -> dict[str, str]:
    """domain -> first_seen date (YYYY-MM-DD)."""
    try:
        with open(SEEN_DOMAINS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_seen_domains(seen: dict[str, str]) -> None:
    with open(SEEN_DOMAINS_FILE, "w", encoding="utf-8") as f:
        json.dump(seen, f, indent=2)


def ensure_today_output_file() -> None:
    """Reset urls_only.csv at the start of each UTC day (display = today only)."""
    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        if Path(URLS_ONLY_DATE_FILE).read_text(encoding="utf-8").strip() == today:
            return
    except FileNotFoundError:
        pass
    for path in (SCRAPED_URLS_ONLY, SCRAPED_FULL_CSV):
        if os.path.exists(path):
            os.remove(path)
    Path(URLS_ONLY_DATE_FILE).write_text(today, encoding="utf-8")
    print(f"[scraper] New day ({today}) — cleared today's output CSV")


def filter_new_domain_records(records: list[dict]) -> tuple[list[dict], int]:
    """Keep only domains never seen before. Returns (new_records, skipped_count)."""
    seen = load_seen_domains()
    new_records: list[dict] = []
    skipped = 0
    batch_domains: set[str] = set()

    for r in records:
        domain = extract_domain(r.get("url", ""))
        if not domain:
            skipped += 1
            continue
        if domain in seen or domain in batch_domains:
            skipped += 1
            continue
        batch_domains.add(domain)
        seen[domain] = (r.get("date") or "")[:10] or datetime.now(timezone.utc).date().isoformat()
        new_records.append({**r, "domain": domain})

    if new_records:
        save_seen_domains(seen)

    return new_records, skipped


def message_datetime_utc(message) -> datetime:
    dt = message.date
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def host_matches_suffix(host: str, suffix: str) -> bool:
    return host == suffix or host.endswith(f".{suffix}")


def is_known_or_internal(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().replace("www.", "")
        if not host:
            return True
        if "telegram" in host or host.endswith(".t.me") or host == "t.me":
            return True
        return any(host_matches_suffix(host, s) for s in KNOWN_HOST_SUFFIXES)
    except Exception:
        return True


def extract_urls_from_message(message) -> list[str]:
    urls: set[str] = set()
    text = message.message or ""
    urls.update(re.findall(r'https?://[^\s<>"\']+', text))

    if message.entities:
        for entity in message.entities:
            if isinstance(entity, (MessageEntityUrl, MessageEntityTextUrl)):
                if hasattr(entity, "url") and entity.url:
                    urls.add(entity.url)
                else:
                    snippet = text[entity.offset: entity.offset + entity.length]
                    if snippet.startswith("http"):
                        urls.add(snippet)

    return [
        u for u in urls
        if urlparse(u).scheme in ("http", "https") and not is_known_or_internal(u)
    ]


def normalize_username(username: str | None) -> str | None:
    if not username:
        return None
    u = username.strip().replace("@", "")
    return u or None


def append_records(records: list[dict]) -> int:
    if not records:
        return 0
    ensure_today_output_file()
    new_records, skipped = filter_new_domain_records(records)
    if not new_records:
        if skipped:
            print(f"   [+] 0 new domains ({skipped} duplicates skipped)")
        return 0

    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)
    df = pd.DataFrame(new_records)

    header_urls = not os.path.exists(SCRAPED_URLS_ONLY)
    url_cols = ["domain", "url", "channel", "date", "message_id", "views", "has_photo"]
    df[url_cols].to_csv(SCRAPED_URLS_ONLY, mode="a", index=False, header=header_urls)

    if not URLS_ONLY_MODE:
        header_full = not os.path.exists(SCRAPED_FULL_CSV)
        df.to_csv(SCRAPED_FULL_CSV, mode="a", index=False, header=header_full)

    print(
        f"   [+] Saved {len(new_records)} NEW domains "
        f"({skipped} duplicates skipped) → {SCRAPED_URLS_ONLY}"
    )
    return len(new_records)


def deduplicate_csv() -> int:
    """Remove duplicate domains from today's output file."""
    if not os.path.exists(SCRAPED_URLS_ONLY):
        return 0
    try:
        df = pd.read_csv(SCRAPED_URLS_ONLY)
        if df.empty:
            return 0
        if "domain" not in df.columns:
            df["domain"] = df["url"].map(extract_domain)
        before = len(df)
        df = df.drop_duplicates(subset=["domain"], keep="first")
        df.to_csv(SCRAPED_URLS_ONLY, index=False)
        removed = before - len(df)
        if removed:
            print(f"[dedup] Removed {removed} duplicate domains. {len(df)} unique today.")
        return len(df)
    except Exception as e:
        print(f"[dedup] Failed: {e}")
        return 0


def build_record(message, channel_username: str, url: str) -> dict:
    return {
        "channel":      channel_username,
        "message_id":   message.id,
        "date":         message_datetime_utc(message).isoformat(),
        "url":          url,
        "has_photo":    bool(getattr(message, "photo", None)),
        "views":        getattr(message, "views", None),
        "text_snippet": (message.message or "")[:400],
    }


# ── Channel discovery ─────────────────────────────────────────────

async def discover_public_channels(client: TelegramClient, keywords: list[str]) -> list[str]:
    queries = AUTO_FIND_QUERIES or keywords[:12] or ["crypto signal", "airdrop", "giveaway"]
    found: list[str] = []
    seen: set[str] = set(CHANNELS)  # don't re-add manually configured channels

    print(f"[discovery] Searching for public channels using {len(queries)} queries...")

    for query in queries:
        if len(found) >= AUTO_FIND_MAX_CHANNELS:
            break
        try:
            result = await client(SearchRequest(q=query, limit=AUTO_FIND_LIMIT_PER_QUERY))
        except FloodWaitError as e:
            print(f"   [!] Flood wait {e.seconds}s...")
            await asyncio.sleep(e.seconds)
            continue
        except Exception as e:
            print(f"   [!] Discovery failed ({query}): {e}")
            continue

        for chat in result.chats or []:
            username = normalize_username(getattr(chat, "username", None))
            if username and username not in seen:
                seen.add(username)
                found.append(username)
            if len(found) >= AUTO_FIND_MAX_CHANNELS:
                break

    print(f"[discovery] Found {len(found)} new public channels")
    return found


# ── Batch scrape ──────────────────────────────────────────────────

async def scrape_channel(
    client: TelegramClient,
    channel_username: str,
    from_date: datetime,
    to_date: datetime,
    keywords: list[str],
) -> list[dict]:
    records = []
    print(f"\n[batch] @{channel_username}  {from_date.date()} → {to_date.date()}")

    try:
        entity = await client.get_entity(channel_username)
    except Exception as e:
        print(f"   [!] Cannot access @{channel_username}: {e}")
        return records

    count = 0
    skipped_old = 0

    async for message in client.iter_messages(
        entity, limit=MAX_MESSAGES_PER_CHANNEL, offset_date=to_date, reverse=False
    ):
        posted = message_datetime_utc(message)
        if posted < from_date:
            skipped_old += 1
            break
        if posted > to_date:
            continue

        count += 1
        if count % 200 == 0:
            print(f"   ... {count} messages processed")

        try:
            text = message.message or ""
            if not text:
                continue
            if keywords and not any(kw in text.lower() for kw in keywords):
                continue
            for url in extract_urls_from_message(message):
                records.append(build_record(message, channel_username, url))
        except UnicodeEncodeError:
            continue
        except Exception:
            continue

    print(f"   [+] {len(records)} suspicious URLs found (skipped {skipped_old} old posts)")
    return records


async def run_batch(client: TelegramClient, channels: list[str], keywords: list[str]) -> list[str]:
    """Batch-scrape all channels. Returns the final channel list (with auto-discovered)."""
    ensure_today_output_file()
    from_date, to_date = resolve_date_range()
    print(f"\n[batch] Window: {from_date.date()} → {to_date.date()}" +
          (" (today only)" if TODAY_ONLY else ""))
    print(f"[batch] Keywords: {keywords or '(all messages)'}")
    seen_count = len(load_seen_domains())
    print(f"[batch] Known domains (skip duplicates): {seen_count}")

    all_channels = list(CHANNELS)
    if AUTO_FIND_CHANNELS:
        discovered = await discover_public_channels(client, keywords)
        all_channels = list(dict.fromkeys(all_channels + discovered))

    if not all_channels:
        print("[batch] No channels to scrape. Set TELEGRAM_SCRAPE_CHANNELS or TELEGRAM_AUTO_FIND_CHANNELS=true")
        return all_channels

    print(f"[batch] Scraping {len(all_channels)} channels...\n")

    new_count = 0
    for ch in all_channels:
        try:
            recs = await scrape_channel(client, ch, from_date, to_date, keywords)
            new_count += append_records(recs)
        except FloodWaitError as e:
            print(f"[!] Flood wait {e.seconds}s...")
            await asyncio.sleep(e.seconds)
        except Exception as e:
            print(f"[!] Error @{ch}: {repr(e)}")

    total = deduplicate_csv()
    print(f"\n[batch] Done — {new_count} new domains today. {total} unique in today's CSV.\n")
    return all_channels


# ── Watch mode ────────────────────────────────────────────────────

async def run_watch(client: TelegramClient, channels: list[str]) -> None:
    """Register real-time event handlers for new messages."""
    if not channels:
        print("[watch] No channels to watch.")
        return

    print(f"\n[watch] Resolving {len(channels)} channel entities...")
    entities = []
    for ch in channels:
        try:
            entities.append(await client.get_entity(ch))
            print(f"   [+] Watching @{ch}")
        except Exception as e:
            print(f"   [!] Cannot watch @{ch}: {e}")

    if not entities:
        print("[watch] No valid channels.")
        return

    @client.on(events.NewMessage(chats=entities))
    async def handler(event):
        keywords = load_keywords()  # reload every message for instant keyword updates
        message = event.message
        text = message.message or ""
        if not text:
            return
        if keywords and not any(kw in text.lower() for kw in keywords):
            return

        try:
            channel_username = (
                event.chat.username or str(event.chat_id)
            )
        except Exception:
            channel_username = str(event.chat_id)

        urls = extract_urls_from_message(message)
        if not urls:
            return

        records = [build_record(message, channel_username, url) for url in urls]
        print(f"[watch] @{channel_username}: {len(urls)} suspicious URL(s) found → saving")
        append_records(records)

    print(f"\n[watch] Listening for new messages on {len(entities)} channels...\n")


# ── Continuous mode ───────────────────────────────────────────────

async def run_continuous(client: TelegramClient) -> None:
    """
    1. Batch-scrape discovered channels with current keywords
    2. Start real-time watch on those channels
    3. Every REDISCOVER_HOURS: re-discover channels + batch again
    """
    print(f"[continuous] Re-discovery interval: every {REDISCOVER_HOURS}h")
    keywords = load_keywords()
    channels = await run_batch(client, list(CHANNELS), keywords)
    await run_watch(client, channels)

    while True:
        sleep_seconds = REDISCOVER_HOURS * 3600
        print(f"[continuous] Next re-discovery in {REDISCOVER_HOURS}h...")
        await asyncio.sleep(sleep_seconds)

        keywords = load_keywords()
        print(f"\n[continuous] Re-discovering channels (keywords: {keywords})...")
        new_channels = await run_batch(client, list(CHANNELS), keywords)
        # Watch mode handlers are already registered; new channels need manual addition
        # (Telethon doesn't support dynamic chats addition to existing handlers)
        # Log for awareness — full restart picks them up
        added = [ch for ch in new_channels if ch not in channels]
        if added:
            print(f"[continuous] {len(added)} new channels found: {added}")
            print("[continuous] Restart scraper to add them to watch mode.")
        channels = new_channels


# ── Entry point ───────────────────────────────────────────────────

async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "continuous"

    if not API_ID or not API_HASH or not PHONE:
        raise ValueError("Missing API_ID, API_HASH, or PHONE in backend/.env")

    if not acquire_scraper_lock():
        sys.exit(0)

    os.makedirs(SCRAPED_OUTPUT_DIR, exist_ok=True)

    print("=" * 50)
    print("  ThreatRadar — Telegram Scam Scraper")
    print("=" * 50)
    print(f"Mode:          {mode}")
    print(f"Keywords file: {KEYWORDS_FILE}")
    print(f"Keywords:      {load_keywords() or '(all — no filter)'}")
    print(f"Manual channels: {CHANNELS or '(none — auto-discover only)'}")
    print(f"Auto-discover: {AUTO_FIND_CHANNELS}")
    print(f"Output dir:    {SCRAPED_OUTPUT_DIR}")
    print("=" * 50 + "\n")

    session_path = session_file_path()
    if not session_path.exists():
        print("\n" + "="*55)
        print("ERROR: No Telegram session file found.")
        print("="*55)
        print("You must generate the session locally first:\n")
        print("  1. Run locally:  python scrape.py batch")
        print("  2. Log in with your phone + verification code")
        print("  3. Encode the session:")
        print("     python -c \"import base64; print(base64.b64encode(")
        print("       open('scraper_session.session','rb').read()).decode())\"")
        print("  4. Set the output as TELEGRAM_SESSION_B64 in Render env vars")
        print("="*55 + "\n")
        sys.exit(1)

    client = TelegramClient(
        SESSION_NAME,
        API_ID,
        API_HASH,
        connection_retries=10,
        retry_delay=2,
        auto_reconnect=True,
        request_retries=5,
    )

    reconnect_delay = 30  # seconds between full reconnects

    while True:
        try:
            await client.connect()

            if not await client.is_user_authorized():
                print("\nERROR: Session file exists but is not authorized.")
                print("Delete scraper_session.session and re-run locally to re-authenticate.")
                sys.exit(1)

            print("[+] Logged in to Telegram.\n")

            if mode == "batch":
                keywords = load_keywords()
                await run_batch(client, list(CHANNELS), keywords)
                break  # batch mode exits after one run

            elif mode == "watch":
                channels = list(CHANNELS)
                if AUTO_FIND_CHANNELS:
                    channels = list(dict.fromkeys(
                        channels + await discover_public_channels(client, load_keywords())
                    ))
                await run_watch(client, channels)
                await client.run_until_disconnected()
                break

            else:  # continuous (default)
                await run_continuous(client)
                await client.run_until_disconnected()
                break

        except EOFError:
            print("\nERROR: Telegram asked for interactive input (no valid session).")
            print("Set TELEGRAM_SESSION_B64 in Render environment variables.")
            sys.exit(1)

        except AuthKeyDuplicatedError:
            handle_dead_session()

        except (ConnectionError, TimeoutError, OSError) as e:
            if is_session_conflict_error(e):
                handle_dead_session()
            print(f"\n[!] Telegram connection lost: {e}")
            print(f"[!] Reconnecting in {reconnect_delay}s...")
            try:
                await client.disconnect()
            except Exception:
                pass
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 300)  # cap at 5 min

        except KeyboardInterrupt:
            print("\n[scraper] Stopped by user.")
            break

        except Exception as e:
            if is_session_conflict_error(e):
                handle_dead_session()
            print(f"\n[!] Unexpected error: {e}")
            print(f"[!] Reconnecting in {reconnect_delay}s...")
            try:
                await client.disconnect()
            except Exception:
                pass
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 300)

        finally:
            try:
                await client.disconnect()
            except Exception:
                pass
            release_scraper_lock()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        release_scraper_lock()
