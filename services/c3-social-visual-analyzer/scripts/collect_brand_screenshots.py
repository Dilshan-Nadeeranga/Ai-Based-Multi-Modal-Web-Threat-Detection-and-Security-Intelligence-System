"""Capture official homepage screenshots for the Brand Reference catalog.

Only opens ``official_website`` values from brand_catalog.jsonl (legitimate
brand sites). Does not open Zenodo phishing URLs or social scrape APIs.

Usage:
  set PLAYWRIGHT_BROWSERS_PATH=%LOCALAPPDATA%\\ms-playwright
  python scripts/collect_brand_screenshots.py
  python scripts/collect_brand_screenshots.py --limit 3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
STATUS = ROOT / "data" / "annotations" / "brand_checklist_status.json"
SHOTS = ROOT / "data" / "reference" / "brand_screenshots"


def load_catalog() -> list[dict]:
    rows = []
    with CATALOG.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def save_catalog(rows: list[dict]) -> None:
    with CATALOG.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def mark_checklist(item: str, done: bool) -> None:
    if not STATUS.exists():
        return
    data = json.loads(STATUS.read_text(encoding="utf-8"))
    for entry in data.get("items", []):
        if entry.get("item") == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data.get("items", []) if entry.get("done"))
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def is_public_http(url: str) -> bool:
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    if not host or host in {"localhost"} or host.endswith(".local"):
        return False
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
        return False
    return True


def capture_one(page, url: str, out_path: Path, *, timeout_ms: int, settle_ms: int, max_height: int) -> dict:
    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    page.wait_for_timeout(settle_ms)
    # Prefer viewport capture so tall marketing pages stay bounded.
    png = page.screenshot(type="png", full_page=False)
    # If the document is short, full_page is fine; clip tall pages.
    try:
        height = page.evaluate("() => Math.min(document.documentElement.scrollHeight || 0, arguments[0])", max_height)
        if 400 < height <= max_height:
            png = page.screenshot(
                type="png",
                clip={"x": 0, "y": 0, "width": page.viewport_size["width"], "height": int(height)},
            )
    except Exception:
        pass
    out_path.write_bytes(png)
    final_url = page.url
    title = ""
    try:
        title = (page.title() or "").strip()[:300]
    except Exception:
        title = ""
    return {
        "final_url": final_url,
        "title": title,
        "http_status": response.status if response else None,
        "bytes": len(png),
        "sha256": hashlib.sha256(png).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=0, help="Capture only the first N brands (0 = all)")
    parser.add_argument("--delay", type=float, default=2.0)
    parser.add_argument("--timeout", type=float, default=35.0)
    parser.add_argument("--settle", type=float, default=2.5)
    parser.add_argument("--only-missing", action="store_true")
    parser.add_argument("--brand-id", action="append", default=[], help="Capture only these brand_id values")
    args = parser.parse_args()

    from playwright.sync_api import sync_playwright

    SHOTS.mkdir(parents=True, exist_ok=True)
    rows = load_catalog()
    if args.brand_id:
        wanted = {value.lower() for value in args.brand_id}
        rows = [row for row in rows if row["brand_id"] in wanted]
    if args.limit > 0:
        rows = rows[: args.limit]

    ok = 0
    fail = 0
    timeout_ms = int(args.timeout * 1000)
    settle_ms = int(args.settle * 1000)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1366, "height": 768},
            locale="en-US",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36 ScamTraceBrandRef/1.0"
            ),
        )
        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        try:
            full_catalog = {row["brand_id"]: row for row in load_catalog()}
            for row in rows:
                brand_id = row["brand_id"]
                url = (row.get("official_website") or "").strip()
                out = SHOTS / f"{brand_id}_home.png"
                catalog_row = full_catalog[brand_id]
                if args.only_missing and out.is_file() and out.stat().st_size > 5000:
                    ok += 1
                    continue
                if not is_public_http(url):
                    print(f"[fail] {brand_id}: bad url")
                    fail += 1
                    continue
                try:
                    meta = capture_one(
                        page, url, out,
                        timeout_ms=timeout_ms,
                        settle_ms=settle_ms,
                        max_height=4000,
                    )
                    rel = f"data/reference/brand_screenshots/{out.name}"
                    catalog_row["screenshot_files"] = [rel]
                    catalog_row["screenshot_sha256"] = meta["sha256"]
                    catalog_row["screenshot_final_url"] = meta["final_url"]
                    catalog_row["screenshot_title"] = meta["title"]
                    catalog_row["screenshot_collected_at"] = datetime.now(timezone.utc).isoformat()
                    if catalog_row.get("status") == "logo_collected":
                        catalog_row["status"] = "logo_and_screenshot"
                    elif catalog_row.get("status") == "metadata_only":
                        catalog_row["status"] = "screenshot_collected"
                    print(f"[ok] {brand_id} {meta['bytes']} bytes <- {meta['final_url'][:80]}")
                    ok += 1
                except Exception as exc:
                    print(f"[fail] {brand_id}: {exc}")
                    fail += 1
                time.sleep(args.delay)
            save_catalog(list(full_catalog.values()))
        finally:
            context.close()
            browser.close()

    all_rows = load_catalog()
    have = sum(1 for row in all_rows if row.get("screenshot_files"))
    mark_checklist("Collect official website screenshots", have == len(all_rows) and fail == 0)
    print(f"Done: {ok} captured this run, {fail} failed. Catalog screenshots: {have}/{len(all_rows)}")


if __name__ == "__main__":
    main()
