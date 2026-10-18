"""Download legitimate brand logos for the Brand Reference catalog.

Sources (official domain only — never Zenodo phishing assets):
  1. Clearbit Logo API: https://logo.clearbit.com/{domain}
  2. Google favicon service (fallback): sz=128
  3. Icons declared by the official homepage (apple-touch-icon / icon links), then its header logo
  4. Wikidata "logo image" (P154), only for the item whose official website (P856) matches the domain

Usage:
  python scripts/collect_brand_logos.py
  python scripts/collect_brand_logos.py --dry-run
  python scripts/collect_brand_logos.py --only-missing   # brands that already have a logo are left untouched
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import httpx
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
STATUS = ROOT / "data" / "annotations" / "brand_checklist_status.json"
LOGOS = ROOT / "data" / "reference" / "brands"
MIN_SIDE = 48
UA = "ScamTrace-C3-BrandReference/1.0 (research; legitimate logo collection)"


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


def validate_image(raw: bytes) -> tuple[bytes, str, int, int]:
    with Image.open(io.BytesIO(raw)) as image:
        image.load()
        width, height = image.size
        wordmark = max(width, height) >= 120 and min(width, height) >= 24
        if min(width, height) < MIN_SIDE and not wordmark:
            raise ValueError(f"too small {width}x{height}")
        if image.mode in ("RGBA", "P") or "A" in image.getbands():
            image = image.convert("RGBA")
        else:
            image = image.convert("RGB")
        out = io.BytesIO()
        image.save(out, format="PNG")
        return out.getvalue(), ".png", width, height


def fetch(url: str, client: httpx.Client) -> bytes:
    response = client.get(url, follow_redirects=True)
    if response.status_code != 200:
        raise ValueError(f"HTTP {response.status_code}")
    ctype = (response.headers.get("content-type") or "").lower()
    if "html" in ctype:
        raise ValueError(f"not an image ({ctype})")
    if len(response.content) < 200:
        raise ValueError("empty body")
    return response.content


SIMPLE_ICON_SLUG = {
    "dhl": "dhl",
    "whatsapp": "whatsapp",
    "ebay": "ebay",
    "hdfcbank": "hdfcbank",
    "amazon": "amazon",
    "apple": "apple",
    "att": "atandt",
    "linkedin": "linkedin",
    "netflix": "netflix",
    "microsoft": "microsoft",
}


def candidate_urls(domain: str, brand_id: str) -> list[str]:
    slug = SIMPLE_ICON_SLUG.get(brand_id, brand_id)
    return [
        f"https://logo.clearbit.com/{domain}",
        f"https://logo.clearbit.com/www.{domain}",
        f"https://cdn.simpleicons.org/{slug}",
        f"https://icons.duckduckgo.com/ip3/{domain}.ico",
        f"https://www.google.com/s2/favicons?domain={domain}&sz=256",
        f"https://www.google.com/s2/favicons?domain={domain}&sz=128",
    ]


def official_site_icons(website: str, client: httpx.Client) -> list[str]:
    """Icons the official homepage declares (apple-touch-icon / icon links), largest first, then its header logo."""
    try:
        response = client.get(website, follow_redirects=True)
    except httpx.HTTPError:
        return []
    host = response.url.host
    found: list[tuple[int, str]] = []
    for tag in re.findall(r"<link\b[^>]*>", response.text, re.I):
        rel = re.search(r'rel=["\']([^"\']+)["\']', tag, re.I)
        href = re.search(r'href=["\']([^"\']+)["\']', tag, re.I)
        if not rel or not href or "icon" not in rel.group(1).lower():
            continue
        sizes = re.search(r'sizes=["\'](\d+)x\d+["\']', tag, re.I)
        size = int(sizes.group(1)) if sizes else (180 if "apple" in rel.group(1).lower() else 32)
        found.append((size, urljoin(str(response.url), href.group(1))))
    header_logo = next((urljoin(str(response.url), src) for src in re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', response.text, re.I)
                        if "logo" in src.lower() and httpx.URL(urljoin(str(response.url), src)).host == host), None)
    return [url for _, url in sorted(found, reverse=True)] + ([header_logo] if header_logo else [])


def _same_site(host: str, domain: str) -> bool:
    if host == domain or host.endswith("." + domain) or domain.endswith("." + host):
        return True
    # e.g. sbi.co.in (Wikidata) vs onlinesbi.sbi (dataset): same organisation label.
    return host.split(".")[0] in domain.split(".")


def wikidata_logo(names: list[str], domain: str, client: httpx.Client) -> list[str]:
    """Wikidata "logo image" (P154) of the item whose official website (P856) is on ``domain``."""
    api = "https://www.wikidata.org/w/api.php"
    seen: set[str] = set()
    try:
        for name in names:
            hits = client.get(api, params={"action": "wbsearchentities", "search": name, "language": "en",
                                           "format": "json", "limit": 5}).json().get("search", [])
            for hit in hits:
                if hit["id"] in seen:
                    continue
                seen.add(hit["id"])
                claims = client.get(api, params={"action": "wbgetentities", "ids": hit["id"], "props": "claims",
                                                 "format": "json"}).json()["entities"][hit["id"]].get("claims", {})
                sites = [c["mainsnak"].get("datavalue", {}).get("value", "") for c in claims.get("P856", [])]
                hosts = [httpx.URL(site).host.removeprefix("www.") for site in sites if site.startswith("http")]
                logos = [c["mainsnak"].get("datavalue", {}).get("value") for c in claims.get("P154", [])]
                if logos and any(_same_site(host, domain) for host in hosts):
                    return [f"https://commons.wikimedia.org/wiki/Special:FilePath/{logo.replace(' ', '_')}?width=256"
                            for logo in logos if logo]
    except (httpx.HTTPError, KeyError, ValueError):
        return []
    return []


def download_logo(domain: str, brand_id: str, client: httpx.Client,
                  website: str | None = None, names: list[str] | None = None) -> tuple[bytes, str, int, int, str]:
    errors: list[str] = []
    best: tuple[bytes, str, int, int, str] | None = None
    candidates = candidate_urls(domain, brand_id)
    if website:
        candidates += official_site_icons(website, client)
    if names:
        candidates += wikidata_logo(names, domain, client)
    for url in candidates:
        try:
            raw = fetch(url, client)
            if raw.lstrip()[:200].lower().startswith((b"<svg", b"<?xml")) and b"<svg" in raw[:2000].lower():
                # Vector logo (e.g. Simple Icons); normalize_brand_logos.py rasterizes it.
                return raw, ".svg", 256, 256, url
            payload, ext, width, height = validate_image(raw)
            score = width * height
            if best is None or score > best[2] * best[3]:
                best = (payload, ext, width, height, url)
            if min(width, height) >= 128:
                return best
        except Exception as exc:
            errors.append(f"{url.split('?', 1)[0]}: {exc}")
    if best:
        return best
    raise RuntimeError("; ".join(errors[:3]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--delay", type=float, default=0.6)
    parser.add_argument("--only-missing", action="store_true", help="Skip brands that already have a logo file")
    args = parser.parse_args()

    LOGOS.mkdir(parents=True, exist_ok=True)
    rows = load_catalog()
    ok = 0
    fail = 0

    with httpx.Client(timeout=30.0, headers={"User-Agent": UA}) as client:
        for row in rows:
            brand_id = row["brand_id"]
            domain = row.get("official_domain") or ""
            existing = LOGOS / f"{brand_id}_primary.png"
            if args.only_missing and (existing.is_file() or row.get("reference_images")):
                ok += 1
                continue
            if not domain:
                print(f"[skip] {brand_id}: no domain")
                fail += 1
                continue
            if args.dry_run:
                print(f"[dry-run] {brand_id} <- {domain}")
                continue
            try:
                names = [n for n in [row.get("display_name"), *(row.get("aliases") or [])] if n]
                payload, ext, width, height, source = download_logo(domain, brand_id, client, row.get("official_website"),
                                                                    names)
                name = f"{brand_id}_primary{ext}"
                path = LOGOS / name
                path.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                rel = f"data/reference/brands/{name}"
                row["reference_images"] = [rel]
                row["logo_sha256"] = digest
                row["logo_source"] = source
                row["logo_size"] = [width, height]
                row["collection_method"] = "public_dataset"
                row["status"] = "logo_collected"
                row["logo_collected_at"] = datetime.now(timezone.utc).isoformat()
                print(f"[ok] {brand_id} {width}x{height} -> {name}")
                ok += 1
            except Exception as exc:
                print(f"[fail] {brand_id} ({domain}): {exc}")
                fail += 1
            time.sleep(args.delay)

    if not args.dry_run:
        save_catalog(rows)
        mark_checklist("Collect legitimate brand logos", ok > 0 and fail == 0)
        print(f"Done: {ok} saved, {fail} failed. Catalog updated.")


if __name__ == "__main__":
    main()
