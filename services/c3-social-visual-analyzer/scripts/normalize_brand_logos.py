"""Normalize brand reference logos and drop exact / near duplicates.

Steps:
  1. Rasterize SVG logos to PNG (Playwright).
  2. Convert to RGB on a white background, EXIF-orient, fit on a 256x256 canvas.
  3. Write data/reference/brands/{brand_id}_normalized.png
  4. Compute perceptual hashes; keep one file per duplicate group.
  5. Update brand_catalog.jsonl and checklist status.

Usage:
  set PLAYWRIGHT_BROWSERS_PATH=%LOCALAPPDATA%\\ms-playwright
  python scripts/normalize_brand_logos.py
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import imagehash
from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
STATUS = ROOT / "data" / "annotations" / "brand_checklist_status.json"
LOGOS = ROOT / "data" / "reference" / "brands"
CANVAS = 256
BACKGROUND = (255, 255, 255)
# Brand icons on white canvases often look similar to pHash alone.
# Require several hashes to agree before treating logos as duplicates.
PHASH_MAX = 2
AHASH_MAX = 2
DHASH_MAX = 4
COLORHASH_MAX = 2


def load_catalog() -> list[dict]:
    return [json.loads(line) for line in CATALOG.read_text(encoding="utf-8").splitlines() if line.strip()]


def save_catalog(rows: list[dict]) -> None:
    CATALOG.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")


def mark_checklist(names: list[str], done: bool) -> None:
    data = json.loads(STATUS.read_text(encoding="utf-8"))
    wanted = set(names)
    for entry in data.get("items", []):
        if entry.get("item") in wanted:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data.get("items", []) if entry.get("done"))
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def primary_path(brand_id: str) -> Path | None:
    for ext in (".png", ".jpg", ".jpeg", ".webp", ".svg"):
        path = LOGOS / f"{brand_id}_primary{ext}"
        if path.is_file():
            return path
    return None


def rasterize_svg(svg_path: Path) -> Image.Image:
    from playwright.sync_api import sync_playwright

    raw = svg_path.read_text(encoding="utf-8", errors="replace")
    html = f"""<!doctype html><html><body style="margin:0;background:#fff">
    <div id="box" style="width:{CANVAS}px;height:{CANVAS}px;display:flex;align-items:center;justify-content:center">
    {raw}
    </div></body></html>"""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": CANVAS, "height": CANVAS})
        page.set_content(html, wait_until="load")
        page.eval_on_selector("svg", f"""(el) => {{
          el.setAttribute('width', '{CANVAS}');
          el.setAttribute('height', '{CANVAS}');
          if (!el.getAttribute('viewBox') && el.width && el.height) {{
            /* keep existing viewBox when present */
          }}
        }}""")
        png = page.locator("#box").screenshot(type="png")
        browser.close()
    return Image.open(io.BytesIO(png)).convert("RGBA")


def load_logo(path: Path) -> Image.Image:
    if path.suffix.lower() == ".svg":
        return rasterize_svg(path)
    image = Image.open(path)
    image.load()
    return ImageOps.exif_transpose(image)


def to_rgb(image: Image.Image) -> Image.Image:
    if image.mode == "RGB" and "transparency" not in image.info:
        return image.copy()
    rgba = image.convert("RGBA")
    canvas = Image.new("RGBA", rgba.size, (*BACKGROUND, 255))
    return Image.alpha_composite(canvas, rgba).convert("RGB")


def fit_square(image: Image.Image, size: int = CANVAS) -> Image.Image:
    rgb = to_rgb(image)
    rgb.thumbnail((size, size), Image.Resampling.LANCZOS)
    canvas = Image.new("RGB", (size, size), BACKGROUND)
    offset = ((size - rgb.size[0]) // 2, (size - rgb.size[1]) // 2)
    canvas.paste(rgb, offset)
    return canvas


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only-missing", action="store_true",
                        help="Leave already-normalized brands untouched (they still take part in the duplicate check)")
    args = parser.parse_args()
    LOGOS.mkdir(parents=True, exist_ok=True)
    rows = load_catalog()
    normalized: dict[str, dict] = {}
    hash_sets: dict[str, dict] = {}

    for row in rows:
        brand_id = row["brand_id"]
        done = ROOT / row["normalized_image"] if row.get("normalized_image") else None
        if args.only_missing and done and done.is_file():
            with Image.open(done) as kept_image:
                kept_image = kept_image.convert("RGB")
                hash_sets[brand_id] = {"sha256": row.get("normalized_sha256"), "phash": imagehash.phash(kept_image),
                                       "ahash": imagehash.average_hash(kept_image), "dhash": imagehash.dhash(kept_image),
                                       "colorhash": imagehash.colorhash(kept_image)}
            normalized[brand_id] = row
            continue
        source = primary_path(brand_id)
        if not source:
            print(f"[fail] {brand_id}: no primary logo")
            continue
        try:
            fitted = fit_square(load_logo(source))
            out = LOGOS / f"{brand_id}_normalized.png"
            fitted.save(out, format="PNG", optimize=True)
            digest = hashlib.sha256(out.read_bytes()).hexdigest()
            hash_sets[brand_id] = {
                "sha256": digest,
                "phash": imagehash.phash(fitted),
                "ahash": imagehash.average_hash(fitted),
                "dhash": imagehash.dhash(fitted),
                "colorhash": imagehash.colorhash(fitted),
            }
            rel = f"data/reference/brands/{out.name}"
            row["normalized_image"] = rel
            row["normalized_sha256"] = digest
            row["normalized_size"] = [CANVAS, CANVAS]
            row["phash"] = str(hash_sets[brand_id]["phash"])
            row.pop("duplicate_of", None)
            row["status"] = "normalized"
            row["normalized_at"] = datetime.now(timezone.utc).isoformat()
            refs = [f"data/reference/brands/{source.name}", rel]
            row["reference_images"] = list(dict.fromkeys(refs))
            normalized[brand_id] = row
            print(f"[ok] {brand_id} <- {source.name} -> {out.name}")
        except Exception as exc:
            print(f"[fail] {brand_id}: {exc}")

    def is_duplicate(left: dict, right: dict) -> bool:
        if left["sha256"] == right["sha256"]:
            return True
        return (
            left["phash"] - right["phash"] <= PHASH_MAX
            and left["ahash"] - right["ahash"] <= AHASH_MAX
            and left["dhash"] - right["dhash"] <= DHASH_MAX
            and left["colorhash"] - right["colorhash"] <= COLORHASH_MAX
        )

    kept: set[str] = set()
    duplicate_of: dict[str, str] = {}
    ordered = list(hash_sets.keys())
    for index, brand_id in enumerate(ordered):
        if brand_id in duplicate_of:
            continue
        kept.add(brand_id)
        for other in ordered[index + 1 :]:
            if other in duplicate_of:
                continue
            if is_duplicate(hash_sets[brand_id], hash_sets[other]):
                duplicate_of[other] = brand_id
                other_row = normalized[other]
                other_row["duplicate_of"] = brand_id
                other_row["status"] = "duplicate_logo"
                print(f"[dup] {other} matches {brand_id}")

    save_catalog(rows)
    mark_checklist(["Normalize reference logos", "Remove duplicate logos"], True)
    print(f"Normalized {len(normalized)} logos, unique {len(kept)}, duplicates {len(duplicate_of)}")


if __name__ == "__main__":
    main()
