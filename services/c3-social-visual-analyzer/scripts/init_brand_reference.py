"""Build the Brand Reference catalog from Zenodo brands.csv (checklist start).

Reads official brand names / domains / identifiers from the Zenodo_Phishing
brands table. Does not download logos or visit websites.

Layout (matches C3 data conventions):
  data/annotations/brand_catalog.jsonl   — tracked metadata
  data/annotations/brand_checklist_status.json
  data/reference/brands/                 — legitimate logos (gitignored)
  data/reference/brand_screenshots/      — official site shots (gitignored)
  data/annotations/logo_boxes.jsonl      — bbox annotations (created empty)

Usage:
  python scripts/init_brand_reference.py
  python scripts/init_brand_reference.py --zenodo-root "D:/Reasearch/Datasets/Zenodo_Phishing"
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANNOTATIONS = ROOT / "data" / "annotations"
REFERENCE = ROOT / "data" / "reference"
CATALOG_FILE = ANNOTATIONS / "brand_catalog.jsonl"
STATUS_FILE = ANNOTATIONS / "brand_checklist_status.json"
BOXES_FILE = ANNOTATIONS / "logo_boxes.jsonl"
LOGOS_DIR = REFERENCE / "brands"
SHOTS_DIR = REFERENCE / "brand_screenshots"
LEGACY_DIR = ROOT / "data" / "brand_reference"

INITIAL_BRAND_IDS = [
    "microsoft",
    "facebook",
    "paypal",
    "amazon",
    "adobe",
    "apple",
    "google",
    "att",
    "dhl",
    "usps",
    "steam",
    "metamask",
    "coinbase",
    "whatsapp",
    "bankofamerica",
    "chase",
    "citibank",
    "ebay",
    "yahoo",
    "instagram",
    "linkedin",
    "netflix",
    "dbsbank",
    "hdfcbank",
]

NAME_FIXES = {
    "att": "AT&T",
}

CHECKLIST = [
    "Select initial target brands",
    "Collect legitimate brand logos",
    "Collect official website screenshots",
    "Record official brand names",
    "Record official domains",
    "Normalize reference logos",
    "Remove duplicate logos",
    "Assign brand IDs",
    "Create logo annotations",
    "Create bounding-box annotations",
    "Create train/validation/test split",
    "Store brand metadata",
    "Generate brand dataset statistics",
]


def load_zenodo_brands(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return {str(row["identifier"]).strip().lower(): row for row in rows if row.get("identifier")}


def build_records(zenodo: dict[str, dict]) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    records: list[dict] = []
    for brand_id in INITIAL_BRAND_IDS:
        src = zenodo.get(brand_id)
        if not src:
            raise SystemExit(f"Brand id not in Zenodo brands.csv: {brand_id}")
        website = (src.get("website") or "").strip()
        domain = website.replace("https://", "").replace("http://", "").split("/")[0].lower()
        if domain.startswith("www."):
            domain = domain[4:]
        records.append({
            "brand_id": brand_id,
            "display_name": NAME_FIXES.get(brand_id, (src.get("name") or "").strip()),
            "aliases": [],
            "official_domain": domain,
            "official_website": website,
            "category": (src.get("category") or "").strip(),
            "description": (src.get("description") or "").strip(),
            "source": "Zenodo_Phishing/brands.csv",
            "collection_method": "public_dataset",
            "reference_images": [],
            "screenshot_files": [],
            "status": "metadata_only",
            "created_at": now,
        })
    return records


def write_status(done: list[str]) -> None:
    items = [{"item": name, "done": name in done} for name in CHECKLIST]
    STATUS_FILE.write_text(json.dumps({
        "title": "Brand Reference + Annotation Dataset",
        "done_count": sum(1 for item in items if item["done"]),
        "total": len(items),
        "items": items,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")


def ensure_dirs() -> None:
    for path in (ANNOTATIONS, LOGOS_DIR, SHOTS_DIR):
        path.mkdir(parents=True, exist_ok=True)
    for folder in (LOGOS_DIR, SHOTS_DIR):
        keep = folder / ".gitkeep"
        if not keep.exists():
            keep.write_text("", encoding="utf-8")
    if not BOXES_FILE.exists():
        BOXES_FILE.write_text("", encoding="utf-8")


def clear_legacy() -> None:
    if not LEGACY_DIR.exists():
        return
    for child in LEGACY_DIR.rglob("*"):
        if child.is_file():
            child.unlink()
    for child in sorted(LEGACY_DIR.rglob("*"), reverse=True):
        if child.is_dir():
            child.rmdir()
    if LEGACY_DIR.exists():
        LEGACY_DIR.rmdir()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--zenodo-root",
        default=r"D:\Reasearch\Datasets\Zenodo_Phishing",
        help="Folder that contains brands.csv",
    )
    args = parser.parse_args()
    brands_csv = Path(args.zenodo_root) / "brands.csv"
    if not brands_csv.is_file():
        raise SystemExit(f"Missing {brands_csv}")

    ensure_dirs()
    records = build_records(load_zenodo_brands(brands_csv))
    with CATALOG_FILE.open("w", encoding="utf-8") as handle:
        for row in records:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    write_status([
        "Select initial target brands",
        "Record official brand names",
        "Record official domains",
        "Assign brand IDs",
        "Store brand metadata",
    ])
    clear_legacy()

    print(f"Wrote {len(records)} brands -> {CATALOG_FILE}")
    print(f"Checklist -> {STATUS_FILE}")
    print(f"Logo folder -> {LOGOS_DIR}")
    print(f"Screenshot folder -> {SHOTS_DIR}")
    print("Next: collect legitimate logos only (not Zenodo phishing assets).")


if __name__ == "__main__":
    main()
