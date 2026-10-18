"""Add the remaining Zenodo_Phishing/brands.csv brands to the Brand Reference catalog (appends only).

init_brand_reference.py rewrites the catalog with the initial 24 brands; this script keeps every existing
row (including the Sri Lankan brands from add_local_brands.py) and appends the other Zenodo brands.
Generic labels without an official website (generic, genericemail, genericcrypto, excelpdfdownload) are skipped.

Display names are cleaned where brands.csv uses a domain or an unclear name, because the live analyzer
uses them for CLIP prompts and brand-name matching.

Next steps (only the new brands are processed):
  python scripts/collect_brand_logos.py --only-missing
  python scripts/collect_brand_screenshots.py --only-missing
  python scripts/normalize_brand_logos.py --only-missing
  python scripts/annotate_brand_logos.py
  python scripts/split_brand_dataset.py --keep-existing
  python scripts/generate_brand_statistics.py

Usage:
  python scripts/add_zenodo_brands.py --zenodo-root "D:/Reasearch/Datasets/Zenodo_Phishing"
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_FILE = ROOT / "data" / "annotations" / "brand_catalog.jsonl"

NAME_FIXES = {
    "auid": ("au by KDDI", ["auone.jp", "au ID"]),
    "aol": ("AOL", ["America Online"]),
    "dkb": ("DKB", ["Deutsche Kreditbank"]),
    "govau": ("myGov", ["Australian Government", "my.gov.au"]),
    "impotsgouv": ("impots.gouv.fr", ["Direction generale des Finances publiques"]),
    "sbbch": ("SBB", ["Swiss Federal Railways", "SBB CFF FFS"]),
    "bdobank": ("BDO Unibank", ["Banco de Oro"]),
    "ups": ("UPS", ["United Parcel Service"]),
    "absa": ("Absa", ["Absa Bank", "Amalgamated Banks of South Africa"]),
    "1and1ionos": ("IONOS", ["1&1 IONOS", "1&1"]),
    "yamatotransport": ("Yamato Transport", ["Kuroneko Yamato"]),
    "unionbankph": ("UnionBank", ["Union Bank of the Philippines"]),
    "bancaintesasanpaolo": ("Intesa Sanpaolo", ["Banca Intesa Sanpaolo"]),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zenodo-root", default=r"D:\Reasearch\Datasets\Zenodo_Phishing")
    args = parser.parse_args()
    brands_csv = Path(args.zenodo_root) / "brands.csv"
    if not brands_csv.is_file():
        raise SystemExit(f"Missing {brands_csv}")

    rows = [json.loads(line) for line in CATALOG_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    existing = {row["brand_id"] for row in rows}
    now = datetime.now(timezone.utc).isoformat()
    added, skipped = [], []
    with brands_csv.open(encoding="utf-8", errors="replace", newline="") as handle:
        for src in csv.DictReader(handle):
            brand_id = (src.get("identifier") or "").strip().lower()
            website = (src.get("website") or "").strip()
            if not brand_id or brand_id in existing:
                continue
            if not website.startswith(("http://", "https://")):
                skipped.append(brand_id)
                continue
            domain = website.split("//", 1)[1].split("/", 1)[0].lower().removeprefix("www.")
            name, aliases = NAME_FIXES.get(brand_id, ((src.get("name") or "").strip(), []))
            rows.append({
                "brand_id": brand_id,
                "display_name": name,
                "aliases": aliases,
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
            existing.add(brand_id)
            added.append(brand_id)
            print(f"[add] {brand_id:20} {domain:26} {name}")
    CATALOG_FILE.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(f"Added {len(added)} brand(s), skipped {len(skipped)} without a website ({', '.join(skipped)}); "
          f"catalog now has {len(rows)} brands")


if __name__ == "__main__":
    main()
