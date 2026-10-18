"""Add Sri Lankan brands to the Brand Reference catalog (appends; existing brands are untouched).

Zenodo_Phishing/brands.csv has no Sri Lankan brands, so these come from official registers:
  * banks     - Central Bank of Sri Lanka, list of Licensed Commercial Banks (website column)
  * telecoms  - Wikidata "official website" (P856) of the operator's item

Brand ids and names avoid common words ("Dialog", "Sampath") because the live analyzer matches brand
names in post text. Re-running is safe: brands already in the catalog are skipped.

Next steps (only the new brands are processed):
  python scripts/collect_brand_logos.py --only-missing
  python scripts/collect_brand_screenshots.py --only-missing
  python scripts/normalize_brand_logos.py
  python scripts/annotate_brand_logos.py
  python scripts/split_brand_dataset.py --keep-existing
  python scripts/generate_brand_statistics.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG_FILE = ROOT / "data" / "annotations" / "brand_catalog.jsonl"

CBSL = {
    "source": "Central Bank of Sri Lanka - Licensed Commercial Banks",
    "source_url": "https://www.cbsl.gov.lk/en/authorized-financial-institutions/licensed-commercial-banks",
}


def wikidata(item: str) -> dict:
    return {"source": f"Wikidata {item} official website (P856)", "source_url": f"https://www.wikidata.org/wiki/{item}"}


LOCAL_BRANDS = [
    ("bankofceylon", "Bank of Ceylon", ["BOC"], "https://www.boc.lk/", "Finance", CBSL),
    ("peoplesbank", "People's Bank", ["Peoples Bank"], "https://www.peoplesbank.lk/", "Finance", CBSL),
    ("combank", "Commercial Bank of Ceylon", ["ComBank"], "https://www.combank.lk/", "Finance", CBSL),
    # The CBSL list still gives hnb.net, which no longer resolves; Wikidata and the site's own manifest give hnb.lk.
    ("hnb", "Hatton National Bank", ["HNB"], "https://www.hnb.lk/", "Finance",
     {"source": "Central Bank of Sri Lanka - Licensed Commercial Banks (name); Wikidata Q3532080 official website (P856)",
      "source_url": "https://www.wikidata.org/wiki/Q3532080"}),
    ("sampathbank", "Sampath Bank", ["Sampath Bank PLC"], "https://www.sampath.lk/", "Finance", CBSL),
    ("seylanbank", "Seylan Bank", ["Seylan Bank PLC"], "https://www.seylan.lk/", "Finance", CBSL),
    ("ndbbank", "National Development Bank", ["NDB Bank"], "https://www.ndbbank.com/", "Finance", CBSL),
    ("nationstrust", "Nations Trust Bank", ["Nations Trust"], "https://www.nationstrust.com/", "Finance", CBSL),
    ("dialogaxiata", "Dialog Axiata", ["Dialog Axiata PLC"], "https://www.dialog.lk/", "Telecommunications",
     wikidata("Q5270580")),
    ("sltmobitel", "SLTMobitel", ["SLT-Mobitel", "Sri Lanka Telecom", "Mobitel"], "https://www.slt.lk/",
     "Telecommunications", wikidata("Q7585968")),
]


def main() -> None:
    rows = [json.loads(line) for line in CATALOG_FILE.read_text(encoding="utf-8").splitlines() if line.strip()]
    existing = {row["brand_id"] for row in rows}
    now = datetime.now(timezone.utc).isoformat()
    added = []
    for brand_id, name, aliases, website, category, source in LOCAL_BRANDS:
        if brand_id in existing:
            print(f"[skip] {brand_id} already in catalog")
            continue
        domain = website.split("//", 1)[1].split("/", 1)[0].lower().removeprefix("www.")
        rows.append({
            "brand_id": brand_id,
            "display_name": name,
            "aliases": aliases,
            "official_domain": domain,
            "official_website": website,
            "category": category,
            "description": f"Sri Lankan {category.lower()} brand ({name}).",
            "source": source["source"],
            "source_url": source["source_url"],
            "region": "LK",
            "collection_method": "manual",
            "reference_images": [],
            "screenshot_files": [],
            "status": "metadata_only",
            "created_at": now,
        })
        added.append(brand_id)
        print(f"[add] {brand_id:14} {domain:18} <- {source['source']}")
    CATALOG_FILE.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(f"Added {len(added)} brand(s); catalog now has {len(rows)} brands -> {CATALOG_FILE}")


if __name__ == "__main__":
    main()
