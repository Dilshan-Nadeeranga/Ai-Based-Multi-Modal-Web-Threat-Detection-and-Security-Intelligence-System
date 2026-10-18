"""Import Smishtank reported smishing messages as labelled external samples for the C3 categories.

Smishtank: D. Timko, M. L. Rahman, "Smishing Dataset I: Phishing SMS Dataset from Smishtank.com",
ACM CODASPY 2024 (https://smishtank.com/dataset). Every row is a user-reported scam SMS with the impersonated
brand, a lure category and the URL labelled by the dataset authors.

C3 category (primary):
  brand_impersonation  the authors recorded an impersonated Brand
  phishing             no brand; lure "Account Alert" or "Delivery"
  financial_scam       no brand; "Finance/Crypto", "Prize/Contest", "Job Advertisement", "Loans/Credit",
                       "Lawsuits/Settlements"
  other_scam           no brand; "Wrong Number/Romance Scam", "Advertisement", "Other"
The lure category is kept as secondary_category; a URL that VirusTotal flagged as malware sets
malware_candidate=true (a candidate only, not the label). No legitimate messages exist in this dataset.

The licence is not included in the download, so the dataset is handled like TelePhish: message text only in
gitignored data/raw/smishtank/, the tracked statistics file holds counts and ids.

Writes:
  data/raw/smishtank/smishtank_samples.jsonl   (gitignored)
  data/statistics/smishtank_import.json        (tracked; no message text)

Usage:
  python scripts/import_smishtank.py --smishtank "D:/Reasearch/Datasets/smishtank/analysisdataset.csv"
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from import_telephish import near_duplicate_key
from prepare_text_baseline import clean_text

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
OUTPUT = ROOT / "data" / "raw" / "smishtank" / "smishtank_samples.jsonl"
STATS = ROOT / "data" / "statistics" / "smishtank_import.json"
SOURCE = "Smishtank (Timko & Rahman, CODASPY 2024)"
MIN_CHARS = 15

LURE_TO_CATEGORY = {
    "account alert": "phishing",
    "delivery": "phishing",
    "finance/crypto": "financial_scam",
    "prize/contest": "financial_scam",
    "job advertisement": "financial_scam",
    "loans/credit": "financial_scam",
    "lawsuits/settlements": "financial_scam",
    "wrong number/romance scam": "other_scam",
    "advertisement": "other_scam",
    "other": "other_scam",
}
# Smishtank brand spellings that differ from the catalog's names / aliases.
BRAND_ALIASES = {"citi": "citibank", "navyfederal": "nfcu", "bofa": "bankofamerica", "wellsfargobank": "wellsfargo",
                 "att": "att", "atandt": "att", "deutschetelekom": "telekom", "unitedparcelservice": "ups"}


def norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def catalog_lookup() -> dict[str, str]:
    lookup = {}
    for row in (json.loads(l) for l in CATALOG.read_text(encoding="utf-8").splitlines() if l.strip()):
        for name in (row["brand_id"], row["display_name"], *row.get("aliases", [])):
            lookup[norm(name)] = row["brand_id"]
    lookup.update({k: v for k, v in BRAND_ALIASES.items() if v in lookup.values()})
    return lookup


def flagged(value: str | None) -> bool:
    return bool(re.match(r"^\s*[1-9]", value or ""))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smishtank", type=Path, default=Path(r"D:\Reasearch\Datasets\smishtank\analysisdataset.csv"))
    args = parser.parse_args()
    if not args.smishtank.is_file():
        raise SystemExit(f"Missing {args.smishtank}")

    catalog = catalog_lookup()
    counts = Counter()
    seen: set[str] = set()
    rows = []
    now = datetime.now(timezone.utc).isoformat()
    with args.smishtank.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        for src in csv.DictReader(handle):
            counts["rows"] += 1
            text = clean_text(src.get("MainText") or src.get("Fulltext"))
            key = near_duplicate_key(text)
            if len(key) < MIN_CHARS:
                counts["too_short"] += 1
                continue
            if key in seen:
                counts["near_duplicates"] += 1
                continue
            seen.add(key)
            lures = [p.strip() for p in re.split(r"[,;]", src.get("Message Categories") or "") if p.strip()]
            brand = (src.get("Brand") or "").strip()
            if brand:
                category = "brand_impersonation"
            else:
                category = next((LURE_TO_CATEGORY[l.lower()] for l in lures if l.lower() in LURE_TO_CATEGORY), "other_scam")
            url = (src.get("Url") or "").strip() or None
            rows.append({
                "sample_id": f"ST_{int(src['messageid']):06d}" if (src.get("messageid") or "").isdigit()
                             else f"ST_{counts['rows']:06d}",
                "source_dataset": SOURCE,
                "platform": "sms",
                "label": 1,
                "scam_type": category,
                "secondary_category": lures,
                "impersonated_brand": brand or None,
                "catalog_brand_id": catalog.get(norm(brand)) if brand else None,
                "malware_candidate": flagged(src.get("Malware")),
                "label_status": "dataset_label",
                "label_basis": "Smishtank author labels (Brand, Message Categories); C3 category mapped by import_smishtank.py",
                "text": text,
                "text_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "url": url,
                "url_type": (src.get("URL Subcategory") or "").strip() or None,
                "domain": (src.get("FullyQualifiedDomain") or "").strip() or None,
                "sender_type": (src.get("SenderType") or "").strip() or None,
                "received": (src.get("timeReceived") or "").strip() or None,
                "created_at": now,
            })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    branded = [r for r in rows if r["impersonated_brand"]]
    summary = {
        "source": SOURCE, "source_url": "https://smishtank.com/dataset", "platform": "sms",
        "licence": "not included in the download; handled as research-only (text kept in gitignored data/raw/)",
        "label_basis": "dataset author labels (impersonated brand, lure category); C3 category mapped by rules",
        "mapping": {"brand_impersonation": "an impersonated Brand is recorded", **{k: v for k, v in LURE_TO_CATEGORY.items()}},
        "counts": {**dict(counts), "imported": len(rows)},
        "categories": dict(Counter(r["scam_type"] for r in rows)),
        "malware_candidates": sum(r["malware_candidate"] for r in rows),
        "with_url": sum(1 for r in rows if r["url"]),
        "url_types": dict(Counter(r["url_type"] for r in rows if r["url_type"])),
        "brand_impersonation": {
            "messages": len(branded),
            "distinct_brands": len({r["impersonated_brand"].lower() for r in branded}),
            "catalog_brands_covered": len({r["catalog_brand_id"] for r in branded if r["catalog_brand_id"]}),
            "messages_for_catalog_brands": sum(1 for r in branded if r["catalog_brand_id"]),
            "top_brands": dict(Counter(r["impersonated_brand"] for r in branded).most_common(15)),
            "by_catalog_brand": dict(Counter(r["catalog_brand_id"] for r in branded if r["catalog_brand_id"]).most_common()),
        },
        "secondary_categories": dict(Counter(l for r in rows for l in r["secondary_category"])),
        "sample_ids": [r["sample_id"] for r in rows],
        "output": str(OUTPUT.relative_to(ROOT)).replace("\\", "/"),
        "created_at": now,
    }
    STATS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("counts", "categories", "malware_candidates", "with_url")}, indent=2))
    print(json.dumps({k: v for k, v in summary["brand_impersonation"].items() if k != "by_catalog_brand"}, indent=2))
    print(f"Wrote {len(rows)} rows -> {OUTPUT}")


if __name__ == "__main__":
    main()
