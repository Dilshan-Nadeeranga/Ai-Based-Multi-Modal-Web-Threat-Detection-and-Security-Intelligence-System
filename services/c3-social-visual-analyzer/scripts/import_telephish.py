"""Import English TelePhish messages as an extra text source (phishing, and matching legitimate messages).

TelePhish: M. Erfan, P. Branco, G.-V. Jourdan, "Comparing Macro and Micro Approaches for Detecting Phishing
Where It Spreads", PST 2025 (https://github.com/minaerfan/TelePhish). Licence: academic research and education
only, no redistribution - so the message text is written under data/raw/ (gitignored) and never to the
tracked annotation files. Labels come from VirusTotal flags on the message URLs and are provisional.

--label phishing    is_phishing, flagged link not on EXCLUDED_LINK_DOMAINS (likely VirusTotal false positives)
--label legitimate  neither is_phishing nor is_malicious; sampled with the same group-category counts as the
                    imported phishing rows, so the group type alone does not predict the label

Both: message_language == "en", text after URL removal >= MIN_CHARS, near-duplicates removed (templated spam
differing only in links / numbers), seeded sample of at most --limit messages, split 70/15/15.

Writes (gitignored):  data/raw/telephish/telephish_{phishing,legitimate}_en.jsonl  (text_baseline_dataset format)
Writes (tracked, no message text):  data/statistics/telephish_import_{phishing,legitimate}.json

Usage:
  python scripts/import_telephish.py --label phishing --limit 100
  python scripts/import_telephish.py --label legitimate      # run after the phishing import
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from prepare_text_baseline import clean_text

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "raw" / "telephish"
STATS_DIR = ROOT / "data" / "statistics"
SOURCE = "TelePhish (Erfan et al., PST 2025)"
MIN_CHARS = 30
# Flagged "phishing" links on these domains are most likely VirusTotal false positives (the official Cheelee
# app/community domains posted in the project's own group, and well-known legitimate services), so those
# messages are not used as phishing training samples.
EXCLUDED_LINK_DOMAINS = {
    "cheelee.io": "official domain of the Cheelee project, posted in its own community group",
    "cheelee.us": "Cheelee support domain used by the official group (cannot be verified as phishing)",
    "lu.ma": "legitimate event-page service",
    "bnbchain.org": "official BNB Chain website",
    "metamask.app.link": "official MetaMask deep-link domain",
}
_URL_TOKEN = re.compile(r"\[URL[^\]]*\]")
_NOISE = re.compile(r"[\d\W_]+")


def flag(row: dict, column: str) -> bool:
    return (row.get(column) or "").strip().upper() in ("1", "TRUE")


def excluded_domain(link: str | None) -> str | None:
    host = (urlparse(link if link and "://" in link else f"http://{link or ''}").hostname or "").removeprefix("www.")
    return next((domain for domain in EXCLUDED_LINK_DOMAINS if host == domain or host.endswith("." + domain)), None)


def near_duplicate_key(text: str) -> str:
    return _NOISE.sub(" ", _URL_TOKEN.sub(" ", text).lower()).strip()[:160]


def output_path(label: str) -> Path:
    return OUT_DIR / f"telephish_{label}_en.jsonl"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telephish", type=Path, default=Path(r"D:\Reasearch\Datasets\TelePhish\TelePhish.csv"))
    parser.add_argument("--label", choices=("phishing", "legitimate"), default="phishing")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if not args.telephish.is_file():
        raise SystemExit(f"Missing {args.telephish}")
    csv.field_size_limit(sys.maxsize)
    phishing = args.label == "phishing"

    quotas: Counter | None = None
    if not phishing:
        imported = output_path("phishing")
        if not imported.is_file():
            raise SystemExit("Run the phishing import first; the legitimate sample matches its group categories.")
        quotas = Counter(json.loads(line)["group_category"] for line in imported.read_text(encoding="utf-8").splitlines()
                         if line.strip())

    counts = Counter()
    by_key: dict[str, dict] = {}
    with args.telephish.open(encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            counts["rows"] += 1
            if phishing != flag(row, "is_phishing") or (not phishing and flag(row, "is_malicious")):
                continue
            counts["label_match"] += 1
            if row.get("message_language") != "en":
                continue
            counts["english"] += 1
            excluded = excluded_domain(row.get("malicious_link")) if phishing else None
            if excluded:
                counts[f"excluded_link_domain:{excluded}"] += 1
                continue
            text = clean_text(row.get("message_content"))
            key = near_duplicate_key(text)
            if len(key) < MIN_CHARS:
                counts["too_short"] += 1
                continue
            if key in by_key:
                counts["near_duplicates"] += 1
                continue
            by_key[key] = {"row": row, "text": text}

    groups: dict[str, list[dict]] = defaultdict(list)
    for item in by_key.values():
        groups[item["row"].get("category") or "unknown"].append(item)
    rng = random.Random(args.seed)
    total = sum(len(items) for items in groups.values())
    chosen: list[dict] = []
    for category in sorted(groups):
        items = sorted(groups[category], key=lambda it: it["row"]["sample_ids"])
        rng.shuffle(items)
        if quotas is not None:
            take = quotas.get(category, 0)
        else:
            take = len(items) if total <= args.limit else max(1, round(args.limit * len(items) / total))
        chosen += items[:take]
    rng.shuffle(chosen)
    chosen = chosen[: args.limit]

    n_val = n_test = round(len(chosen) * 0.15)
    now = datetime.now(timezone.utc).isoformat()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for index, item in enumerate(chosen):
        src = item["row"]
        split = "test" if index < n_test else "val" if index < n_test + n_val else "train"
        rows.append({
            "sample_id": f"TP_{int(src['sample_ids']):06d}",
            "source_dataset": SOURCE,
            "platform": "telegram",
            "label": 1 if phishing else 0,
            "scam_type": "phishing" if phishing else "legitimate",
            "label_status": "provisional",
            "label_basis": ("VirusTotal flagged a URL in the message as phishing" if phishing
                            else "no URL in the message was flagged by VirusTotal (phishing or malicious)"),
            "group_category": src.get("category"),
            "text": item["text"],
            "text_hash": hashlib.sha256(item["text"].encode("utf-8")).hexdigest(),
            "malicious_link": (src.get("malicious_link") or None) if phishing else None,
            "split": split,
            "created_at": now,
        })
    out = output_path(args.label)
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")

    summary = {
        "source": SOURCE, "source_url": "https://github.com/minaerfan/TelePhish", "label": args.label,
        "licence": "academic research and education only; no redistribution (text kept in gitignored data/raw/)",
        "filters": {"label": args.label, "message_language": "en", "min_chars_without_urls": MIN_CHARS,
                    "near_duplicates_removed": True, "limit": args.limit, "seed": args.seed,
                    **({"excluded_link_domains": EXCLUDED_LINK_DOMAINS} if phishing else
                       {"matched_group_categories": dict(quotas or {})})},
        "counts": {**dict(counts), "unique_candidates": total, "imported": len(rows)},
        "imported_by_group_category": dict(Counter(r["group_category"] for r in rows)),
        "splits": dict(Counter(r["split"] for r in rows)),
        "sample_ids": [r["sample_id"] for r in rows],
        "output": str(out.relative_to(ROOT)).replace("\\", "/"),
        "created_at": now,
    }
    (STATS_DIR / f"telephish_import_{args.label}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("counts", "imported_by_group_category", "splits")}, indent=2))
    print(f"Wrote {len(rows)} rows -> {out}")


if __name__ == "__main__":
    main()
