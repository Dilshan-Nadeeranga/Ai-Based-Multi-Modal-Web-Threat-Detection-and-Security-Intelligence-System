"""Assign each brand to train / validation / test (no brand leakage).

With one normalized logo per brand, the unit of split is ``brand_id``.
Default ratios: 70% train / 15% val / 15% test (seeded shuffle).

Writes:
  data/annotations/brand_splits.jsonl   — one row per brand
  data/annotations/brand_splits.json    — summary lists

Usage:
  python scripts/split_brand_dataset.py
  python scripts/split_brand_dataset.py --seed 42 --train 0.7 --val 0.15 --test 0.15
  python scripts/split_brand_dataset.py --keep-existing   # only new brands are assigned; old ones keep their split
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
STATUS = ROOT / "data" / "annotations" / "brand_checklist_status.json"
SPLIT_JSONL = ROOT / "data" / "annotations" / "brand_splits.jsonl"
SPLIT_JSON = ROOT / "data" / "annotations" / "brand_splits.json"


def load_catalog() -> list[dict]:
    return [json.loads(line) for line in CATALOG.read_text(encoding="utf-8").splitlines() if line.strip()]


def mark_checklist(item: str, done: bool) -> None:
    data = json.loads(STATUS.read_text(encoding="utf-8"))
    for entry in data.get("items", []):
        if entry.get("item") == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data.get("items", []) if entry.get("done"))
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def allocate(n: int, train: float, val: float, test: float) -> tuple[int, int, int]:
    if abs(train + val + test - 1.0) > 1e-6:
        raise SystemExit("train+val+test must sum to 1.0")
    n_train = int(round(n * train))
    n_val = int(round(n * val))
    n_test = n - n_train - n_val
    if n >= 3:
        n_train = max(1, n_train)
        n_val = max(1, n_val)
        n_test = max(1, n - n_train - n_val)
        # Rebalance if rounding overflowed.
        while n_train + n_val + n_test > n and n_train > 1:
            n_train -= 1
        while n_train + n_val + n_test < n:
            n_train += 1
    return n_train, n_val, n_test


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train", type=float, default=0.70)
    parser.add_argument("--val", type=float, default=0.15)
    parser.add_argument("--test", type=float, default=0.15)
    parser.add_argument("--keep-existing", action="store_true",
                        help="Keep the split of brands already in brand_splits.jsonl and only assign new brands")
    args = parser.parse_args()

    rows = [row for row in load_catalog() if row.get("status") != "duplicate_logo" and row.get("normalized_image")]
    brands = sorted(row["brand_id"] for row in rows)
    assignment: dict[str, str] = {}
    if args.keep_existing and SPLIT_JSONL.exists():
        previous = [json.loads(line) for line in SPLIT_JSONL.read_text(encoding="utf-8").splitlines() if line.strip()]
        assignment = {item["brand_id"]: item["split"] for item in previous if item["brand_id"] in brands}
    rng = random.Random(args.seed)
    shuffled = [brand_id for brand_id in brands if brand_id not in assignment]
    rng.shuffle(shuffled)

    n_train, n_val, n_test = allocate(len(shuffled), args.train, args.val, args.test)
    assignment.update({brand_id: "train" for brand_id in shuffled[:n_train]})
    assignment.update({brand_id: "val" for brand_id in shuffled[n_train : n_train + n_val]})
    assignment.update({brand_id: "test" for brand_id in shuffled[n_train + n_val :]})
    train_ids = [b for b in brands if assignment[b] == "train"]
    val_ids = [b for b in brands if assignment[b] == "val"]
    test_ids = [b for b in brands if assignment[b] == "test"]

    now = datetime.now(timezone.utc).isoformat()
    by_id = {row["brand_id"]: row for row in rows}
    split_rows = []
    for brand_id in brands:
        row = by_id[brand_id]
        split = assignment[brand_id]
        split_rows.append({
            "brand_id": brand_id,
            "split": split,
            "display_name": row.get("display_name"),
            "category": row.get("category"),
            "normalized_image": row.get("normalized_image"),
            "annotation_id": f"logo_{brand_id}",
            "seed": args.seed,
            "created_at": now,
        })
        print(f"[split] {brand_id:20} -> {split}")

    SPLIT_JSONL.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in split_rows) + "\n",
        encoding="utf-8",
    )
    SPLIT_JSON.write_text(json.dumps({
        "seed": args.seed,
        "ratios": {"train": args.train, "val": args.val, "test": args.test},
        "counts": {"train": len(train_ids), "val": len(val_ids), "test": len(test_ids), "total": len(brands)},
        "train": sorted(train_ids),
        "val": sorted(val_ids),
        "test": sorted(test_ids),
        "unit": "brand_id",
        "note": "Each brand appears in exactly one split to avoid brand leakage.",
        "created_at": now,
    }, indent=2), encoding="utf-8")

    mark_checklist("Create train/validation/test split", True)
    print(f"Wrote {SPLIT_JSONL}")
    print(f"Counts train={len(train_ids)} val={len(val_ids)} test={len(test_ids)}")


if __name__ == "__main__":
    main()
