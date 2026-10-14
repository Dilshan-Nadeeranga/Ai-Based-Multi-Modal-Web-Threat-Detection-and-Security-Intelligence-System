"""Generate Brand Reference dataset statistics from files on disk.

Reads catalog, logos, screenshots, annotations, boxes, and splits.
Does not invent counts.

Writes:
  data/statistics/brand_dataset_statistics.json

Usage:
  python scripts/generate_brand_statistics.py
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANNOTATIONS = ROOT / "data" / "annotations"
REFERENCE = ROOT / "data" / "reference"
STATS = ROOT / "data" / "statistics" / "brand_dataset_statistics.json"
STATUS = ANNOTATIONS / "brand_checklist_status.json"


def load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def existing(rel: str | None) -> bool:
    if not rel:
        return False
    return (ROOT / rel).is_file()


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


def main() -> None:
    catalog = load_jsonl(ANNOTATIONS / "brand_catalog.jsonl")
    logos = load_jsonl(ANNOTATIONS / "logo_annotations.jsonl")
    boxes = load_jsonl(ANNOTATIONS / "logo_boxes.jsonl")
    splits = load_jsonl(ANNOTATIONS / "brand_splits.jsonl")
    classes = {}
    classes_path = ANNOTATIONS / "brand_classes.json"
    if classes_path.is_file():
        classes = json.loads(classes_path.read_text(encoding="utf-8"))

    primary_present = 0
    normalized_present = 0
    screenshot_present = 0
    categories: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for row in catalog:
        categories[row.get("category") or "unknown"] += 1
        status_counts[row.get("status") or "unknown"] += 1
        refs = row.get("reference_images") or []
        if any(existing(path) and "_primary." in path for path in refs):
            primary_present += 1
        if existing(row.get("normalized_image")):
            normalized_present += 1
        shots = row.get("screenshot_files") or []
        if any(existing(path) for path in shots):
            screenshot_present += 1

    split_counts = Counter(row.get("split") for row in splits)
    box_areas = []
    for box in boxes:
        xywh = box.get("bbox_xywh") or [0, 0, 0, 0]
        box_areas.append(xywh[2] * xywh[3])

    logo_files = list((REFERENCE / "brands").glob("*_primary.*")) if (REFERENCE / "brands").is_dir() else []
    norm_files = list((REFERENCE / "brands").glob("*_normalized.png")) if (REFERENCE / "brands").is_dir() else []
    shot_files = list((REFERENCE / "brand_screenshots").glob("*_home.png")) if (REFERENCE / "brand_screenshots").is_dir() else []

    stats = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "brands_in_catalog": len(catalog),
        "classes": len(classes.get("classes") or []),
        "primary_logos_on_disk": len(logo_files),
        "normalized_logos_on_disk": len(norm_files),
        "screenshots_on_disk": len(shot_files),
        "catalog_with_primary_file": primary_present,
        "catalog_with_normalized_file": normalized_present,
        "catalog_with_screenshot_file": screenshot_present,
        "logo_annotations": len(logos),
        "logo_boxes": len(boxes),
        "brands_in_splits": len(splits),
        "split_counts": {
            "train": split_counts.get("train", 0),
            "val": split_counts.get("val", 0),
            "test": split_counts.get("test", 0),
        },
        "categories": dict(categories.most_common()),
        "status_counts": dict(status_counts.most_common()),
        "bbox_area_px_min": min(box_areas) if box_areas else 0,
        "bbox_area_px_max": max(box_areas) if box_areas else 0,
        "bbox_area_px_mean": round(sum(box_areas) / len(box_areas), 2) if box_areas else 0,
        "checklist": json.loads(STATUS.read_text(encoding="utf-8")) if STATUS.exists() else None,
    }

    STATS.parent.mkdir(parents=True, exist_ok=True)
    STATS.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    mark_checklist("Generate brand dataset statistics", True)
    print(json.dumps({
        "brands": stats["brands_in_catalog"],
        "normalized": stats["normalized_logos_on_disk"],
        "screenshots": stats["screenshots_on_disk"],
        "annotations": stats["logo_annotations"],
        "boxes": stats["logo_boxes"],
        "splits": stats["split_counts"],
        "wrote": str(STATS),
    }, indent=2))


if __name__ == "__main__":
    main()
