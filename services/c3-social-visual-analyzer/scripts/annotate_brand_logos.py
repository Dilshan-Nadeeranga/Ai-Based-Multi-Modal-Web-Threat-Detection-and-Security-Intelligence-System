"""Create logo class annotations and tight bounding boxes for normalized logos.

Writes:
  data/annotations/logo_annotations.jsonl
  data/annotations/logo_boxes.jsonl

Each normalized logo is labelled with its brand_id. The box is the tight
non-white content region on the 256x256 canvas (pixel xyxy + YOLO cxcywh).

Homepage screenshots are listed as context only — logo boxes on screenshots
are not auto-labelled (that needs a detector or manual review).

Usage:
  python scripts/annotate_brand_logos.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "annotations" / "brand_catalog.jsonl"
STATUS = ROOT / "data" / "annotations" / "brand_checklist_status.json"
ANNOTATIONS = ROOT / "data" / "annotations" / "logo_annotations.jsonl"
BOXES = ROOT / "data" / "annotations" / "logo_boxes.jsonl"
WHITE_THRESH = 250  # pixels at/above this on all RGB channels count as background


def load_catalog() -> list[dict]:
    return [json.loads(line) for line in CATALOG.read_text(encoding="utf-8").splitlines() if line.strip()]


def mark_checklist(names: list[str], done: bool) -> None:
    data = json.loads(STATUS.read_text(encoding="utf-8"))
    wanted = set(names)
    for entry in data.get("items", []):
        if entry.get("item") in wanted:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data.get("items", []) if entry.get("done"))
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def tight_box(image_path: Path) -> dict:
    image = Image.open(image_path).convert("RGB")
    width, height = image.size
    array = np.asarray(image, dtype=np.uint8)
    mask = ~((array[:, :, 0] >= WHITE_THRESH) & (array[:, :, 1] >= WHITE_THRESH) & (array[:, :, 2] >= WHITE_THRESH))
    if not mask.any():
        # Nearly blank logo — use a centered fallback box so the row stays valid.
        side = max(8, min(width, height) // 4)
        x1 = (width - side) // 2
        y1 = (height - side) // 2
        x2 = x1 + side - 1
        y2 = y1 + side - 1
    else:
        ys, xs = np.where(mask)
        x1, x2 = int(xs.min()), int(xs.max())
        y1, y2 = int(ys.min()), int(ys.max())
    box_w = x2 - x1 + 1
    box_h = y2 - y1 + 1
    cx = (x1 + x2 + 1) / 2.0 / width
    cy = (y1 + y2 + 1) / 2.0 / height
    nw = box_w / width
    nh = box_h / height
    return {
        "image_width": width,
        "image_height": height,
        "bbox_xyxy": [x1, y1, x2, y2],
        "bbox_xywh": [x1, y1, box_w, box_h],
        "bbox_yolo_cxcywh": [round(cx, 6), round(cy, 6), round(nw, 6), round(nh, 6)],
        "content_pixels": int(mask.sum()) if mask.any() else 0,
    }


def main() -> None:
    rows = load_catalog()
    now = datetime.now(timezone.utc).isoformat()
    annotations: list[dict] = []
    boxes: list[dict] = []
    class_names = sorted({row["brand_id"] for row in rows})
    class_to_id = {name: index for index, name in enumerate(class_names)}

    for row in rows:
        brand_id = row["brand_id"]
        if row.get("status") == "duplicate_logo":
            continue
        rel = row.get("normalized_image")
        if not rel:
            print(f"[skip] {brand_id}: no normalized_image")
            continue
        path = ROOT / rel
        if not path.is_file():
            print(f"[fail] {brand_id}: missing {rel}")
            continue
        geom = tight_box(path)
        annotation_id = f"logo_{brand_id}"
        annotations.append({
            "annotation_id": annotation_id,
            "brand_id": brand_id,
            "class_id": class_to_id[brand_id],
            "display_name": row.get("display_name") or brand_id,
            "image_path": rel,
            "image_role": "reference_logo_normalized",
            "label": brand_id,
            "label_type": "brand_logo",
            "collection_method": row.get("collection_method") or "public_dataset",
            "source": row.get("logo_source") or row.get("source"),
            "screenshot_path": (row.get("screenshot_files") or [None])[0],
            "created_at": now,
        })
        boxes.append({
            "annotation_id": annotation_id,
            "brand_id": brand_id,
            "class_id": class_to_id[brand_id],
            "image_path": rel,
            "image_role": "reference_logo_normalized",
            **geom,
            "box_source": "tight_non_white_auto",
            "created_at": now,
        })
        print(f"[ok] {brand_id} box={geom['bbox_xyxy']}")

    ANNOTATIONS.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in annotations) + ("\n" if annotations else ""),
        encoding="utf-8",
    )
    BOXES.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in boxes) + ("\n" if boxes else ""),
        encoding="utf-8",
    )
    classes_path = ROOT / "data" / "annotations" / "brand_classes.json"
    classes_path.write_text(json.dumps({
        "classes": class_names,
        "class_to_id": class_to_id,
        "updated_at": now,
    }, indent=2), encoding="utf-8")

    mark_checklist(["Create logo annotations", "Create bounding-box annotations"], True)
    print(f"Wrote {len(annotations)} logo annotations and {len(boxes)} boxes")
    print(f"Classes ({len(class_names)}) -> {classes_path}")


if __name__ == "__main__":
    main()
