"""Build the single-class ``logo`` YOLO dataset (checklist: Prepare YOLO dataset).

Two sources of boxes:
  * dom       — Zenodo_Phishing pages rendered offline (JavaScript off, every
                non-file request blocked). Visible <img>/<svg>/background
                elements whose src/alt/class/id mention "logo" become boxes.
                These are weak labels: unnamed logos on a page stay unlabeled.
  * synthetic — normalized reference logos pasted onto legit-page screenshots
                and social post images. Logo brands follow brand_splits.json,
                so val/test logos are brands the detector never saw.

Writes:
  data/processed/logo_yolo/{images,labels}/{train,val,test}/   (gitignored)
  data/processed/logo_yolo/data.yaml
  data/annotations/logo_yolo_manifest.jsonl
  data/annotations/logo_detection_checklist_status.json
  data/statistics/logo_yolo_dataset_statistics.json

Usage:
  python scripts/prepare_logo_yolo_dataset.py
  python scripts/prepare_logo_yolo_dataset.py --max-pages 200 --synthetic 300
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap
import numpy as np
from PIL import Image, ImageEnhance

from app.services.image_preprocessor import convert_to_rgb

ROOT = _bootstrap.SERVICE_ROOT
ANNOTATIONS = ROOT / "data" / "annotations"
CATALOG = ANNOTATIONS / "brand_catalog.jsonl"
BRAND_SPLITS = ANNOTATIONS / "brand_splits.json"
METADATA = ANNOTATIONS / "dataset_metadata.jsonl"
MANIFEST = ANNOTATIONS / "logo_yolo_manifest.jsonl"
STATUS = ANNOTATIONS / "logo_detection_checklist_status.json"
STATS = ROOT / "data" / "statistics" / "logo_yolo_dataset_statistics.json"
YOLO_DIR = ROOT / "data" / "processed" / "logo_yolo"
DEFAULT_ZENODO = Path(r"D:\Reasearch\Datasets\Zenodo_Phishing")
VIEWPORT = {"width": 1366, "height": 768}
SPLITS = ("train", "val", "test")

CHECKLIST = [
    "Prepare YOLO dataset",
    "Configure YOLO model",
    "Train logo detector baseline",
    "Validate logo detector",
    "Detect logo bounding boxes",
    "Extract detected logo regions",
    "Compare detected logo with references",
    "Generate visual embeddings",
    "Calculate logo similarity",
    "Compare post image with website image",
    "Save similarity results",
    "Visualize detected logo regions",
    "Evaluate baseline performance",
]

LOGO_BOXES_JS = r"""
() => {
  const vw = innerWidth, vh = innerHeight, out = [];
  const named = el => /logo/i.test([el.getAttribute('src'), el.getAttribute('srcset'), el.getAttribute('alt'),
    el.getAttribute('class'), el.id, el.getAttribute('title'), el.getAttribute('aria-label'),
    el.getAttribute('href')].join(' '));
  const visible = el => {
    for (let node = el; node && node.nodeType === 1; node = node.parentElement) {
      const s = getComputedStyle(node);
      if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) < 0.1) return false;
    }
    return true;
  };
  for (const el of document.querySelectorAll('img, svg, [class*="logo" i], [id*="logo" i]')) {
    const tag = el.tagName.toLowerCase();
    const bg = getComputedStyle(el).backgroundImage;
    let kind = null;
    if (tag === 'img') { if (!el.complete || el.naturalWidth === 0) continue; kind = 'img'; }
    else if (tag === 'svg') { if (el.parentElement && el.parentElement.closest('svg')) continue; kind = 'svg'; }
    else if (bg && bg.startsWith('url(') && !el.querySelector('img, svg')) kind = 'background';
    else continue;
    const container = el.parentElement && el.parentElement.closest('[class*="logo" i], [id*="logo" i], a[href*="logo" i]');
    if (!named(el) && !container) continue;
    if (!visible(el)) continue;
    const r = el.getBoundingClientRect();
    const x1 = Math.max(0, r.left), y1 = Math.max(0, r.top);
    const x2 = Math.min(vw, r.right), y2 = Math.min(vh, r.bottom);
    out.push({kind, x1, y1, x2, y2});
  }
  return out;
}
"""


def mark_checklist(item: str, done: bool = True) -> None:
    if STATUS.exists():
        data = json.loads(STATUS.read_text(encoding="utf-8"))
    else:
        data = {"task": "Logo / UI Detection + Visual Similarity",
                "items": [{"item": name, "done": False} for name in CHECKLIST]}
    for entry in data["items"]:
        if entry["item"] == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data["items"] if entry["done"])
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def iou(a: list[float], b: list[float]) -> float:
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    union = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / union if union else 0.0


def clean_boxes(raw: list[dict], width: int, height: int) -> list[list[float]]:
    boxes: list[list[float]] = []
    for item in sorted(raw, key=lambda r: (r["x2"] - r["x1"]) * (r["y2"] - r["y1"])):
        w, h = item["x2"] - item["x1"], item["y2"] - item["y1"]
        if w < 10 or h < 8 or w * h > 0.25 * width * height or not 1 / 10 <= w / h <= 12:
            continue
        box = [round(item["x1"], 1), round(item["y1"], 1), round(item["x2"], 1), round(item["y2"], 1)]
        if all(iou(box, kept) < 0.6 for kept in boxes):
            boxes.append(box)
    return boxes


def yolo_lines(boxes: list[list[float]], width: int, height: int) -> list[str]:
    lines = []
    for x1, y1, x2, y2 in boxes:
        cx, cy = (x1 + x2) / 2 / width, (y1 + y2) / 2 / height
        lines.append(f"0 {cx:.6f} {cy:.6f} {(x2 - x1) / width:.6f} {(y2 - y1) / height:.6f}")
    return lines


def save_sample(image: Image.Image, boxes: list[list[float]], split: str, name: str) -> str:
    image_path = YOLO_DIR / "images" / split / f"{name}.jpg"
    image.save(image_path, quality=90)
    (YOLO_DIR / "labels" / split / f"{name}.txt").write_text("\n".join(yolo_lines(boxes, *image.size)), encoding="utf-8")
    return str(image_path.relative_to(ROOT)).replace("\\", "/")


def split_ids(ids: list[str], seed: int, train: float = 0.7, val: float = 0.15) -> dict[str, str]:
    shuffled = sorted(ids)
    random.Random(seed).shuffle(shuffled)
    n_train, n_val = round(len(shuffled) * train), round(len(shuffled) * val)
    return {page: "train" if i < n_train else "val" if i < n_train + n_val else "test" for i, page in enumerate(shuffled)}


# ---------------------------------------------------------------- dom (real)

def zenodo_targets(root: Path) -> dict[str, str | None]:
    csv.field_size_limit(sys.maxsize)
    with (root / "phishing.csv").open(encoding="utf-8", errors="replace", newline="") as handle:
        return {row["_id"]: (json.loads(row["brands"] or "[]") or [None])[0] for row in csv.DictReader(handle)}


def render_dom_pages(root: Path, seed: int, max_pages: int | None) -> tuple[list[dict], list[tuple[str, Path]]]:
    from playwright.sync_api import sync_playwright

    targets = zenodo_targets(root)
    pages = []
    for part, label in (("phishing_0001-0500", "phishing"), ("not-phishing_0001-0500", "legit")):
        for page_id in sorted(os.listdir(root / part)):
            html = root / part / page_id / "index.html"
            if html.exists():
                pages.append((page_id, label, html))
    random.Random(seed).shuffle(pages)
    pages = pages[:max_pages] if max_pages else pages
    assignment = split_ids([p[0] for p in pages], seed)

    rows, backgrounds = [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=VIEWPORT, java_script_enabled=False, service_workers="block")
        context.route("**/*", lambda route: route.continue_() if route.request.url.startswith("file:") else route.abort())
        page = context.new_page()
        for index, (page_id, label, html) in enumerate(pages, 1):
            try:
                page.goto(html.as_uri(), wait_until="domcontentloaded", timeout=8000)
                try:
                    page.wait_for_load_state("load", timeout=2500)
                except Exception:  # noqa: BLE001 - render what has loaded
                    pass
                boxes = clean_boxes(page.evaluate(LOGO_BOXES_JS), VIEWPORT["width"], VIEWPORT["height"])
                shot = YOLO_DIR / "_render.png"
                page.screenshot(path=str(shot))
            except Exception as exc:  # noqa: BLE001 - offline pages fail in many ways
                print(f"[dom] skip {page_id}: {type(exc).__name__}")
                continue
            image = convert_to_rgb(Image.open(shot))
            if not boxes:
                if label == "legit":
                    background = YOLO_DIR / "_backgrounds" / f"{page_id}.jpg"
                    image.save(background, quality=90)
                    backgrounds.append((assignment[page_id], background))
                continue
            split = assignment[page_id]
            rows.append({
                "image_id": f"dom_{page_id}", "origin": "dom", "split": split, "page_label": label,
                "source_page": f"{label}/{page_id}", "target_brand": targets.get(page_id) if label == "phishing" else None,
                "image": save_sample(image, boxes, split, f"dom_{page_id}"),
                "width": image.width, "height": image.height,
                "boxes": [{"xyxy": box, "brand_id": None} for box in boxes],
            })
            if index % 100 == 0:
                print(f"  ... rendered {index}/{len(pages)} ({len(rows)} with logo boxes)")
        browser.close()
    (YOLO_DIR / "_render.png").unlink(missing_ok=True)
    return rows, backgrounds


# ------------------------------------------------------------ synthetic

def logo_tile(path: Path) -> Image.Image:
    """Tight RGBA crop of a normalized (logo on white) reference image."""
    rgb = np.asarray(convert_to_rgb(Image.open(path)))
    mask = (rgb < 235).any(axis=2)
    ys, xs = np.where(mask)
    y1, y2, x1, x2 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
    crop = rgb[y1:y2, x1:x2]
    alpha = np.where(mask[y1:y2, x1:x2], 255, 0).astype(np.uint8)
    return Image.fromarray(np.dstack([crop, alpha]), "RGBA")


def synthetic_samples(backgrounds: dict[str, list[Path]], count: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    catalog = {row["brand_id"]: row for row in read_jsonl(CATALOG) if row.get("normalized_image")}
    brand_split = json.loads(BRAND_SPLITS.read_text(encoding="utf-8"))
    tiles = {brand: logo_tile(ROOT / catalog[brand]["normalized_image"]) for brand in catalog}
    per_split = {"train": round(count * 0.7), "val": round(count * 0.15)}
    per_split["test"] = count - per_split["train"] - per_split["val"]

    rows = []
    for split in SPLITS:
        brands = [b for b in brand_split[split] if b in tiles]
        pool = backgrounds[split]
        for index in range(per_split[split]):
            background_path = pool[index % len(pool)]
            canvas = convert_to_rgb(Image.open(background_path))
            canvas.thumbnail((1366, 1366))
            canvas = canvas.copy()
            boxes = []
            for _ in range(rng.choice((1, 1, 2, 3))):
                brand = rng.choice(brands)
                tile = tiles[brand]
                target_w = max(24, int(canvas.width * rng.uniform(0.05, 0.25)))
                scale = target_w / tile.width
                size = (target_w, max(10, int(tile.height * scale)))
                if size[1] > canvas.height * 0.4:
                    size = (max(10, int(size[0] * canvas.height * 0.4 / size[1])), int(canvas.height * 0.4))
                logo = tile.resize(size, Image.LANCZOS)
                logo = ImageEnhance.Brightness(logo).enhance(rng.uniform(0.85, 1.1))
                pad = 6 if rng.random() < 0.5 else 0
                for _attempt in range(20):
                    x = rng.randint(0, max(0, canvas.width - size[0] - 2 * pad))
                    y = rng.randint(0, max(0, canvas.height - size[1] - 2 * pad))
                    box = [x, y, x + size[0] + 2 * pad, y + size[1] + 2 * pad]
                    if all(iou(box, b["xyxy"]) == 0 for b in boxes):
                        break
                else:
                    continue
                if pad:
                    canvas.paste((255, 255, 255), (box[0], box[1], box[2], box[3]))
                canvas.paste(logo, (x + pad, y + pad), logo)
                boxes.append({"xyxy": [float(v) for v in box], "brand_id": brand})
            if not boxes:
                continue
            name = f"syn_{split}_{index:04d}"
            rows.append({
                "image_id": name, "origin": "synthetic", "split": split, "page_label": None,
                "source_page": str(background_path.relative_to(ROOT) if background_path.is_relative_to(ROOT) else background_path.name).replace("\\", "/"),
                "target_brand": None, "image": save_sample(canvas, [b["xyxy"] for b in boxes], split, name),
                "width": canvas.width, "height": canvas.height, "boxes": boxes,
            })
    return rows


def post_backgrounds(seed: int) -> dict[str, list[Path]]:
    paths = []
    for record in read_jsonl(METADATA):
        if (record.get("source") or {}).get("source_dataset", "") and "Fakeddit" in record["source"]["source_dataset"]:
            paths.extend(ROOT / ref for ref in (record.get("post") or {}).get("images", []) if (ROOT / ref).exists())
    assignment = split_ids([str(p) for p in paths], seed)
    return {split: [p for p in paths if assignment[str(p)] == split] for split in SPLITS}


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zenodo", type=Path, default=DEFAULT_ZENODO)
    parser.add_argument("--max-pages", type=int, default=None)
    parser.add_argument("--synthetic", type=int, default=400)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if YOLO_DIR.exists():
        shutil.rmtree(YOLO_DIR)
    for kind in ("images", "labels"):
        for split in SPLITS:
            (YOLO_DIR / kind / split).mkdir(parents=True, exist_ok=True)
    (YOLO_DIR / "_backgrounds").mkdir(parents=True)

    print("[dom] rendering Zenodo pages offline")
    dom_rows, web_backgrounds = render_dom_pages(args.zenodo, args.seed, args.max_pages)
    print(f"[dom] {len(dom_rows)} pages with logo boxes, {len(web_backgrounds)} logo-free legit backgrounds")

    posts = post_backgrounds(args.seed)
    rng = random.Random(args.seed)
    backgrounds = {}
    for split in SPLITS:
        backgrounds[split] = [path for s, path in web_backgrounds if s == split] + posts[split]
        rng.shuffle(backgrounds[split])
    synthetic_rows = synthetic_samples(backgrounds, args.synthetic, args.seed)
    print(f"[synthetic] {len(synthetic_rows)} images")

    rows = dom_rows + synthetic_rows
    shutil.rmtree(YOLO_DIR / "_backgrounds")
    MANIFEST.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
    (YOLO_DIR / "data.yaml").write_text(
        f"path: {YOLO_DIR.as_posix()}\ntrain: images/train\nval: images/val\ntest: images/test\nnames:\n  0: logo\n",
        encoding="utf-8",
    )

    counts = {split: {origin: Counter() for origin in ("dom", "synthetic")} for split in SPLITS}
    for row in rows:
        counts[row["split"]][row["origin"]]["images"] += 1
        counts[row["split"]][row["origin"]]["boxes"] += len(row["boxes"])
    STATS.write_text(json.dumps({
        "classes": ["logo"],
        "counts": {split: {origin: dict(c) for origin, c in v.items()} for split, v in counts.items()},
        "dom_page_labels": dict(Counter(r["page_label"] for r in dom_rows)),
        "dom_box_kinds_note": "weak labels: only elements named *logo* are boxed",
        "synthetic_brands_by_split": {s: sorted({b["brand_id"] for r in synthetic_rows if r["split"] == s for b in r["boxes"]}) for s in SPLITS},
        "seed": args.seed,
        "data_yaml": "data/processed/logo_yolo/data.yaml",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    mark_checklist("Prepare YOLO dataset")
    for split in SPLITS:
        print(f"  {split:5}: {json.dumps({o: dict(c) for o, c in counts[split].items()})}")


if __name__ == "__main__":
    main()
