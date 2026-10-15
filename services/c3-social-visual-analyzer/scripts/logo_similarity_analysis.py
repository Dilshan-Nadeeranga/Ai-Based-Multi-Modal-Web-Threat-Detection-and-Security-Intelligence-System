"""Detect logos, match them to reference brands and compare post vs website images.

Requires the trained detector (scripts/train_logo_detector.py).

Steps (checklist items):
  Detect logo bounding boxes -> Extract detected logo regions -> Generate visual
  embeddings (CLIP image encoder) -> Calculate logo similarity (cosine + pHash)
  -> Compare detected logo with references (Top-K brands) -> Compare post image
  with website image -> Save similarity results -> Visualize -> Evaluate.

Evaluation:
  * Detection on the YOLO test split (IoU >= 0.5), overall / dom / synthetic.
  * Brand matching: synthetic test boxes (brand known, brands unseen by the
    detector) and Zenodo dom test pages whose phishing target is in the catalog.
    The accept threshold is picked on the val split (max F1).

Writes:
  data/processed/logo_crops/ , data/processed/logo_viz/        (gitignored)
  data/annotations/logo_similarity_results.jsonl   — dataset post images + web screenshots
  data/annotations/post_web_similarity.jsonl       — post image vs destination screenshot
  data/statistics/logo_baseline_evaluation.json
  data/statistics/logo_detection_examples.png

Usage:
  python scripts/logo_similarity_analysis.py
  python scripts/logo_similarity_analysis.py --conf 0.25 --clip openai/clip-vit-base-patch16
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

import imagehash
import numpy as np
from PIL import Image, ImageDraw

from clip_brand_analysis import embed_images, letterbox, load_clip, open_rgb
from prepare_logo_yolo_dataset import CATALOG, MANIFEST, ROOT, iou, logo_tile, mark_checklist, read_jsonl

ANNOTATIONS = ROOT / "data" / "annotations"
METADATA = ANNOTATIONS / "dataset_metadata.jsonl"
CAPTURES = ANNOTATIONS / "webpage_captures.jsonl"
RESULTS = ANNOTATIONS / "logo_similarity_results.jsonl"
PAIRS = ANNOTATIONS / "post_web_similarity.jsonl"
STATS_DIR = ROOT / "data" / "statistics"
EVALUATION = STATS_DIR / "logo_baseline_evaluation.json"
EXAMPLES = STATS_DIR / "logo_detection_examples.png"
TRAINING = STATS_DIR / "logo_detector_training.json"
CROPS_DIR = ROOT / "data" / "processed" / "logo_crops"
VIZ_DIR = ROOT / "data" / "processed" / "logo_viz"
DEFAULT_DETECTOR = ROOT / "models" / "logo_detector" / "yolo11n_logo_baseline_best.pt"
DEFAULT_CLIP = "openai/clip-vit-base-patch16"


def rel(path: Path) -> str:
    path = path.resolve()
    return str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path).replace("\\", "/")


def detect(detector, image: Image.Image, conf: float) -> list[dict]:
    result = detector.predict(image, conf=conf, imgsz=640, device="cpu", max_det=20, verbose=False)[0]
    return [{"xyxy": [round(float(v), 1) for v in box.xyxy[0].tolist()], "det_conf": round(float(box.conf[0]), 4)}
            for box in result.boxes]


def crop(image: Image.Image, xyxy: list[float], pad: int = 4) -> Image.Image:
    x1, y1, x2, y2 = xyxy
    return image.crop((max(0, int(x1) - pad), max(0, int(y1) - pad),
                       min(image.width, int(x2) + pad), min(image.height, int(y2) + pad)))


class Matcher:
    """CLIP image embeddings of logo crops vs. reference logos."""

    def __init__(self, clip_name: str) -> None:
        self.model, self.processor = load_clip(clip_name)
        brands = sorted((row for row in read_jsonl(CATALOG) if row.get("normalized_image")), key=lambda r: r["brand_id"])
        self.brand_ids = [row["brand_id"] for row in brands]
        tiles = [logo_tile(ROOT / row["normalized_image"]) for row in brands]
        self.ref_images = [self._flatten(tile) for tile in tiles]
        self.ref_emb = self.embed(self.ref_images)
        self.ref_hash = [imagehash.phash(image) for image in self.ref_images]

    @staticmethod
    def _flatten(tile: Image.Image) -> Image.Image:
        canvas = Image.new("RGB", tile.size, (255, 255, 255))
        canvas.paste(tile, (0, 0), tile)
        return canvas

    def embed(self, images: list[Image.Image]) -> np.ndarray:
        if not images:
            return np.zeros((0, self.ref_emb.shape[1] if hasattr(self, "ref_emb") else 512), dtype=np.float32)
        return embed_images(self.model, self.processor, [letterbox(image) for image in images])

    def candidates(self, embedding: np.ndarray, crop_image: Image.Image, k: int) -> list[dict]:
        sims = self.ref_emb @ embedding
        crop_hash = imagehash.phash(crop_image)
        return [{"brand_id": self.brand_ids[i], "cosine": round(float(sims[i]), 4),
                 "phash_distance": int(crop_hash - self.ref_hash[i])} for i in np.argsort(-sims)[:k]]


def analyze_image(path: Path, detector, matcher: Matcher, conf: float, k: int, crop_dir: Path, tag: str,
                  screenshot: bool = False) -> dict:
    image = open_rgb(path)
    if screenshot:
        image = image.crop((0, 0, image.width, min(image.height, int(image.width * 0.75))))
    detections = detect(detector, image, conf)
    crops = [crop(image, det["xyxy"]) for det in detections]
    embeddings = matcher.embed(crops)
    for index, (det, crop_image) in enumerate(zip(detections, crops)):
        crop_path = crop_dir / f"{tag}_{index:02d}.png"
        crop_image.save(crop_path)
        det["crop"] = rel(crop_path)
        det["top_k"] = matcher.candidates(embeddings[index], crop_image, k)
    global_emb = matcher.embed([image])[0]
    return {"image": image, "detections": detections, "embeddings": embeddings, "global_embedding": global_emb}


def best_brand(detections: list[dict]) -> tuple[str | None, float]:
    best = max((d["top_k"][0] for d in detections if d.get("top_k")), key=lambda c: c["cosine"], default=None)
    return (best["brand_id"], best["cosine"]) if best else (None, 0.0)


def f1_at(items: list[dict], threshold: float) -> dict:
    tp = fp = fn = 0
    for item in items:
        pred = item["pred"] if item["score"] >= threshold else None
        if pred is not None and pred == item["true"]:
            tp += 1
        elif pred is not None:
            fp += 1
        if item["true"] is not None and pred != item["true"]:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"n": len(items), "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def top1(items: list[dict]) -> float | None:
    known = [item for item in items if item["true"] is not None]
    return round(sum(item["pred"] == item["true"] for item in known) / len(known), 4) if known else None


def draw(image: Image.Image, detections: list[dict], truth: list[list[float]] | None = None) -> Image.Image:
    canvas = image.copy()
    pen = ImageDraw.Draw(canvas)
    for box in truth or []:
        pen.rectangle(box, outline=(0, 160, 255), width=2)
    for det in detections:
        pen.rectangle(det["xyxy"], outline=(255, 40, 40), width=3)
        label = f"{det['top_k'][0]['brand_id']} {det['top_k'][0]['cosine']:.2f} | {det['det_conf']:.2f}" if det.get("top_k") else ""
        x, y = det["xyxy"][0], max(0, det["xyxy"][1] - 14)
        pen.rectangle((x, y, x + 7 * len(label), y + 13), fill=(255, 40, 40))
        pen.text((x + 2, y), label, fill=(255, 255, 255))
    return canvas


def grid(images: list[Image.Image], path: Path, columns: int = 3, cell: tuple[int, int] = (520, 340)) -> None:
    rows = (len(images) + columns - 1) // columns
    sheet = Image.new("RGB", (cell[0] * columns, cell[1] * rows), (255, 255, 255))
    for index, image in enumerate(images):
        thumb = image.copy()
        thumb.thumbnail(cell)
        sheet.paste(thumb, ((index % columns) * cell[0], (index // columns) * cell[1]))
    sheet.save(path)


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--detector", type=Path, default=DEFAULT_DETECTOR)
    parser.add_argument("--clip", default=DEFAULT_CLIP)
    parser.add_argument("--conf", type=float, default=0.25)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()
    started = time.time()

    from ultralytics import YOLO

    detector = YOLO(str(args.detector))
    matcher = Matcher(args.clip)
    catalog_ids = set(matcher.brand_ids)
    for directory in (CROPS_DIR, VIZ_DIR):
        if directory.exists():
            shutil.rmtree(directory)
    for sub in ("eval", "posts", "screenshots"):
        (CROPS_DIR / sub).mkdir(parents=True)
    VIZ_DIR.mkdir(parents=True)
    examples: list[Image.Image] = []

    # ------------------------------------------------ YOLO val/test (evaluation)
    det_counts = {s: {o: Counter() for o in ("dom", "synthetic")} for s in ("val", "test")}
    match_items = {s: {"synthetic_gt_crop": [], "synthetic_detected": [], "dom_page": []} for s in ("val", "test")}
    for row in read_jsonl(MANIFEST):
        if row["split"] not in ("val", "test"):
            continue
        split, origin = row["split"], row["origin"]
        out = analyze_image(ROOT / row["image"], detector, matcher, args.conf, args.top_k, CROPS_DIR / "eval", row["image_id"])
        truth = [b["xyxy"] for b in row["boxes"]]
        matched = set()
        for det in out["detections"]:
            hit = max(range(len(truth)), key=lambda i: iou(det["xyxy"], truth[i]), default=None)
            if hit is not None and hit not in matched and iou(det["xyxy"], truth[hit]) >= 0.5:
                matched.add(hit)
                det["gt_index"] = hit
                det_counts[split][origin]["tp"] += 1
            else:
                det_counts[split][origin]["fp"] += 1
        det_counts[split][origin]["fn"] += len(truth) - len(matched)

        if origin == "synthetic":
            gt_crops = [crop(out["image"], box) for box in truth]
            for box, emb, gt_crop in zip(row["boxes"], matcher.embed(gt_crops), gt_crops):
                top = matcher.candidates(emb, gt_crop, 1)[0]
                match_items[split]["synthetic_gt_crop"].append({"true": box["brand_id"], "pred": top["brand_id"], "score": top["cosine"]})
            for det in out["detections"]:
                if "gt_index" in det:
                    top = det["top_k"][0]
                    match_items[split]["synthetic_detected"].append(
                        {"true": row["boxes"][det["gt_index"]]["brand_id"], "pred": top["brand_id"], "score": top["cosine"]})
        elif row["page_label"] == "phishing":
            pred, score = best_brand(out["detections"])
            target = row["target_brand"]
            match_items[split]["dom_page"].append({"true": target if target in catalog_ids else None, "pred": pred, "score": score})
        if split == "test" and len(examples) < 6 and (origin == "synthetic" or len(examples) < 3):
            examples.append(draw(out["image"], out["detections"], truth))
    mark_checklist("Detect logo bounding boxes")
    mark_checklist("Extract detected logo regions")
    mark_checklist("Generate visual embeddings")
    mark_checklist("Calculate logo similarity")
    mark_checklist("Compare detected logo with references")

    val_items = match_items["val"]["synthetic_detected"] + match_items["val"]["dom_page"]
    threshold = max(np.round(np.arange(0.5, 1.0, 0.01), 2), key=lambda t: f1_at(val_items, float(t))["f1"])
    threshold = float(threshold)

    # --------------------------------------------- dataset posts / screenshots
    now = datetime.now(timezone.utc).isoformat()
    results, analyzed = [], {}
    metadata = read_jsonl(METADATA)
    for record in metadata:
        for index, ref in enumerate((record.get("post") or {}).get("images", [])):
            path = ROOT / ref
            if not path.exists():
                continue
            out = analyze_image(path, detector, matcher, args.conf, args.top_k, CROPS_DIR / "posts", f"{record['sample_id']}_{index:02d}")
            analyzed[("post", record["sample_id"])] = out
            pred, score = best_brand(out["detections"])
            results.append({"sample_id": record["sample_id"], "input_type": "post_image", "image": ref,
                            "source": (record.get("source") or {}).get("source_dataset") or "manual",
                            "claimed_brand": (record.get("brand") or {}).get("claimed_brand"),
                            "detections": out["detections"], "best_brand": pred if score >= threshold else None,
                            "best_cosine": round(score, 4), "threshold": threshold, "created_at": now})
    for capture in read_jsonl(CAPTURES):
        shot = ROOT / (capture.get("screenshot") or "")
        if capture.get("status") != "captured" or not shot.is_file():
            continue
        out = analyze_image(shot, detector, matcher, args.conf, args.top_k, CROPS_DIR / "screenshots", capture["sample_id"], screenshot=True)
        analyzed[("web", capture["sample_id"])] = out
        pred, score = best_brand(out["detections"])
        results.append({"sample_id": capture["sample_id"], "input_type": "website_screenshot", "image": capture["screenshot"],
                        "final_domain": capture.get("final_registered_domain"), "detections": out["detections"],
                        "best_brand": pred if score >= threshold else None, "best_cosine": round(score, 4),
                        "threshold": threshold, "created_at": now})
        out_image = draw(out["image"], out["detections"])
        out_image.save(VIZ_DIR / f"{capture['sample_id']}_web.jpg")
        if len(examples) < 9:
            examples.append(out_image)
    for row in results:
        if row["input_type"] == "post_image" and row["source"] == "manual":
            out = analyzed[("post", row["sample_id"])]
            image = draw(out["image"], out["detections"])
            image.save(VIZ_DIR / f"{row['sample_id']}_post.jpg")
            if len(examples) < 12:
                examples.append(image)

    # ------------------------------------------ post image vs website image
    pairs = []
    for (kind, sample_id), web in analyzed.items():
        if kind != "web" or ("post", sample_id) not in analyzed:
            continue
        post = analyzed[("post", sample_id)]
        cross = post["embeddings"] @ web["embeddings"].T if len(post["embeddings"]) and len(web["embeddings"]) else None
        post_brand, post_score = best_brand(post["detections"])
        web_brand, web_score = best_brand(web["detections"])
        pairs.append({
            "sample_id": sample_id,
            "global_cosine": round(float(post["global_embedding"] @ web["global_embedding"]), 4),
            "global_phash_distance": int(imagehash.phash(post["image"]) - imagehash.phash(web["image"])),
            "post_logos": len(post["detections"]), "web_logos": len(web["detections"]),
            "best_logo_pair_cosine": round(float(cross.max()), 4) if cross is not None else None,
            "post_best_brand": post_brand, "post_best_cosine": round(post_score, 4),
            "web_best_brand": web_brand, "web_best_cosine": round(web_score, 4),
            "same_reference_brand": bool(post_brand and post_brand == web_brand),
            "created_at": now,
        })
    mark_checklist("Compare post image with website image")

    RESULTS.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in results) + "\n", encoding="utf-8")
    PAIRS.write_text("\n".join(json.dumps(row) for row in pairs) + ("\n" if pairs else ""), encoding="utf-8")
    mark_checklist("Save similarity results")

    grid(examples, EXAMPLES)
    mark_checklist("Visualize detected logo regions")

    def prf(c: Counter) -> dict:
        p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0.0
        r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
        return {"tp": c["tp"], "fp": c["fp"], "fn": c["fn"], "precision": round(p, 4), "recall": round(r, 4),
                "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}

    detection = {}
    for split in ("val", "test"):
        total = det_counts[split]["dom"] + det_counts[split]["synthetic"]
        detection[split] = {"all": prf(total), "dom": prf(det_counts[split]["dom"]), "synthetic": prf(det_counts[split]["synthetic"])}
    matching = {name: {"top1": top1(items), **f1_at(items, threshold)} for name, items in match_items["test"].items()}
    evaluation = {
        "detector": rel(args.detector), "clip": args.clip, "det_conf": args.conf, "iou_match": 0.5,
        "brand_threshold": threshold, "threshold_selection": "max F1 on val (synthetic detected boxes + dom phishing pages)",
        "yolo_metrics": json.loads(TRAINING.read_text(encoding="utf-8"))["metrics"] if TRAINING.exists() else None,
        "detection_at_conf": detection,
        "brand_matching_test": matching,
        "dataset": {
            "post_images": sum(r["input_type"] == "post_image" for r in results),
            "post_images_with_logo": sum(r["input_type"] == "post_image" and bool(r["detections"]) for r in results),
            "website_screenshots": sum(r["input_type"] == "website_screenshot" for r in results),
            "accepted_brands": dict(Counter(r["best_brand"] for r in results if r["best_brand"])),
        },
        "post_web_pairs": pairs,
        "runtime_seconds": round(time.time() - started, 1),
        "created_at": now,
    }
    EVALUATION.write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
    mark_checklist("Evaluate baseline performance")

    print(f"[threshold] brand cosine >= {threshold}")
    for split, values in detection.items():
        print(f"[detect:{split}] {json.dumps(values)}")
    for name, values in matching.items():
        print(f"[match:test:{name}] {values}")
    for pair in pairs:
        print(f"[pair] {pair['sample_id']} global={pair['global_cosine']} logos={pair['post_logos']}/{pair['web_logos']} "
              f"best_pair={pair['best_logo_pair_cosine']} brands={pair['post_best_brand']}/{pair['web_best_brand']}")
    print(f"[dataset] {json.dumps(evaluation['dataset'])}")
    print(f"Wrote {EVALUATION} ({evaluation['runtime_seconds']}s)")


if __name__ == "__main__":
    main()
