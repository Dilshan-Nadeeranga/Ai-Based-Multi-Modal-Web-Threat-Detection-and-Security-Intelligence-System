"""Visual threat + CLIP brand analysis (zero-shot, 24 reference brands).

Pipeline (checklist items):
  Load CLIP model -> preprocess images -> image / brand-text / reference-logo
  embeddings -> cosine similarity -> Top-K candidates -> select threshold on a
  calibration split -> analyze post images and website screenshots -> store
  predicted brand + confidence -> evaluate -> save experiment results.

Evaluation data (brand ground truth, never used as references):
  * Zenodo_Phishing phishing screenshots: target brand from phishing.csv.
    Brands outside the catalog are "unknown" and must be rejected.
    Split 50/50 (seeded, stratified known/unknown) into calibration / test.
  * Official homepage screenshots of the catalog brands (known brands).

Writes:
  models/clip_brand/<model>/                       — cached embeddings (gitignored)
  data/annotations/clip_brand_predictions.jsonl    — dataset post images + web screenshots
  data/annotations/clip_brand_checklist_status.json
  data/statistics/clip_brand_experiment_<model>.json       — config, threshold, metrics
  data/statistics/clip_brand_eval_predictions_<model>.jsonl

Usage:
  python scripts/clip_brand_analysis.py
  python scripts/clip_brand_analysis.py --model openai/clip-vit-base-patch16 --top-k 5
  python scripts/clip_brand_analysis.py --write-metadata   # also fill brand.detected_brand/confidence
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

import numpy as np
import torch
from PIL import Image

from app.services.image_preprocessor import convert_to_rgb

ROOT = _bootstrap.SERVICE_ROOT
ANNOTATIONS = ROOT / "data" / "annotations"
CATALOG = ANNOTATIONS / "brand_catalog.jsonl"
METADATA = ANNOTATIONS / "dataset_metadata.jsonl"
CAPTURES = ANNOTATIONS / "webpage_captures.jsonl"
PREDICTIONS = ANNOTATIONS / "clip_brand_predictions.jsonl"
STATUS = ANNOTATIONS / "clip_brand_checklist_status.json"
STATS_DIR = ROOT / "data" / "statistics"
EXPERIMENT = "clip_brand_experiment_{run}.json"
EVAL_PREDICTIONS = "clip_brand_eval_predictions_{run}.jsonl"
CACHE_DIR = ROOT / "models" / "clip_brand"

DEFAULT_MODEL = "openai/clip-vit-base-patch32"
DEFAULT_ZENODO = Path(r"D:\Reasearch\Datasets\Zenodo_Phishing")
ZENODO_SHOTS = ("original_js_on.jpg", "index_js_on.jpg", "clean_js_on.jpg")
LOGIT_SCALE = 100.0
MODES = ("text", "logo", "fused")

CHECKLIST = [
    "Load CLIP model",
    "Preprocess post images",
    "Generate image embeddings",
    "Generate brand text embeddings",
    "Generate reference-logo embeddings",
    "Calculate cosine similarity",
    "Generate Top-K brand candidates",
    "Select similarity threshold",
    "Analyze post image brand",
    "Analyze website screenshot brand",
    "Store predicted brand",
    "Store similarity confidence",
    "Evaluate brand recognition",
    "Save experiment results",
]

TEXT_TEMPLATES = (
    "the {name} logo",
    "a screenshot of the {name} website",
    "a {name} login page",
    "a social media post from {name}",
    "{name}",
)


def mark_checklist(item: str, done: bool = True) -> None:
    if STATUS.exists():
        data = json.loads(STATUS.read_text(encoding="utf-8"))
    else:
        data = {"task": "Visual Threat + CLIP Brand Analysis",
                "items": [{"item": name, "done": False} for name in CHECKLIST]}
    for entry in data["items"]:
        if entry["item"] == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data["items"] if entry["done"])
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------- CLIP

def load_clip(name: str):
    from transformers import CLIPModel, CLIPProcessor

    model = CLIPModel.from_pretrained(name).eval()
    processor = CLIPProcessor.from_pretrained(name)
    return model, processor


def _features(output) -> torch.Tensor:
    return output if isinstance(output, torch.Tensor) else output.pooler_output


@torch.no_grad()
def embed_images(model, processor, images: list[Image.Image], batch_size: int = 16) -> np.ndarray:
    vectors = []
    for start in range(0, len(images), batch_size):
        inputs = processor(images=images[start:start + batch_size], return_tensors="pt")
        features = _features(model.get_image_features(pixel_values=inputs["pixel_values"]))
        vectors.append(torch.nn.functional.normalize(features, dim=-1))
    return torch.cat(vectors).numpy()


@torch.no_grad()
def embed_texts(model, processor, texts: list[str]) -> np.ndarray:
    inputs = processor(text=texts, padding=True, truncation=True, return_tensors="pt")
    features = _features(model.get_text_features(input_ids=inputs["input_ids"], attention_mask=inputs["attention_mask"]))
    return torch.nn.functional.normalize(features, dim=-1).numpy()


# ------------------------------------------------------------------ preprocessing

def letterbox(image: Image.Image, fill: tuple[int, int, int] = (255, 255, 255)) -> Image.Image:
    width, height = image.size
    side = max(width, height)
    canvas = Image.new("RGB", (side, side), fill)
    canvas.paste(image, ((side - width) // 2, (side - height) // 2))
    return canvas


def open_rgb(path: Path) -> Image.Image:
    with Image.open(path) as image:
        image.load()
        rgb = convert_to_rgb(image)
    rgb.thumbnail((1600, 6000))
    return rgb


def post_views(image: Image.Image) -> list[Image.Image]:
    """Whole image (letterboxed) + CLIP's default centre crop."""
    return [letterbox(image), image]


def screenshot_views(image: Image.Image) -> list[Image.Image]:
    """First viewport + top-left header, where logos usually sit."""
    width, height = image.size
    viewport = image.crop((0, 0, width, min(height, int(width * 0.75))))
    header = viewport.crop((0, 0, max(1, width // 2), max(1, viewport.height // 3)))
    return [letterbox(viewport), letterbox(header)]


# ------------------------------------------------------------------- references

def load_brands() -> list[dict]:
    brands = [row for row in read_jsonl(CATALOG) if row.get("normalized_image") and row.get("status") != "duplicate_logo"]
    return sorted(brands, key=lambda row: row["brand_id"])


def brand_prompts(brand: dict) -> list[str]:
    names = [brand["display_name"], *brand.get("aliases", [])]
    prompts = [template.format(name=name) for name in names for template in TEXT_TEMPLATES]
    if brand.get("official_domain"):
        prompts.append(f"the {brand['official_domain']} website")
    return prompts


def reference_embeddings(model, processor, brands: list[dict], cache: Path) -> tuple[np.ndarray, np.ndarray]:
    text_vectors = []
    for brand in brands:
        vectors = embed_texts(model, processor, brand_prompts(brand))
        mean = vectors.mean(axis=0)
        text_vectors.append(mean / np.linalg.norm(mean))
    text_emb = np.stack(text_vectors)
    mark_checklist("Generate brand text embeddings")

    logos = [open_rgb(ROOT / brand["normalized_image"]) for brand in brands]
    logo_emb = embed_images(model, processor, logos)
    mark_checklist("Generate reference-logo embeddings")

    cache.mkdir(parents=True, exist_ok=True)
    np.save(cache / "brand_text_embeddings.npy", text_emb)
    np.save(cache / "reference_logo_embeddings.npy", logo_emb)
    (cache / "brand_order.json").write_text(json.dumps([b["brand_id"] for b in brands], indent=2), encoding="utf-8")
    return text_emb, logo_emb


# ---------------------------------------------------------------------- scoring

def softmax(logits: np.ndarray) -> np.ndarray:
    shifted = np.exp(logits - logits.max())
    return shifted / shifted.sum()


def score_views(view_emb: np.ndarray, text_emb: np.ndarray, logo_emb: np.ndarray) -> dict[str, np.ndarray]:
    """Cosine similarity per brand (max over views) and per-mode probabilities."""
    text_sim = (view_emb @ text_emb.T).max(axis=0)
    logo_sim = (view_emb @ logo_emb.T).max(axis=0)
    return {
        "text_sim": text_sim,
        "logo_sim": logo_sim,
        "text": softmax(LOGIT_SCALE * text_sim),
        "logo": softmax(LOGIT_SCALE * logo_sim),
        "fused": softmax(LOGIT_SCALE * 0.5 * (text_sim + logo_sim)),
    }


def top_k(scores: dict[str, np.ndarray], mode: str, brand_ids: list[str], k: int) -> list[dict]:
    probs = scores[mode]
    order = np.argsort(-probs)[:k]
    return [{
        "brand_id": brand_ids[i],
        "probability": round(float(probs[i]), 4),
        "text_cosine": round(float(scores["text_sim"][i]), 4),
        "logo_cosine": round(float(scores["logo_sim"][i]), 4),
    } for i in order]


def analyze(items: list[dict], model, processor, text_emb, logo_emb) -> None:
    """Attach ``scores`` to each item ({"paths": [...], "kind": post|screenshot})."""
    for index, item in enumerate(items, 1):
        views = []
        for path in item["paths"]:
            try:
                image = open_rgb(path)
            except (OSError, ValueError) as exc:
                print(f"[skip] {path}: {exc}")
                continue
            views.extend(screenshot_views(image) if item["kind"] == "screenshot" else post_views(image))
        item["scores"] = score_views(embed_images(model, processor, views), text_emb, logo_emb) if views else None
        if index % 100 == 0:
            print(f"  ... {index}/{len(items)}")


# ------------------------------------------------------------------- evaluation

def decide(item: dict, mode: str, threshold: float, brand_ids: list[str]) -> tuple[str | None, float, str]:
    probs = item["scores"][mode]
    best = int(np.argmax(probs))
    confidence = float(probs[best])
    return (brand_ids[best] if confidence >= threshold else None), confidence, brand_ids[best]


def evaluate(items: list[dict], mode: str, threshold: float, brand_ids: list[str]) -> dict:
    items = [item for item in items if item.get("scores") is not None]
    known = [item for item in items if item["true"] is not None]
    unknown = [item for item in items if item["true"] is None]
    tp = fp = fn = correct = rejected_unknown = 0
    per_brand: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for item in items:
        pred, _, _ = decide(item, mode, threshold, brand_ids)
        if pred is not None and pred == item["true"]:
            tp += 1
        elif pred is not None:
            fp += 1
        if item["true"] is not None:
            fn += pred != item["true"]
            per_brand[item["true"]][1] += 1
            per_brand[item["true"]][0] += pred == item["true"]
        else:
            rejected_unknown += pred is None
        correct += pred == item["true"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def topk_acc(k: int) -> float | None:
        if not known:
            return None
        hits = sum(item["true"] in [brand_ids[i] for i in np.argsort(-item["scores"][mode])[:k]] for item in known)
        return round(hits / len(known), 4)

    return {
        "n": len(items), "n_known": len(known), "n_unknown": len(unknown),
        "closed_set_top1": topk_acc(1), "closed_set_top3": topk_acc(3), "closed_set_top5": topk_acc(5),
        "open_set_accuracy": round(correct / len(items), 4) if items else None,
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "unknown_rejection_rate": round(rejected_unknown / len(unknown), 4) if unknown else None,
        "per_brand_recall": {b: {"correct": c, "n": n, "recall": round(c / n, 4)} for b, (c, n) in sorted(per_brand.items())},
    }


def select_threshold(items: list[dict], mode: str, brand_ids: list[str], min_reject: float) -> tuple[float, float]:
    """Max open-set F1 among thresholds that still reject ``min_reject`` of unknown brands."""
    best_t, best_f1 = 0.99, -1.0
    for threshold in np.round(np.arange(0.0, 1.0, 0.01), 2):
        metrics = evaluate(items, mode, float(threshold), brand_ids)
        f1, reject = metrics["f1"], metrics["unknown_rejection_rate"]
        if reject is not None and reject < min_reject:
            continue
        if f1 > best_f1:
            best_t, best_f1 = float(threshold), f1
    return best_t, best_f1


# ------------------------------------------------------------------------ data

def zenodo_items(root: Path, brand_ids: set[str], limit: int | None) -> list[dict]:
    folder = root / "phishing_0001-0500"
    csv.field_size_limit(sys.maxsize)
    with (root / "phishing.csv").open(encoding="utf-8", errors="replace", newline="") as handle:
        targets = {row["_id"]: json.loads(row["brands"] or "[]") for row in csv.DictReader(handle)}
    items = []
    for sample in sorted(os.listdir(folder))[:limit]:
        shot = next((folder / sample / "screenshots" / name for name in ZENODO_SHOTS
                     if (folder / sample / "screenshots" / name).exists()), None)
        if shot is None or sample not in targets:
            continue
        target = (targets[sample] or [None])[0]
        items.append({"id": sample, "kind": "screenshot", "paths": [shot], "source": "zenodo_phishing",
                      "target_brand": target, "true": target if target in brand_ids else None})
    return items


def official_items(brands: list[dict]) -> list[dict]:
    items = []
    for brand in brands:
        files = [ROOT / ref for ref in brand.get("screenshot_files", []) if (ROOT / ref).exists()]
        if files:
            items.append({"id": f"official_{brand['brand_id']}", "kind": "screenshot", "paths": files[:1],
                          "source": "official_homepage", "true": brand["brand_id"]})
    return items


def calibration_split(items: list[dict], seed: int) -> tuple[list[dict], list[dict]]:
    rng = random.Random(seed)
    calibration, test = [], []
    for is_known in (True, False):
        group = [item for item in items if (item["true"] is not None) == is_known]
        rng.shuffle(group)
        half = len(group) // 2
        calibration.extend(group[:half])
        test.extend(group[half:])
    return calibration, test


def dataset_items(brands: list[dict]) -> list[dict]:
    names = {}
    for brand in brands:
        for name in (brand["brand_id"], brand["display_name"], *brand.get("aliases", [])):
            names[name.lower()] = brand["brand_id"]
    items = []
    for record in read_jsonl(METADATA):
        paths = [ROOT / ref for ref in (record.get("post") or {}).get("images", []) if (ROOT / ref).exists()]
        if paths:
            claimed = (record.get("brand") or {}).get("claimed_brand")
            items.append({"id": record["sample_id"], "kind": "post", "paths": paths,
                          "source": (record.get("source") or {}).get("source_dataset") or "manual",
                          "claimed_brand": claimed,
                          "true": names.get((claimed or "").lower()) if claimed else "n/a"})
    mark_checklist("Preprocess post images")
    for capture in read_jsonl(CAPTURES):
        shot = ROOT / (capture.get("screenshot") or "")
        if capture.get("status") == "captured" and shot.is_file():
            items.append({"id": capture["sample_id"], "kind": "screenshot", "paths": [shot], "source": "webpage_capture",
                          "final_domain": capture.get("final_registered_domain"), "true": "n/a"})
    return items


def write_metadata(predictions: list[dict], display: dict[str, str]) -> int:
    by_sample: dict[str, dict] = {}
    for row in predictions:
        current = by_sample.get(row["sample_id"])
        if row["predicted_brand"] and (current is None or row["confidence"] > current["confidence"]):
            by_sample[row["sample_id"]] = row
    lines, changed = [], 0
    for line in METADATA.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        row = by_sample.get(record["sample_id"])
        if row:
            brand = record.setdefault("brand", {})
            brand["detected_brand"] = display[row["predicted_brand"]]
            brand["confidence"] = round(row["confidence"], 4)
            changed += 1
        lines.append(json.dumps(record, ensure_ascii=False))
    tmp = METADATA.with_suffix(".jsonl.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, METADATA)
    return changed


# ------------------------------------------------------------------------- main

def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--zenodo", type=Path, default=DEFAULT_ZENODO)
    parser.add_argument("--zenodo-limit", type=int, default=None)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--min-reject", type=float, default=0.90,
                        help="Minimum unknown-brand rejection rate on calibration when picking the threshold")
    parser.add_argument("--write-metadata", action="store_true",
                        help="Also write accepted predictions into dataset_metadata.jsonl brand fields")
    args = parser.parse_args()
    started = time.time()
    STATS_DIR.mkdir(parents=True, exist_ok=True)
    run = args.model.split("/")[-1]
    experiment_path = STATS_DIR / EXPERIMENT.format(run=run)
    eval_path = STATS_DIR / EVAL_PREDICTIONS.format(run=run)

    print(f"[clip] loading {args.model}")
    model, processor = load_clip(args.model)
    mark_checklist("Load CLIP model")

    brands = load_brands()
    brand_ids = [brand["brand_id"] for brand in brands]
    display = {brand["brand_id"]: brand["display_name"] for brand in brands}
    text_emb, logo_emb = reference_embeddings(model, processor, brands, CACHE_DIR / args.model.split("/")[-1])
    print(f"[refs] {len(brands)} brands, embedding dim {text_emb.shape[1]}")

    zenodo = zenodo_items(args.zenodo, set(brand_ids), args.zenodo_limit) if args.zenodo.exists() else []
    official = official_items(brands)
    data_items = dataset_items(brands)
    print(f"[data] zenodo={len(zenodo)} official={len(official)} dataset={len(data_items)}")

    for label, items in (("zenodo", zenodo), ("official", official), ("dataset", data_items)):
        print(f"[embed] {label}")
        analyze(items, model, processor, text_emb, logo_emb)
    mark_checklist("Generate image embeddings")
    mark_checklist("Calculate cosine similarity")

    calibration, test = calibration_split(zenodo, args.seed)
    candidates = {}
    for mode in MODES:
        threshold, f1 = select_threshold(calibration, mode, brand_ids, args.min_reject)
        candidates[mode] = {"threshold": threshold, "calibration_f1": round(f1, 4),
                            "calibration_top1": evaluate(calibration, mode, threshold, brand_ids)["closed_set_top1"]}
        print(f"[calibrate] {mode:5} threshold={threshold} f1={f1:.4f} top1={candidates[mode]['calibration_top1']}")
    mode = max(MODES, key=lambda m: (candidates[m]["calibration_f1"], candidates[m]["calibration_top1"] or 0))
    threshold = candidates[mode]["threshold"]
    mark_checklist("Select similarity threshold")
    print(f"[select] mode={mode} threshold={threshold}")

    now = datetime.now(timezone.utc).isoformat()
    predictions = []
    for item in data_items:
        if item["scores"] is None:
            continue
        pred, confidence, best = decide(item, mode, threshold, brand_ids)
        predictions.append({
            "sample_id": item["id"], "input_type": "post_image" if item["kind"] == "post" else "website_screenshot",
            "source": item["source"], "images": [str(p.relative_to(ROOT)).replace("\\", "/") for p in item["paths"]],
            "claimed_brand": item.get("claimed_brand"), "final_domain": item.get("final_domain"),
            "predicted_brand": pred, "predicted_display_name": display.get(pred) if pred else None,
            "confidence": round(confidence, 4), "best_candidate": best,
            "top_k": top_k(item["scores"], mode, brand_ids, args.top_k),
            "model": args.model, "mode": mode, "threshold": threshold, "created_at": now,
        })
    mark_checklist("Generate Top-K brand candidates")
    mark_checklist("Analyze post image brand")
    mark_checklist("Analyze website screenshot brand")
    PREDICTIONS.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in predictions) + "\n", encoding="utf-8")
    mark_checklist("Store predicted brand")
    mark_checklist("Store similarity confidence")
    changed = write_metadata(predictions, display) if args.write_metadata else 0

    results = {
        "zenodo_test": {m: evaluate(test, m, candidates[m]["threshold"], brand_ids) for m in MODES},
        "zenodo_calibration": evaluate(calibration, mode, threshold, brand_ids),
        "official_homepages": evaluate(official, mode, threshold, brand_ids),
    }
    manual = [i for i in data_items if i["kind"] == "post" and i["source"] == "manual" and i.get("scores") is not None]
    manual_known = [i for i in manual if i["true"] not in (None, "n/a")]
    manual_unknown = [dict(i, true=None) for i in manual if i["true"] is None]
    results["manual_posts_out_of_catalog"] = evaluate(manual_unknown, mode, threshold, brand_ids)
    if manual_known:
        results["manual_posts_in_catalog"] = evaluate(manual_known, mode, threshold, brand_ids)
    mark_checklist("Evaluate brand recognition")

    eval_rows = []
    for split, items in (("calibration", calibration), ("test", test), ("official", official)):
        for item in items:
            if item["scores"] is None:
                continue
            pred, confidence, best = decide(item, mode, threshold, brand_ids)
            eval_rows.append({"id": item["id"], "split": split, "source": item["source"],
                              "target_brand": item.get("target_brand", item["true"]), "true": item["true"],
                              "predicted_brand": pred, "confidence": round(confidence, 4), "best_candidate": best,
                              "correct": pred == item["true"], "top_k": top_k(item["scores"], mode, brand_ids, args.top_k)})
    eval_path.write_text("\n".join(json.dumps(row) for row in eval_rows) + "\n", encoding="utf-8")

    experiment = {
        "experiment": "clip_brand_zero_shot",
        "model": args.model,
        "brands": brand_ids,
        "text_templates": TEXT_TEMPLATES,
        "logit_scale": LOGIT_SCALE,
        "views": {"post": ["letterbox_full", "center_crop"], "screenshot": ["letterbox_viewport", "letterbox_header_left"]},
        "selected_mode": mode,
        "selected_threshold": threshold,
        "threshold_selection": f"max open-set F1 on Zenodo calibration split with unknown rejection >= {args.min_reject}",
        "mode_candidates": candidates,
        "seed": args.seed,
        "data": {
            "zenodo_calibration": len(calibration), "zenodo_test": len(test),
            "zenodo_target_brands_out_of_catalog": dict(Counter(i["target_brand"] for i in zenodo if i["true"] is None).most_common(15)),
            "official_homepages": len(official),
            "dataset_post_images": sum(1 for p in predictions if p["input_type"] == "post_image"),
            "dataset_website_screenshots": sum(1 for p in predictions if p["input_type"] == "website_screenshot"),
        },
        "results": results,
        "dataset_predictions": {
            "accepted": sum(1 for p in predictions if p["predicted_brand"]),
            "rejected_unknown": sum(1 for p in predictions if not p["predicted_brand"]),
            "accepted_by_brand": dict(Counter(p["predicted_brand"] for p in predictions if p["predicted_brand"])),
            "metadata_rows_updated": changed,
        },
        "outputs": {"predictions": "data/annotations/clip_brand_predictions.jsonl",
                    "eval_predictions": f"data/statistics/{eval_path.name}",
                    "embeddings": f"models/clip_brand/{run}/"},
        "runtime_seconds": round(time.time() - started, 1),
        "created_at": now,
    }
    experiment_path.write_text(json.dumps(experiment, indent=2), encoding="utf-8")
    mark_checklist("Save experiment results")

    for name, metrics in results.items():
        if name == "zenodo_test":
            for m, r in metrics.items():
                print(f"[test:{m:5}] top1={r['closed_set_top1']} top5={r['closed_set_top5']} "
                      f"P={r['precision']} R={r['recall']} F1={r['f1']} reject_unknown={r['unknown_rejection_rate']}")
        else:
            print(f"[{name}] n={metrics['n']} top1={metrics['closed_set_top1']} F1={metrics['f1']} "
                  f"reject_unknown={metrics['unknown_rejection_rate']}")
    print(f"[dataset] accepted={experiment['dataset_predictions']['accepted']} "
          f"rejected={experiment['dataset_predictions']['rejected_unknown']} metadata_updated={changed}")
    print(f"Wrote {experiment_path} ({experiment['runtime_seconds']}s)")


if __name__ == "__main__":
    main()
