"""Prepare the Text + OCR threat baseline dataset.

Steps (checklist items):
  1. Clean social post text
  2. Clean OCR text (runs Tesseract on post images when OCR is missing)
  3. Combine/compare post and OCR text
  4. Prepare training data (stratified train/val/test split)

Only verified rows with ``labels.is_scam`` in {0, 1} are used. Fakeddit rows
(``not_annotated``) are excluded; they are a misinformation task, not scam.

Writes:
  data/annotations/text_baseline_dataset.jsonl   — one row per sample
  data/annotations/text_baseline_splits.json     — split summary
  data/annotations/text_baseline_checklist_status.json

Usage:
  python scripts/prepare_text_baseline.py
  python scripts/prepare_text_baseline.py --seed 42 --no-ocr
  python scripts/prepare_text_baseline.py --keep-existing   # add new samples without moving existing ones
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import random
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import _bootstrap

ROOT = _bootstrap.SERVICE_ROOT
METADATA = ROOT / "data" / "annotations" / "dataset_metadata.jsonl"
DATASET = ROOT / "data" / "annotations" / "text_baseline_dataset.jsonl"
SPLITS = ROOT / "data" / "annotations" / "text_baseline_splits.json"
STATUS = ROOT / "data" / "annotations" / "text_baseline_checklist_status.json"

CHECKLIST = [
    "Clean social post text",
    "Clean OCR text",
    "Combine/compare post and OCR text",
    "Tokenize text",
    "Select baseline transformer",
    "Prepare training data",
    "Train text baseline",
    "Validate text baseline",
    "Test text baseline",
    "Calculate Precision/Recall/F1",
    "Generate confusion matrix",
    "Save trained model",
]

MAX_CHARS = 4000
OCR_DUPLICATE_OVERLAP = 0.8

_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_TAG = re.compile(r"<[^>]{1,200}>")
_ZERO_WIDTH = re.compile(r"[\u200b\u200e\u200f\u2060\ufeff]")  # keep ZWJ/ZWNJ for Sinhala/Tamil
_CONTROL = re.compile(r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]")
_SPACES = re.compile(r"[ \t\u00a0\u3000]+")
_REPEAT = re.compile(r"(.)\1{4,}")
_WORD = re.compile(r"\w+", re.UNICODE)


def ensure_status() -> dict:
    if STATUS.exists():
        return json.loads(STATUS.read_text(encoding="utf-8"))
    data = {
        "task": "Text + OCR Threat Baseline",
        "items": [{"item": item, "done": False} for item in CHECKLIST],
        "done_count": 0,
    }
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def mark_checklist(item: str, done: bool) -> None:
    data = ensure_status()
    for entry in data.get("items", []):
        if entry.get("item") == item:
            entry["done"] = done
    data["done_count"] = sum(1 for entry in data.get("items", []) if entry.get("done"))
    data["updated_at"] = datetime.now(timezone.utc).isoformat()
    STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _url_token(match: re.Match) -> str:
    raw = match.group(0).rstrip(".,);]")
    try:
        host = urlparse(raw if "://" in raw else f"http://{raw}").hostname or ""
    except ValueError:  # malformed URL, e.g. an unbalanced "[" read as an IPv6 host
        host = ""
    return f" [URL {host.removeprefix('www.')}] " if host else " [URL] "


def clean_text(text: str | None) -> str:
    """Normalise post/OCR text while keeping words, URLs (as host) and Unicode scripts."""
    if not text:
        return ""
    value = unicodedata.normalize("NFKC", html.unescape(text))
    value = _TAG.sub(" ", value)
    value = _ZERO_WIDTH.sub("", value)
    value = _CONTROL.sub(" ", value)
    value = _URL.sub(_url_token, value)
    value = _REPEAT.sub(r"\1\1\1", value)
    lines = (_SPACES.sub(" ", line).strip() for line in value.replace("\r", "\n").split("\n"))
    value = " ".join(line for line in lines if line)
    return value[:MAX_CHARS].strip()


def word_set(text: str) -> set[str]:
    return {word.lower() for word in _WORD.findall(text) if len(word) > 1}


def compare(post: str, ocr: str) -> dict:
    post_words, ocr_words = word_set(post), word_set(ocr)
    if not ocr_words:
        return {"ocr_word_count": 0, "jaccard": None, "ocr_in_post": None, "ocr_new_words": 0}
    shared = post_words & ocr_words
    return {
        "ocr_word_count": len(ocr_words),
        "jaccard": round(len(shared) / len(post_words | ocr_words), 4),
        "ocr_in_post": round(len(shared) / len(ocr_words), 4),
        "ocr_new_words": len(ocr_words - post_words),
    }


def combine(post: str, ocr: str, stats: dict) -> tuple[str, str]:
    if not ocr:
        return post, "post_only"
    if not post:
        return ocr, "ocr_only"
    if (stats.get("ocr_in_post") or 0) >= OCR_DUPLICATE_OVERLAP:
        return post, "post_only_ocr_duplicate"
    return f"{post} [OCR] {ocr}", "post_plus_ocr"


def run_ocr(images: list[str], engine) -> tuple[str, float | None]:
    from PIL import Image

    from app.services.image_preprocessor import convert_to_rgb

    texts, confidences = [], []
    for ref in images:
        path = ROOT / ref
        if not path.exists():
            continue
        with Image.open(path) as image:
            result = engine.extract(convert_to_rgb(image))
        if result.text:
            texts.append(result.text)
        if result.average_confidence is not None:
            confidences.append(result.average_confidence)
    confidence = round(sum(confidences) / len(confidences), 2) if confidences else None
    return "\n".join(texts), confidence


def previous_splits() -> dict[str, str]:
    if not DATASET.exists():
        return {}
    rows = (json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip())
    return {row["sample_id"]: row["split"] for row in rows}


def stratified_split(rows: list[dict], seed: int, train: float, val: float,
                     keep: dict[str, str] | None = None) -> dict[str, str]:
    """Split by (source, label); identical texts stay in the same split.

    With ``keep``, rows already assigned there keep their split (and so do identical texts); only the remaining
    rows are split, per (source, label) group, with the same ratios.
    """
    keep = keep or {}
    assignment: dict[str, str] = {row["sample_id"]: keep[row["sample_id"]] for row in rows if row["sample_id"] in keep}
    by_hash = {row["text_hash"]: assignment[row["sample_id"]] for row in rows if row["sample_id"] in assignment}
    groups: dict[tuple, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        if row["sample_id"] in assignment:
            continue
        if row["text_hash"] in by_hash:
            assignment[row["sample_id"]] = by_hash[row["text_hash"]]
            continue
        groups[(row["source_dataset"], row["label"])][row["text_hash"]].append(row["sample_id"])
    rng = random.Random(seed)
    for key in sorted(groups):
        clusters = [groups[key][h] for h in sorted(groups[key])]
        rng.shuffle(clusters)
        n = len(clusters)
        n_train = max(1, round(n * train))
        n_val = max(1, round(n * val)) if n >= 3 else 0
        for index, cluster in enumerate(clusters):
            split = "train" if index < n_train else "val" if index < n_train + n_val else "test"
            for sample_id in cluster:
                assignment[sample_id] = split
    return assignment


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train", type=float, default=0.70)
    parser.add_argument("--val", type=float, default=0.15)
    parser.add_argument("--no-ocr", action="store_true", help="Do not run Tesseract on images")
    parser.add_argument("--keep-existing", action="store_true",
                        help="Keep the split of rows already in text_baseline_dataset.jsonl; only new rows are assigned")
    args = parser.parse_args()
    keep = previous_splits() if args.keep_existing else None

    ensure_status()
    engine = None
    if not args.no_ocr:
        from app.services.ocr_service import create_ocr_engine

        engine = create_ocr_engine(_bootstrap.load_settings())
        if not engine.is_available():
            print("[ocr] Tesseract unavailable; OCR text will be empty")
            engine = None

    rows = []
    for line in METADATA.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        labels = record.get("labels") or {}
        if labels.get("label_status") != "verified" or labels.get("is_scam") not in (0, 1):
            continue
        post = record.get("post") or {}
        ocr = record.get("ocr") or {}
        source = record.get("source") or {}

        ocr_raw, ocr_confidence, ocr_origin = ocr.get("text") or "", ocr.get("average_confidence"), "metadata"
        if not ocr_raw and engine and post.get("images"):
            ocr_raw, ocr_confidence = run_ocr(post["images"], engine)
            ocr_origin = "tesseract"
            print(f"[ocr] {record['sample_id']}: {len(ocr_raw)} chars, conf={ocr_confidence}")
        if not ocr_raw:
            ocr_origin = None

        post_clean = clean_text(post.get("text"))
        ocr_clean = clean_text(ocr_raw)
        stats = compare(post_clean, ocr_clean)
        text, mode = combine(post_clean, ocr_clean, stats)
        rows.append({
            "sample_id": record["sample_id"],
            "source_dataset": source.get("source_dataset") or "manual",
            "platform": source.get("platform"),
            "label": int(labels["is_scam"]),
            "scam_type": labels.get("scam_type"),
            "post_text_clean": post_clean,
            "ocr_text_clean": ocr_clean,
            "ocr_origin": ocr_origin,
            "ocr_confidence": ocr_confidence,
            "comparison": stats,
            "combine_mode": mode,
            "text": text,
            "text_hash": hashlib.sha256(text.lower().encode("utf-8")).hexdigest(),
        })

    rows = [row for row in rows if row["text"]]
    mark_checklist("Clean social post text", True)
    mark_checklist("Clean OCR text", True)
    mark_checklist("Combine/compare post and OCR text", True)

    assignment = stratified_split(rows, args.seed, args.train, args.val, keep)
    now = datetime.now(timezone.utc).isoformat()
    for row in rows:
        row["split"] = assignment[row["sample_id"]]
        row["created_at"] = now
    DATASET.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")

    counts = Counter((row["split"], row["label"]) for row in rows)
    duplicates = len(rows) - len({row["text_hash"] for row in rows})
    summary = {
        "seed": args.seed,
        "ratios": {"train": args.train, "val": args.val, "test": round(1 - args.train - args.val, 4)},
        "unit": "sample_id (stratified by source_dataset + label; identical texts kept together)",
        "total": len(rows),
        "duplicate_texts": duplicates,
        "counts": {
            split: {"legit": counts[(split, 0)], "scam": counts[(split, 1)], "total": counts[(split, 0)] + counts[(split, 1)]}
            for split in ("train", "val", "test")
        },
        "by_source": dict(Counter(f"{row['source_dataset']}|{row['label']}" for row in rows)),
        "combine_modes": dict(Counter(row["combine_mode"] for row in rows)),
        "excluded": "Rows without verified is_scam label (e.g. Fakeddit not_annotated)",
        "created_at": now,
    }
    SPLITS.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    mark_checklist("Prepare training data", True)

    print(f"Wrote {DATASET} ({len(rows)} rows)")
    for split in ("train", "val", "test"):
        print(f"  {split:5}: {summary['counts'][split]}")
    print(f"  combine modes: {summary['combine_modes']}")


if __name__ == "__main__":
    main()
