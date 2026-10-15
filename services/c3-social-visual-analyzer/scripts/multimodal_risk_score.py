"""Preliminary multimodal risk score (LOW / MEDIUM / HIGH) for every sample.

Component scores (0-1, ``None`` when the source is missing):
  text      DistilBERT text baseline P(scam) on the cleaned post text
  ocr       same model on OCR text (>= 15 chars)
  visual    CLIP ViT-B/16 zero-shot: threat prompts vs benign prompts on the post image
  brand     brand similarity: max(logo-to-reference cosine, CLIP brand confidence)
  website   1 - CLIP cosine(post image, landing-page screenshot)
Consistency features come from consistency_results.jsonl (flags, brand mismatch).

Fusion rule (preliminary, hand-set — not learned):
  base   = weighted mean of available components
           (text 0.50, ocr 0.15, visual 0.15, website 0.20)
  brand  = only adds risk when the brand evidence is inconsistent:
           +0.10 * brand  if a brand identity mismatch was detected
  flags  = +0.25 strong / +0.15 moderate / +0.05 weak brand mismatch,
           +0.03 per other low flag (max +0.09)
  score  = min(1, base + brand + flags)
  level  = HIGH >= 0.70, MEDIUM >= 0.40, else LOW
  floor  = LOOKALIKE_DOMAIN or claimed-brand BRAND_DOMAIN_MISMATCH -> at least MEDIUM

The text model was trained on the text_baseline train split, so scores for those
rows are optimistic; the evaluation uses the held-out test split.

Writes:
  data/annotations/risk_scores.jsonl
  data/annotations/risk_score_checklist_status.json
  data/statistics/risk_score_statistics.json

Usage:
  python scripts/multimodal_risk_score.py
"""

from __future__ import annotations

import argparse
import json
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
from sklearn.metrics import roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from clip_brand_analysis import embed_images, embed_texts, letterbox, load_clip, open_rgb
from prepare_text_baseline import clean_text

ROOT = _bootstrap.SERVICE_ROOT
ANNOTATIONS = ROOT / "data" / "annotations"
METADATA = ANNOTATIONS / "dataset_metadata.jsonl"
TEXT_BASELINE = ANNOTATIONS / "text_baseline_dataset.jsonl"
CLIP_PREDICTIONS = ANNOTATIONS / "clip_brand_predictions.jsonl"
LOGO_RESULTS = ANNOTATIONS / "logo_similarity_results.jsonl"
CONSISTENCY = ANNOTATIONS / "consistency_results.jsonl"
OCR_CACHE = ROOT / "data" / "processed" / "consistency" / "ocr_cache.json"
RESULTS = ANNOTATIONS / "risk_scores.jsonl"
STATUS = ANNOTATIONS / "risk_score_checklist_status.json"
STATISTICS = ROOT / "data" / "statistics" / "risk_score_statistics.json"
TEXT_MODEL = ROOT / "models" / "text_baseline" / "distilbert-base-uncased"
DEFAULT_CLIP = "openai/clip-vit-base-patch16"

CHECKLIST = [
    "Collect text threat score",
    "Collect OCR threat score",
    "Collect visual threat score",
    "Collect brand similarity score",
    "Collect website similarity score",
    "Add consistency/mismatch features",
    "Create preliminary fusion rule",
    "Generate LOW / MEDIUM / HIGH result",
]

WEIGHTS = {"text": 0.50, "ocr": 0.15, "visual": 0.15, "website": 0.20}
BRAND_WEIGHT = 0.10
MISMATCH_BOOST = {"strong": 0.25, "moderate": 0.15, "weak": 0.05}
LOW_FLAG_BOOST, LOW_FLAG_CAP = 0.03, 0.09
HIGH_AT, MEDIUM_AT = 0.70, 0.40
MIN_OCR_CHARS = 15

THREAT_PROMPTS = (
    "a fake giveaway post asking people to click a link",
    "a scam advertisement promising free money or prizes",
    "a phishing login page asking for a password",
    "a fake bank or delivery notice asking for payment details",
    "a cryptocurrency investment scam post",
    "a fake job offer asking for a fee",
)
BENIGN_PROMPTS = (
    "an ordinary personal photo",
    "a normal news photo",
    "a legitimate company advertisement",
    "a meme or funny picture",
    "a screenshot of an ordinary website",
    "a photo of everyday objects or places",
)


def mark_checklist(item: str, done: bool = True) -> None:
    if STATUS.exists():
        data = json.loads(STATUS.read_text(encoding="utf-8"))
    else:
        data = {"task": "Preliminary Multimodal Risk Score",
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


@torch.no_grad()
def scam_probabilities(texts: dict[str, str], batch_size: int = 32) -> dict[str, float]:
    tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(TEXT_MODEL).eval()
    ids = [sid for sid, text in texts.items() if text]
    scores = {}
    for start in range(0, len(ids), batch_size):
        chunk = ids[start:start + batch_size]
        encoded = tokenizer([texts[sid] for sid in chunk], truncation=True, max_length=256, padding=True, return_tensors="pt")
        probs = torch.softmax(model(**encoded).logits, dim=-1)[:, 1].tolist()
        scores.update({sid: round(p, 4) for sid, p in zip(chunk, probs)})
    return scores


def fuse(components: dict[str, float | None], consistency: dict | None) -> dict:
    available = {name: value for name, value in components.items() if name in WEIGHTS and value is not None}
    total_weight = sum(WEIGHTS[name] for name in available)
    base = sum(WEIGHTS[name] * value for name, value in available.items()) / total_weight if total_weight else 0.0
    reasons, boost = [], 0.0

    mismatch = (consistency or {}).get("brand_identity_mismatch") or {}
    flags = (consistency or {}).get("flags") or []
    if mismatch.get("detected"):
        boost += MISMATCH_BOOST[mismatch["strength"]]
        reasons.append(f"{mismatch['strength']} brand identity mismatch ({', '.join(mismatch['reasons'])})")
        if components.get("brand") is not None:
            boost += BRAND_WEIGHT * components["brand"]
            reasons.append(f"impersonated brand similarity {components['brand']:.2f}")
    brand_codes = set(mismatch.get("reasons") or [])
    low_flags = [f for f in flags if f["severity"] == "low" and f["code"] not in brand_codes]
    if low_flags:
        boost += min(LOW_FLAG_CAP, LOW_FLAG_BOOST * len(low_flags))
        reasons.append("low flags: " + ", ".join(sorted({f["code"] for f in low_flags})))

    score = min(1.0, base + boost)
    level = "HIGH" if score >= HIGH_AT else "MEDIUM" if score >= MEDIUM_AT else "LOW"
    floor = any(f["code"] == "LOOKALIKE_DOMAIN" or (f["code"] == "BRAND_DOMAIN_MISMATCH" and f["severity"] == "high")
                for f in flags)
    if floor and level == "LOW":
        level = "MEDIUM"
        reasons.append("raised to MEDIUM: brand/domain mismatch")
    for name, value in sorted(available.items(), key=lambda kv: -WEIGHTS[kv[0]] * kv[1]):
        if value >= 0.5:
            reasons.insert(0, f"{name} threat score {value:.2f}")
    return {"base": round(base, 4), "boost": round(boost, 4), "score": round(score, 4), "level": level,
            "components_used": sorted(available), "reasons": reasons}


def auc(rows: list[dict], key: str) -> dict:
    pairs = [(r["is_scam"], r["components"][key] if key != "score" else r["fusion"]["score"]) for r in rows]
    pairs = [(y, s) for y, s in pairs if s is not None]
    labels = {y for y, _ in pairs}
    return {"n": len(pairs), "auc": round(float(roc_auc_score([y for y, _ in pairs], [s for _, s in pairs])), 4)
            if len(labels) == 2 else None}


def level_table(rows: list[dict]) -> dict:
    table = defaultdict(Counter)
    for row in rows:
        table["scam" if row["is_scam"] else "legit"][row["fusion"]["level"]] += 1
    return {group: {level: counts[level] for level in ("LOW", "MEDIUM", "HIGH")} for group, counts in sorted(table.items())}


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--clip", default=DEFAULT_CLIP)
    args = parser.parse_args()
    started = time.time()

    records = read_jsonl(METADATA)
    baseline = {row["sample_id"]: row for row in read_jsonl(TEXT_BASELINE)}
    clips = {(r["sample_id"], r["input_type"]): r for r in read_jsonl(CLIP_PREDICTIONS)}
    logos = {(r["sample_id"], r["input_type"]): r for r in read_jsonl(LOGO_RESULTS)}
    consistency = {r["sample_id"]: r for r in read_jsonl(CONSISTENCY)}
    ocr_cache = json.loads(OCR_CACHE.read_text(encoding="utf-8")) if OCR_CACHE.exists() else {}

    # text + OCR threat scores
    texts, ocrs = {}, {}
    for record in records:
        sid = record["sample_id"]
        texts[sid] = baseline[sid]["post_text_clean"] if sid in baseline else clean_text((record.get("post") or {}).get("text"))
        ocr = (baseline.get(sid) or {}).get("ocr_text_clean") or clean_text(ocr_cache.get(sid))
        ocrs[sid] = ocr if len(ocr) >= MIN_OCR_CHARS else ""
    print("[text] scoring post text")
    text_scores = scam_probabilities(texts)
    mark_checklist("Collect text threat score")
    print("[ocr] scoring OCR text")
    ocr_scores = scam_probabilities(ocrs)
    mark_checklist("Collect OCR threat score")

    # visual threat score (CLIP zero-shot threat vs benign prompts)
    print("[visual] CLIP zero-shot threat prompts")
    model, processor = load_clip(args.clip)
    prompts = embed_texts(model, processor, list(THREAT_PROMPTS + BENIGN_PROMPTS))
    visual_scores = {}
    with_images = [r for r in records if any((ROOT / ref).exists() for ref in (r.get("post") or {}).get("images", []))]
    for start in range(0, len(with_images), 32):
        batch = with_images[start:start + 32]
        images = [letterbox(open_rgb(next(ROOT / ref for ref in r["post"]["images"] if (ROOT / ref).exists()))) for r in batch]
        for record, vector in zip(batch, embed_images(model, processor, images)):
            logits = 100.0 * prompts @ vector
            probs = np.exp(logits - logits.max())
            probs /= probs.sum()
            visual_scores[record["sample_id"]] = round(float(probs[:len(THREAT_PROMPTS)].sum()), 4)
    mark_checklist("Collect visual threat score")

    now = datetime.now(timezone.utc).isoformat()
    rows = []
    for record in records:
        sid = record["sample_id"]
        labels = record.get("labels") or {}
        cons = consistency.get(sid)

        # brand similarity
        logo = logos.get((sid, "post_image"))
        clip = clips.get((sid, "post_image"))
        brand_parts = {"logo_cosine": logo["best_cosine"] if logo and logo.get("detections") else None,
                       "clip_brand_confidence": clip["confidence"] if clip else None}
        brand_values = [v for v in brand_parts.values() if v is not None]
        brand_score = round(max(brand_values), 4) if brand_values else None
        brand_id = (logo or {}).get("best_brand") or (clip or {}).get("predicted_brand")

        # website similarity
        post_web = ((cons or {}).get("comparisons") or {}).get("post_web_image") or {}
        website_similarity = post_web.get("clip_cosine") if post_web.get("status") == "computed" else None
        website_risk = round(max(0.0, 1.0 - website_similarity), 4) if website_similarity is not None else None

        components = {"text": text_scores.get(sid), "ocr": ocr_scores.get(sid), "visual": visual_scores.get(sid),
                      "brand": brand_score, "website": website_risk}
        mismatch = (cons or {}).get("brand_identity_mismatch") or {}
        features = {
            "flag_count": len((cons or {}).get("flags") or []),
            "flags": [f["code"] for f in (cons or {}).get("flags") or []],
            "max_severity": (cons or {}).get("max_severity"),
            "brand_mismatch": bool(mismatch.get("detected")),
            "brand_mismatch_strength": mismatch.get("strength"),
            "brand_domain_status": (((cons or {}).get("comparisons") or {}).get("brand_domain") or {}).get("status"),
            "text_image_cosine": (((cons or {}).get("comparisons") or {}).get("text_image") or {}).get("clip_cosine"),
        }
        rows.append({
            "sample_id": sid, "source": (record.get("source") or {}).get("source_dataset") or "manual",
            "is_scam": labels.get("is_scam"), "label_status": labels.get("label_status"),
            "text_split": (baseline.get(sid) or {}).get("split"),
            "components": components,
            "brand_detail": {**brand_parts, "brand_id": brand_id},
            "website_detail": {"post_web_cosine": website_similarity},
            "consistency_features": features,
            "fusion": fuse(components, cons),
            "evidence_summary": (cons or {}).get("evidence_summary"),
            "created_at": now,
        })
    mark_checklist("Collect brand similarity score")
    mark_checklist("Collect website similarity score")
    mark_checklist("Add consistency/mismatch features")
    mark_checklist("Create preliminary fusion rule")

    RESULTS.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
    mark_checklist("Generate LOW / MEDIUM / HIGH result")

    verified = [r for r in rows if r["label_status"] == "verified" and r["is_scam"] in (0, 1)]
    test = [r for r in verified if r["text_split"] == "test"]
    manual = [r for r in verified if r["source"] == "manual"]
    statistics = {
        "samples": len(rows),
        "level_counts": dict(Counter(r["fusion"]["level"] for r in rows)),
        "level_counts_by_source": {s: dict(Counter(r["fusion"]["level"] for r in rows if r["source"] == s))
                                   for s in sorted({r["source"] for r in rows})},
        "component_coverage": {name: sum(r["components"][name] is not None for r in rows) for name in rows[0]["components"]},
        "evaluation_test_split": {
            "n": len(test), "levels_by_label": level_table(test),
            "auc": {name: auc(test, name) for name in ("text", "ocr", "visual", "brand", "score")},
            "high_or_medium_recall_scam": round(sum(r["fusion"]["level"] != "LOW" for r in test if r["is_scam"]) /
                                                max(1, sum(r["is_scam"] for r in test)), 4),
            "high_precision": round(sum(r["is_scam"] for r in test if r["fusion"]["level"] == "HIGH") /
                                    max(1, sum(r["fusion"]["level"] == "HIGH" for r in test)), 4),
        },
        "evaluation_all_verified_optimistic": {"n": len(verified), "levels_by_label": level_table(verified),
                                               "auc_score": auc(verified, "score")},
        "manual_posts": {"n": len(manual), "levels_by_label": level_table(manual),
                         "auc": {name: auc(manual, name) for name in ("text", "ocr", "visual", "brand", "score")}},
        "fusion_rule": {"weights": WEIGHTS, "brand_weight_if_mismatch": BRAND_WEIGHT, "mismatch_boost": MISMATCH_BOOST,
                        "low_flag_boost": LOW_FLAG_BOOST, "low_flag_cap": LOW_FLAG_CAP,
                        "levels": {"HIGH": f">= {HIGH_AT}", "MEDIUM": f">= {MEDIUM_AT}", "LOW": f"< {MEDIUM_AT}"},
                        "floor": "LOOKALIKE_DOMAIN or claimed-brand BRAND_DOMAIN_MISMATCH -> at least MEDIUM"},
        "visual_prompts": {"threat": THREAT_PROMPTS, "benign": BENIGN_PROMPTS},
        "notes": [
            "Preliminary hand-set rule; weights are not learned.",
            "Text model saw the train split, so 'all verified' metrics are optimistic; use the test split.",
            "Fakeddit rows are not_annotated: their levels are not evaluated.",
        ],
        "runtime_seconds": round(time.time() - started, 1),
        "created_at": now,
    }
    STATISTICS.write_text(json.dumps(statistics, indent=2), encoding="utf-8")

    print(f"[levels] {statistics['level_counts']}")
    print(f"[by source] {json.dumps(statistics['level_counts_by_source'])}")
    print(f"[coverage] {statistics['component_coverage']}")
    ev = statistics["evaluation_test_split"]
    print(f"[test n={ev['n']}] levels {json.dumps(ev['levels_by_label'])} AUC {json.dumps({k: v['auc'] for k, v in ev['auc'].items()})}")
    print(f"[test] scam flagged MEDIUM/HIGH={ev['high_or_medium_recall_scam']} HIGH precision={ev['high_precision']}")
    print(f"[manual n={len(manual)}] levels {json.dumps(statistics['manual_posts']['levels_by_label'])} "
          f"AUC {json.dumps({k: v['auc'] for k, v in statistics['manual_posts']['auc'].items()})}")
    for row in rows:
        if row["source"] == "manual":
            c = row["components"]
            print(f"  {row['sample_id']} y={row['is_scam']} {row['fusion']['level']:6} {row['fusion']['score']:.2f} "
                  f"text={c['text']} ocr={c['ocr']} visual={c['visual']} brand={c['brand']}")
    print(f"Wrote {RESULTS} ({statistics['runtime_seconds']}s)")


if __name__ == "__main__":
    main()
