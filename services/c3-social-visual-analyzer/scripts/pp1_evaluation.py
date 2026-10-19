"""PP1 evaluation: freeze dataset + model versions and evaluate every C3 model on its held-out test split.

Checklist (data/annotations/pp1_evaluation_checklist_status.json):
  Freeze PP1 dataset version / baseline model versions  -> SHA-256 manifest of dataset files and model weights
  Run test dataset                                       -> inference on each model's frozen test split
  Accuracy / Precision / Recall / F1 / ROC-AUC / FPR     -> per model ("scam" = positive class)
  Confusion matrices                                     -> data/statistics/pp1_confusion_matrices.png
  Test legitimate / scam scenario                        -> full live analyzer on the manual Facebook test posts
  Document limitations + next work                       -> docs/pp1_evaluation.md (written from these results)

Models evaluated here: text scam model (binary), threat category model (4 classes), misinformation model,
preliminary multimodal risk score (fusion). CLIP brand recognition and the logo detector keep their own,
larger evaluation sets; their saved results are included and their false positive rate derived.

Writes:
  data/statistics/pp1_freeze_manifest.json
  data/statistics/pp1_evaluation.json
  data/statistics/pp1_confusion_matrices.png
  data/annotations/pp1_evaluation_checklist_status.json

Usage:
  python scripts/pp1_evaluation.py              # web capture of the scenario links in the sandboxed browser
  python scripts/pp1_evaluation.py --no-capture # scenarios without visiting the links
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
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

import numpy as np
import torch
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ROOT = _bootstrap.SERVICE_ROOT
ANN = ROOT / "data" / "annotations"
STATS = ROOT / "data" / "statistics"
MODELS = ROOT / "models"
VERSION = "PP1"

DATASET_FILES = ["dataset_metadata.jsonl", "labels.jsonl", "text_baseline_dataset.jsonl", "text_baseline_splits.json",
                 "brand_catalog.jsonl", "brand_splits.jsonl", "logo_annotations.jsonl", "logo_boxes.jsonl",
                 "consistency_results.jsonl", "risk_scores.jsonl", "clip_brand_predictions.jsonl"]
MODEL_FILES = {
    "text_scam_model": "text_baseline/distilbert-base-uncased/model.safetensors",
    "threat_category_model": "threat_category/distilbert-base-uncased/model.safetensors",
    "misinformation_model": "misinformation/distilbert-base-uncased/model.safetensors",
    "logo_detector": "logo_detector/yolo11n_logo_baseline_best.pt",
}
EXTERNAL_MODELS = {"clip_brand_model": "openai/clip-vit-base-patch16 (Hugging Face, zero-shot, not fine-tuned)"}
CHECKLIST = ["Freeze PP1 dataset version", "Freeze baseline model versions", "Run test dataset", "Calculate Accuracy",
             "Calculate Precision", "Calculate Recall", "Calculate F1-score", "Calculate ROC-AUC",
             "Calculate False Positive Rate", "Generate confusion matrix", "Test legitimate scenario",
             "Test scam scenario", "Document limitations + next work"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def mark(done: list[str]) -> None:
    path = ANN / "pp1_evaluation_checklist_status.json"
    items = [{"item": name, "done": name in done} for name in CHECKLIST]
    path.write_text(json.dumps({"task": "PP1 Evaluation", "items": items, "done_count": sum(i["done"] for i in items),
                                "updated_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")


# ----------------------------------------------------------------------------- freeze
def freeze() -> dict:
    data = {}
    for name in DATASET_FILES:
        path = ANN / name
        if path.exists():
            text = path.read_text(encoding="utf-8")
            data[name] = {"sha256": sha256(path), "rows": sum(1 for l in text.splitlines() if l.strip())
                          if name.endswith(".jsonl") else None, "bytes": path.stat().st_size}
    metadata = jsonl(ANN / "dataset_metadata.jsonl")
    labels = [r.get("labels") or {} for r in metadata]
    text_rows = jsonl(ANN / "text_baseline_dataset.jsonl")
    models = {}
    for key, rel in MODEL_FILES.items():
        path = MODELS / rel
        models[key] = {"path": f"models/{rel}", "sha256": sha256(path), "bytes": path.stat().st_size,
                       "modified": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}
    manifest = {
        "version": VERSION, "frozen_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "files": data,
            "samples": len(metadata),
            "scam_types": dict(Counter(l.get("scam_type") for l in labels if l.get("is_scam") in (0, 1))),
            "binary": dict(Counter({0: "legitimate", 1: "scam"}.get(l.get("is_scam"), "not_annotated") for l in labels)),
            "text_splits": {s: dict(Counter(r["scam_type"] for r in text_rows if r["split"] == s)) for s in ("train", "val", "test")},
        },
        "models": models, "external_models": EXTERNAL_MODELS,
        "note": "Hashes identify the exact files evaluated; regenerate or retrain only with a new version name.",
    }
    (STATS / "pp1_freeze_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


# ----------------------------------------------------------------------------- metrics
def binary_metrics(y: list[int], pred: list[int], score: list[float] | None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    p, r, f1, _ = precision_recall_fscore_support(y, pred, labels=[1], average="binary", pos_label=1, zero_division=0)
    return {"n": len(y), "accuracy": round((tp + tn) / len(y), 4), "precision": round(float(p), 4),
            "recall": round(float(r), 4), "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc_score(y, score)), 4) if score is not None and len(set(y)) == 2 else None,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
            "confusion_matrix": {"labels": ["legitimate", "scam"], "rows_true_cols_pred": [[int(tn), int(fp)], [int(fn), int(tp)]]}}


@torch.no_grad()
def predict(model_dir: Path, texts: list[str], max_length: int) -> np.ndarray:
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).eval()
    probs = []
    for start in range(0, len(texts), 16):
        enc = tokenizer(texts[start:start + 16], truncation=True, max_length=max_length, padding=True, return_tensors="pt")
        probs.append(torch.softmax(model(**enc).logits, dim=-1).numpy())
    return np.concatenate(probs), model.config.id2label


def eval_text_scam() -> dict:
    test = [r for r in jsonl(ANN / "text_baseline_dataset.jsonl") if r["split"] == "test"]
    probs, _ = predict(MODELS / "text_baseline" / "distilbert-base-uncased", [r["text"] for r in test], 256)
    y, score = [r["label"] for r in test], probs[:, 1].tolist()
    pred = [int(s >= 0.5) for s in score]
    result = {"model": "text scam model (DistilBERT, binary)", "test_set": "text_baseline test split",
              "threshold": 0.5, **binary_metrics(y, pred, score), "by_source": {}}
    for source in sorted({r["source_dataset"] for r in test}):
        idx = [i for i, r in enumerate(test) if r["source_dataset"] == source]
        result["by_source"][source] = {"n": len(idx), "accuracy": round(float(np.mean([y[i] == pred[i] for i in idx])), 4)}
    return result


def eval_category() -> dict:
    labels = ["legitimate", "phishing", "financial_scam", "data_theft"]
    test = [r for r in jsonl(ANN / "text_baseline_dataset.jsonl") if r["split"] == "test" and r["scam_type"] in labels]
    probs, id2label = predict(MODELS / "threat_category" / "distilbert-base-uncased", [r["text"] for r in test], 256)
    order = [id2label[i] for i in range(len(id2label))]
    y = [order.index(r["scam_type"]) for r in test]
    pred = probs.argmax(axis=1).tolist()
    p, r_, f1, support = precision_recall_fscore_support(y, pred, labels=list(range(len(order))), zero_division=0)
    macro = precision_recall_fscore_support(y, pred, labels=list(range(len(order))), average="macro", zero_division=0)
    per_class_auc = {}
    for k, name in enumerate(order):
        target = [int(v == k) for v in y]
        per_class_auc[name] = round(float(roc_auc_score(target, probs[:, k])), 4) if 0 < sum(target) < len(target) else None
    legit = order.index("legitimate")
    collapsed = binary_metrics([int(v != legit) for v in y], [int(v != legit) for v in pred], (1 - probs[:, legit]).tolist())
    aucs = [v for v in per_class_auc.values() if v is not None]
    return {
        "model": "threat category model (DistilBERT, 4 classes)", "test_set": "text_baseline test split (4 trained classes)",
        "n": len(y), "accuracy": round(float(np.mean(np.array(y) == np.array(pred))), 4),
        "precision_macro": round(float(macro[0]), 4), "recall_macro": round(float(macro[1]), 4), "f1_macro": round(float(macro[2]), 4),
        "roc_auc_macro_ovr": round(float(np.mean(aucs)), 4) if aucs else None, "roc_auc_per_class_ovr": per_class_auc,
        "false_positive_rate": collapsed["false_positive_rate"],
        "false_positive_rate_note": "legitimate posts predicted as any scam class",
        "per_class": {name: {"precision": round(float(p[k]), 4), "recall": round(float(r_[k]), 4), "f1": round(float(f1[k]), 4),
                             "support": int(support[k])} for k, name in enumerate(order)},
        "as_scam_vs_legitimate": collapsed,
        "confusion_matrix": {"labels": order, "rows_true_cols_pred":
                             confusion_matrix(y, pred, labels=list(range(len(order)))).tolist()},
        "not_trained_categories": ["brand_impersonation", "malware", "browser_abuse", "other_scam (rule-based in the analyzer)"],
    }


def eval_misinformation() -> dict:
    from train_threat_category import misinformation_rows

    test = misinformation_rows(42)["test"]
    probs, _ = predict(MODELS / "misinformation" / "distilbert-base-uncased", [r["text"] for r in test], 64)
    y, score = [r["y"] for r in test], probs[:, 1].tolist()
    result = binary_metrics(y, [int(s >= 0.5) for s in score], score)
    result["confusion_matrix"]["labels"] = ["real", "fake"]
    return {"model": "misinformation model (DistilBERT, binary)", "test_set": "Fakeddit stratified test split (seed 42)",
            "positive_class": "fake", "threshold": 0.5, **result,
            "label_note": "Fakeddit labels are provisional (derived from the subreddit)"}


def eval_risk() -> dict:
    rows = [r for r in jsonl(ANN / "risk_scores.jsonl") if r.get("text_split") == "test" and r.get("is_scam") in (0, 1)]
    y = [r["is_scam"] for r in rows]
    score = [r["fusion"]["score"] for r in rows]
    levels = [r["fusion"]["level"] for r in rows]
    medium = binary_metrics(y, [int(l in ("MEDIUM", "HIGH")) for l in levels], score)
    high = binary_metrics(y, [int(l == "HIGH") for l in levels], score)
    return {"model": "preliminary multimodal risk score (rule-based fusion)", "test_set": "text_baseline test split",
            "operating_points": {"MEDIUM_or_HIGH_is_scam": medium, "HIGH_is_scam": high},
            "level_counts_by_label": {lab: dict(Counter(l for l, v in zip(levels, y) if v == k)) for k, lab in ((0, "legitimate"), (1, "scam"))}}


def saved_vision() -> dict:
    def load(name):
        path = STATS / name
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    clip = load("clip_brand_experiment_clip-vit-base-patch16.json")
    mode = clip.get("selected_mode", "fused")
    zen = ((clip.get("results") or {}).get("zenodo_test") or {}).get(mode) or {}
    logo_train, logo_eval = load("logo_detector_training.json"), load("logo_baseline_evaluation.json")
    return {
        "clip_brand_recognition": {
            "source": "saved evaluation (clip_brand_experiment_clip-vit-base-patch16.json)", "test_set": "Zenodo phishing test pages",
            "mode": mode, "threshold": clip.get("selected_threshold"), "n": zen.get("n"),
            "precision": zen.get("precision"), "recall": zen.get("recall"), "f1": zen.get("f1"),
            "top1_accuracy_closed_set": zen.get("closed_set_top1"),
            "false_positive_rate": round(1 - zen["unknown_rejection_rate"], 4) if zen.get("unknown_rejection_rate") is not None else None,
            "false_positive_rate_note": "unknown-brand pages wrongly accepted as a catalog brand",
            "roc_auc": None, "roc_auc_note": "open-set brand identification; reported as precision/recall/F1",
        },
        "logo_detector": {
            "source": "saved evaluation (logo_detector_training.json, logo_baseline_evaluation.json)",
            "detection_test": ((logo_train.get("metrics") or {}).get("test")),
            "brand_matching_test": logo_eval.get("brand_matching_test"), "brand_threshold": logo_eval.get("brand_threshold"),
        },
    }


# ----------------------------------------------------------------------------- scenarios
def scenarios(capture: bool) -> list[dict]:
    from app.main import create_app

    settings = _bootstrap.load_settings()
    if not capture:
        settings.web_capture_enabled = False
    service = create_app(settings=settings).state.social_service
    test_ids = {r["sample_id"]: r["scam_type"] for r in jsonl(ANN / "text_baseline_dataset.jsonl")
                if r["split"] == "test" and r["source_dataset"] == "manual"}
    results = []
    for record in jsonl(ANN / "dataset_metadata.jsonl"):
        if record["sample_id"] not in test_ids:
            continue
        post, labels = record.get("post") or {}, record.get("labels") or {}
        image_path = ROOT / post["images"][0] if post.get("images") else None
        urls = post.get("embedded_urls") or []
        started = time.time()
        output = service.analyze(
            platform=(record.get("source") or {}).get("platform") or "facebook", post_text=post.get("text") or "",
            image_file=io.BytesIO(image_path.read_bytes()) if image_path and image_path.exists() else None,
            image_filename=image_path.name if image_path else None, embedded_url=urls[0] if urls else None)
        assessment, classification = output["assessment"], output.get("classification") or {}
        is_scam = labels.get("is_scam") == 1
        expected = "MEDIUM or HIGH, a scam category" if is_scam else "LOW, legitimate"
        passed = (assessment["level"] in ("MEDIUM", "HIGH") and classification.get("primary") not in (None, "LEGITIMATE")
                  if is_scam else assessment["level"] == "LOW" and classification.get("primary") == "LEGITIMATE")
        results.append({
            "scenario": "scam" if is_scam else "legitimate", "sample_id": record["sample_id"],
            "true_label": labels.get("scam_type"), "claimed_brand": (record.get("brand") or {}).get("claimed_brand"),
            "level": assessment["level"], "score": assessment["score"], "primary_category": classification.get("primary"),
            "detected": [d["category"] for d in classification.get("detected", [])], "expected": expected, "passed": passed,
            "steps": {s["key"]: s["status"] for s in output["pipeline"]},
            "reasons": (output.get("risk") or {}).get("reasons"), "conclusion": assessment["conclusion"],
            "seconds": round(time.time() - started, 1),
        })
        print(f"[scenario] {record['sample_id']} {results[-1]['scenario']:10} -> {assessment['level']:6} "
              f"{classification.get('primary')} {'PASS' if passed else 'FAIL'}")
    return results


# ----------------------------------------------------------------------------- figure
def plot(matrices: list[tuple[str, dict]]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, len(matrices), figsize=(5.2 * len(matrices), 4.6), dpi=140)
    for ax, (title, cm) in zip(axes, matrices):
        data, labels = np.array(cm["rows_true_cols_pred"]), cm["labels"]
        ax.imshow(data, cmap="Blues")
        ax.set_xticks(range(len(labels)), [l.replace("_", " ") for l in labels], rotation=30, ha="right", fontsize=8)
        ax.set_yticks(range(len(labels)), [l.replace("_", " ") for l in labels], fontsize=8)
        ax.set_xlabel("Predicted", fontsize=8)
        ax.set_ylabel("True", fontsize=8)
        ax.set_title(title, fontsize=9)
        for i in range(len(labels)):
            for j in range(len(labels)):
                ax.text(j, i, str(data[i, j]), ha="center", va="center", fontsize=10,
                        color="white" if data[i, j] > data.max() / 2 else "black")
    fig.tight_layout()
    fig.savefig(STATS / "pp1_confusion_matrices.png")
    plt.close(fig)


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-capture", action="store_true", help="Do not capture scenario links in the sandboxed browser")
    args = parser.parse_args()
    started = time.time()

    manifest = freeze()
    print(f"[freeze] dataset {manifest['dataset']['samples']} samples, {len(manifest['models'])} model files hashed")
    text, category, misinfo, risk = eval_text_scam(), eval_category(), eval_misinformation(), eval_risk()
    for name, m in (("text", text), ("misinformation", misinfo), ("risk MEDIUM+", risk["operating_points"]["MEDIUM_or_HIGH_is_scam"])):
        print(f"[{name}] n={m['n']} acc={m['accuracy']} P={m['precision']} R={m['recall']} F1={m['f1']} "
              f"AUC={m['roc_auc']} FPR={m['false_positive_rate']}")
    print(f"[category] n={category['n']} acc={category['accuracy']} macroF1={category['f1_macro']} "
          f"AUC={category['roc_auc_macro_ovr']} FPR={category['false_positive_rate']}")
    plot([("Text scam model", text["confusion_matrix"]), ("Threat category model", category["confusion_matrix"]),
          ("Misinformation model", misinfo["confusion_matrix"]),
          ("Risk score (MEDIUM/HIGH = scam)", risk["operating_points"]["MEDIUM_or_HIGH_is_scam"]["confusion_matrix"])])
    scenario_results = scenarios(capture=not args.no_capture)

    report = {
        "version": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
        "freeze_manifest": "data/statistics/pp1_freeze_manifest.json",
        "positive_class": "scam (fake for the misinformation model)",
        "models": {"text_scam_model": text, "threat_category_model": category, "misinformation_model": misinfo,
                   "multimodal_risk_score": risk, **saved_vision()},
        "scenarios": {"capture_enabled": not args.no_capture, "results": scenario_results,
                      "legitimate_passed": sum(r["passed"] for r in scenario_results if r["scenario"] == "legitimate"),
                      "legitimate_total": sum(r["scenario"] == "legitimate" for r in scenario_results),
                      "scam_passed": sum(r["passed"] for r in scenario_results if r["scenario"] == "scam"),
                      "scam_total": sum(r["scenario"] == "scam" for r in scenario_results)},
        "confusion_matrices_png": "data/statistics/pp1_confusion_matrices.png",
        "runtime_seconds": round(time.time() - started, 1),
    }
    (STATS / "pp1_evaluation.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    mark(CHECKLIST[:-1] + (["Document limitations + next work"] if (ROOT / "docs" / "pp1_evaluation.md").exists() else []))
    s = report["scenarios"]
    print(f"[scenarios] legitimate {s['legitimate_passed']}/{s['legitimate_total']} passed, "
          f"scam {s['scam_passed']}/{s['scam_total']} passed")
    print(f"Wrote {STATS / 'pp1_evaluation.json'} ({report['runtime_seconds']}s)")


if __name__ == "__main__":
    main()
