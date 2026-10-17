"""Metrics of the Part 6A text models (tasks 8-12), built on Part 4's evaluation.

Part 6: XLM-R content classification (6A, page level).

``compute_metrics`` of Part 4 (macro-F1 primary, weighted-F1, accuracy, balanced
accuracy, ROC-AUC OvR, benign FPR, per-class P/R/F1, confusion matrix) is reused
unchanged, so the text arms are scored exactly like DOM-only and Behavior-only.
Added here: macro precision / recall, per-language results over FIXED buckets
(en, si, ta, mixed, other - an empty bucket is reported with n = 0 rather than
silently missing) with a small-n warning, and mean ± std over seeds.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import precision_recall_fscore_support

from c2_analyzer.classifiers.dom_baseline.evaluate import SCALAR_METRICS, compute_metrics

TEXT_SCALARS = ("macro_precision", "macro_recall") + SCALAR_METRICS


def full_metrics(
    y_true, y_pred, proba: np.ndarray | None, labels: list[str], present_only: bool = False
) -> dict:
    """Part 4 metrics + macro precision / recall (over the same classes as macro-F1)."""
    metrics = compute_metrics(y_true, y_pred, proba, labels, present_only=present_only)
    y_true, y_pred = np.asarray(y_true, dtype=int), np.asarray(y_pred, dtype=int)
    used = sorted(set(y_true.tolist())) if present_only else list(range(len(labels)))
    precision, recall, _, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=used, average="macro", zero_division=0
    )
    return {"macro_precision": float(precision), "macro_recall": float(recall), **metrics}


def per_language(
    y_true,
    y_pred,
    languages,
    labels: list[str],
    buckets: list[str],
    min_support: int,
) -> dict:
    """Metrics per language bucket (classes present in that bucket only)."""
    y_true, y_pred = np.asarray(y_true, dtype=int), np.asarray(y_pred, dtype=int)
    languages = np.asarray(languages)
    result = {}
    for bucket in buckets + sorted(set(languages.tolist()) - set(buckets)):
        mask = languages == bucket
        n = int(mask.sum())
        if not n:
            result[bucket] = {"n": 0, "small_n": True}
            continue
        m = full_metrics(y_true[mask], y_pred[mask], None, labels, present_only=True)
        result[bucket] = {
            "n": n,
            "accuracy": m["accuracy"],
            "macro_precision": m["macro_precision"],
            "macro_recall": m["macro_recall"],
            "macro_f1": m["macro_f1"],
            "benign_fpr": m["benign_fpr"],
            "labels": {
                label: int((y_true[mask] == i).sum())
                for i, label in enumerate(labels)
                if (y_true[mask] == i).any()
            },
            "small_n": n < min_support,
        }
    return result


def seed_summary(runs: list[dict]) -> dict:
    """{"mean", "std", "n_seeds"} over seeds: scalar metrics + per-class F1."""
    mean, std = {}, {}
    for key in TEXT_SCALARS:
        values = [run[key] for run in runs if run.get(key) is not None]
        mean[key] = float(np.mean(values)) if values else None
        std[key] = float(np.std(values)) if values else None
    for label in runs[0]["per_class"] if runs else []:
        values = [run["per_class"][label]["f1"] for run in runs]
        mean[f"f1_{label}"] = float(np.mean(values))
        std[f"f1_{label}"] = float(np.std(values))
    return {"mean": mean, "std": std, "n_seeds": len(runs)}


def misclassified_rows(rows: list[dict], proba: np.ndarray, labels: list[str], model: str):
    """misclassified.csv rows (``rows`` = examples in the order of ``proba``)."""
    out = []
    for row, probabilities in zip(rows, proba, strict=True):
        predicted = int(np.argmax(probabilities))
        if predicted != int(row["label_id"]):
            out.append(
                {
                    "model": model,
                    "split": row["split"],
                    "sample_id": row["sample_id"],
                    "language": row["language"],
                    "true": labels[int(row["label_id"])],
                    "predicted": labels[predicted],
                    "top_probability": round(float(probabilities.max()), 4),
                    "true_probability": round(float(probabilities[int(row["label_id"])]), 4),
                }
            )
    return out
